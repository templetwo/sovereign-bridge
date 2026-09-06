"""Seat identity — the third auth path on POST /api/call.

Anthony, 2026-09-05: *"Inside my network, meaning seats I've put on the Studio,
no tokens... Every Studio terminal gets its seat identity in its environment so
every write signs itself."*

EVERY TEST HERE IS A FAIL-CLOSED PROOF. The dangerous direction for this feature
is not "a seat is wrongly refused" — it is "something that is not a seat gets
the read+write surface." So the deny cases are the point, and each one is
written so that it FAILS if the corresponding guard is removed.

⚠ REWRITTEN 2026-09-06 AFTER THE CODEX REVIEW. The tests below used to prove a
LOOPBACK check. Loopback was never an identity — see the module docstring — so
every "the path works" test here now runs over the SEAT SOCKET, simulated by
stamping the same ASGI scope extension seat_socket stamps. The transport that
produces that extension (kernel peer credentials, the environment read, the
real socket) is proven separately and for real, subprocess and all, in
tests/test_seat_socket.py. Neither file is sufficient alone: this one would
pass against a listener that stamped anything it liked, and that one would pass
against a bridge that ignored the stamp.

FOUR HARNESS TRAPS, each of which would silently turn a real check into a
no-op:

  1. TestClient's default peer address is the STRING "testclient", not an IP.
     A loopback check written against it would pass in tests and gate nothing in
     production. Kept as history: the loopback check is GONE, and `tcp_client`
     below exists to prove that a TCP request is refused no matter what address
     or headers it presents.

  2. The registry path must be resolved fresh per request or SOVEREIGN_ROOT
     redirection is a no-op (bridge is imported at collection time, so a
     module-level constant is already bound). `registry` below sets the env var
     and NEVER touches the live ~/.sovereign — this suite writes to tmp_path
     only.

  3. tests/test_bridge_writepath.py monkeypatches bridge.check_auth to bypass
     auth. The new wrapper still routes the bearer branch THROUGH check_auth, so
     that bypass keeps working; test_writepath_auth_bypass_still_works below
     pins that, because breaking it would break a passing suite silently.

  4. TestClient runs the app's lifespan ONLY as a context manager. None of these
     tests use `with`, so no listener is started and no socket is ever bound —
     including under SOVEREIGN_ROOT. If you convert a test here to `with
     TestClient(...)`, check where it binds before you do.
"""

import json
import os
import signal
import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import bridge  # noqa: E402
import seat_identity as si  # noqa: E402
import seat_socket as ss  # noqa: E402
import session_tokens as st  # noqa: E402

MASTER = "test-master-token-0123456789abcdef-0123456789abcdef"
SEAT = "grok-build-studio"

# The peer address a seated Studio terminal actually presents. It no longer
# grants anything — kept so the TCP-denial tests present a realistic request.
LOOPBACK_PEER = ("127.0.0.1", 51234)
# Something on the LAN. Not a seat, however friendly.
REMOTE_PEER = ("10.0.0.5", 51234)

READ_TOOL = "recall_insights"
WRITE_TOOL = "record_insight"


def peer(seat=SEAT, **overrides):
    """A VERIFIED peer identity, shaped exactly as seat_socket.resolve_peer
    returns it. `seat` is what the calling process's SOVEREIGN_SEAT says — not
    what the request declares in its header. Those two being separable is the
    entire point of the fix."""
    return {"ok": True, "pid": os.getpid(), "uid": os.getuid(), "seat": seat, **overrides}


class StampPeer:
    """The listener, simulated: stamps a peer identity into the ASGI scope.

    This is the ONE thing seat_socket does that a TestClient cannot, and it is
    faithful to the real thing in the way that matters — it sets the extension
    on the scope, which no header or body can do.
    """

    def __init__(self, app, verified):
        self.app = app
        self.verified = verified

    async def __call__(self, scope, receive, send):
        if scope.get("type") == "http" and self.verified is not None:
            extensions = dict(scope.get("extensions") or {})
            extensions[ss.SEAT_PEER_EXT] = self.verified
            scope = {**scope, "extensions": extensions}
        await self.app(scope, receive, send)


@pytest.fixture
def registry(monkeypatch, tmp_path):
    """A seat registry under a tmp SOVEREIGN_ROOT. Returns a writer so a test
    can change or delete it. NOTHING here touches ~/.sovereign."""
    monkeypatch.setenv("SOVEREIGN_ROOT", str(tmp_path))
    monkeypatch.setattr(st, "DB_PATH", tmp_path / "session_tokens.db")
    monkeypatch.setattr(bridge, "BEARER_TOKEN", MASTER)
    path = tmp_path / "hq" / "seats" / "registry.json"
    path.parent.mkdir(parents=True)

    def write(seats):
        path.write_text(json.dumps({"seats": seats}))

    write(
        {
            "hq-claude-studio": {"substrate": "anthropic", "kind": "hq", "enabled": True},
            SEAT: {"substrate": "xai", "kind": "seated", "enabled": True},
            "retired-seat": {"substrate": "xai", "kind": "seated", "enabled": False},
        }
    )
    write.path = path
    return write


@pytest.fixture
def calls(monkeypatch):
    """Record every (tool, arguments) that reaches the stack."""
    seen = []

    async def fake(tool, args):
        seen.append((tool, args))
        return {"ok": True, "result": {"echo": tool}}

    monkeypatch.setattr(bridge, "call_mcp_tool", fake)
    return seen


def client(env_seat=SEAT, verified=None):
    """A client ON THE SEAT SOCKET: its connection carries a verified identity.

    `env_seat` is the seat the CALLING PROCESS is running as. Pass a different
    value than the header to reproduce the impersonation the review found.
    """
    return TestClient(
        StampPeer(bridge.app, peer(env_seat) if verified is None else verified),
        client=LOOPBACK_PEER,
    )


def tcp_client(addr=LOOPBACK_PEER):
    """A client on the ORDINARY TCP listener. No scope extension, ever — which
    is precisely what makes it not a seat."""
    return TestClient(bridge.app, client=addr)


def call(c, tool, headers, **args):
    return c.post("/api/call", json={"tool": tool, "arguments": args}, headers=headers)


def seat_hdr(seat=SEAT):
    return {"X-Sovereign-Seat": seat}


# `None` is a MEANINGFUL value for `verified` — it is what a TCP request has —
# so "not passed" needs its own sentinel. Defaulting on None would have made
# _reason(verified=None) silently test the happy path, which is how a helper
# quietly stops testing the thing its caller named.
_UNSET = object()


def _reason(tool=READ_TOOL, seat=SEAT, verified=_UNSET, extra=None):
    """The machine-readable denial reason, taken from resolve_seat directly.

    An HTTP 401 says only THAT the door was shut. Several guards shut it, and a
    test that asserts on prose can pass because two different messages happen to
    share a word — which is exactly how the registry-absence test passed with
    its guard deleted. This reads the reason the code itself named.

    `verified` defaults to a good peer seated as SEAT, so a test that changes
    only one variable is changing only one variable.
    """
    headers = dict(extra or {})
    try:
        si.resolve_seat(peer() if verified is _UNSET else verified, seat, headers)
    except si.SeatDenied as denied:
        return denied.reason
    return "allowed"


# ── The path works ──────────────────────────────────────────────────────────


def test_seated_terminal_may_read(registry, calls):
    r = call(client(), READ_TOOL, seat_hdr(), query="anything")
    assert r.status_code == 200, r.text
    assert calls[0][0] == READ_TOOL


def test_seated_terminal_may_write(registry, calls):
    r = call(client(), WRITE_TOOL, seat_hdr(), content="c", domain="d")
    assert r.status_code == 200, r.text
    assert calls[0][0] == WRITE_TOOL


def test_no_bearer_is_needed(registry, calls):
    """The whole point: a seated seat with no token can reach the record."""
    r = client().post(
        "/api/call", json={"tool": READ_TOOL, "arguments": {}}, headers=seat_hdr()
    )
    assert r.status_code == 200
    assert "authorization" not in {k.lower() for k in r.request.headers}


# ── The path fails closed ───────────────────────────────────────────────────


def test_a_seat_cannot_declare_another_seats_id(registry, calls):
    """⚠ THE P1 THE CODEX REVIEW FOUND, REPRODUCED AND THEN CLOSED.

    Verbatim from the finding: "With SOVEREIGN_SEAT=codex-astra-studio in the
    caller's environment, header hq-claude-studio returned 200 and dispatched
    source_instance=hq-claude-studio."

    Both seats below are registered and enabled, so nothing but the BINDING can
    refuse this. The old code validated registry membership and never asked
    which process was calling; seat ids are not secrets, so the header was a
    claim nobody checked. This is the test that fails if the env-match check at
    seat_identity.py is deleted — the socket is only the transport that makes
    the check possible, and a test that proves the socket proves nothing here.
    """
    r = call(client(env_seat="codex-astra-studio"), READ_TOOL, seat_hdr("hq-claude-studio"))
    assert r.status_code == 401, "a seat impersonated another seat"
    assert (
        _reason(seat="hq-claude-studio", verified=peer("codex-astra-studio"))
        == "seat_mismatch"
    )
    assert not calls, "a refused request must never reach the stack"


def test_a_seat_may_call_as_itself(registry, calls):
    """The other half of the binding, so the guard above cannot be satisfied by
    refusing everything. Same shape as the impersonation test, one variable
    changed: the header now names the process's own seat."""
    r = call(client(env_seat=SEAT), READ_TOOL, seat_hdr(SEAT))
    assert r.status_code == 200, r.text


def test_tcp_is_not_a_seat_path_at_all(registry, calls):
    """LOOPBACK WAS NEVER AN IDENTITY, and this is the test that says so.

    cloudflared runs on this machine and connects to 127.0.0.1:8100, so a
    request from the open internet arrives with a LOOPBACK peer. bridge.py
    already relies on this: its rate limiter treats CF-Connecting-IP as proof of
    tunnel origin, and the connector route notes request.client.host is ALWAYS
    127.0.0.1. So the address proves nothing, and neither does the absence of a
    forwarding header — any local process could send a bare, clean request.

    A TCP connection carries no scope extension because uvicorn never builds
    one, which is why this fails closed by construction rather than by a check.
    """
    for addr in (LOOPBACK_PEER, REMOTE_PEER):
        r = call(tcp_client(addr), READ_TOOL, seat_hdr())
        assert r.status_code == 401, f"{addr} took the seat path over TCP"
        assert "socket" in r.json()["detail"], "the 401 must say where to go instead"
    assert _reason(verified=None) == "not_socket"
    assert not calls


def test_forwarding_headers_are_refused_by_an_ALLOWLIST(registry, calls):
    """P2 FORWARDING, with the four headers the old denylist MISSED first.

    The review found X-Forwarded-Proto, X-Forwarded-Port, CF-Connecting-IPv6 and
    True-Client-IP each admitted a loopback request when supplied alone. The
    denylist could only ever name the relays somebody thought of. `x-made-up`
    is in this list on purpose: it is the proof that the mechanism is an
    allowlist and not a longer denylist, and it is the case a future proxy adds.
    """
    missed_by_the_denylist = (
        "X-Forwarded-Proto",
        "X-Forwarded-Port",
        "CF-Connecting-IPv6",
        "True-Client-IP",
    )
    for header in missed_by_the_denylist + (
        "CF-Connecting-IP",
        "X-Forwarded-For",
        "X-Real-IP",
        "Forwarded",
        "Via",
        "X-Made-Up-Header",
    ):
        r = client().post(
            "/api/call",
            json={"tool": READ_TOOL, "arguments": {}},
            headers={**seat_hdr(), header: "203.0.113.9"},
        )
        assert r.status_code == 401, f"{header} did not deny"
        assert _reason(extra={header.lower(): "203.0.113.9"}) == "relayed"
        assert header.lower() in r.json()["detail"], "the 401 must name the header"
    assert not calls


def test_the_headers_a_real_client_sends_are_allowed(registry, calls):
    """The allowlist's other edge: deny everything is not a fix, it is an
    outage. curl over a Unix socket sends these, and a 401 on `expect` would
    break exactly the writes >1 KiB that matter most (curl switches to
    100-continue above ~1 KiB, so a small-payload test would never see it)."""
    r = client().post(
        "/api/call",
        json={"tool": READ_TOOL, "arguments": {}},
        headers={
            **seat_hdr(),
            "Host": "localhost",
            "User-Agent": "curl/8.7.1",
            "Accept": "*/*",
            "Content-Type": "application/json",
            "Expect": "100-continue",
        },
    )
    assert r.status_code == 200, r.text


def test_unknown_seat_is_refused(registry, calls):
    """A process genuinely seated as something Anthony never registered. The
    env and the header AGREE here — that is deliberate, so the denial comes
    from the registry and not from the binding one check earlier."""
    stranger = "seat-that-was-never-seated"
    r = call(client(env_seat=stranger), READ_TOOL, seat_hdr(stranger))
    assert r.status_code == 401
    assert _reason(seat=stranger, verified=peer(stranger)) == "unknown_seat"
    assert not calls


def test_disabled_seat_is_refused(registry, calls):
    """Registered is not the same as enabled — this is the revocation lever.
    Env and header agree, so only `enabled` can be doing the refusing."""
    r = call(client(env_seat="retired-seat"), READ_TOOL, seat_hdr("retired-seat"))
    assert r.status_code == 401
    assert _reason(seat="retired-seat", verified=peer("retired-seat")) == "seat_disabled"
    assert not calls


def test_enabled_must_be_literally_true(registry, calls):
    """Truthy is not consent. "yes", 1 and "true" are all NOT enabled."""
    for value in ("true", 1, "yes", None):
        registry({SEAT: {"enabled": value}})
        r = call(client(), READ_TOOL, seat_hdr())
        assert r.status_code == 401, f"enabled={value!r} was accepted"
    assert not calls


def test_missing_registry_denies_everything(registry, calls):
    """Absence is the off switch, never 'no restrictions'. The feature is inert
    until Anthony creates the file — that is the deploy step, and deleting the
    file is the kill switch.

    ASSERTED ON THE SPECIFIC GUARD, not just on the 401. Written the obvious way
    (`assert "registry" in detail`) this test PASSED with the absence check
    deleted — a None registry then fell through to the unknown-seat branch,
    whose message also contains the word "registry". Fail-closed by luck reads
    identical to fail-closed by design, and only a falsifier run tells them
    apart. `_reason` reads the machine word, which is unambiguous.
    """
    registry.path.unlink()
    r = call(client(), READ_TOOL, seat_hdr())
    assert r.status_code == 401
    assert _reason(READ_TOOL) == "no_registry"
    assert not calls


def test_malformed_registry_denies_everything(registry, calls):
    """A truncated write must not open the door — and must be diagnosed as a
    registry fault, not mistaken for an unregistered seat."""
    for junk in ("", "{", "[]", '{"seats": "everyone"}', '{"no_seats_key": 1}'):
        registry.path.write_text(junk)
        r = call(client(), READ_TOOL, seat_hdr())
        assert r.status_code == 401, f"registry {junk!r} was accepted"
        assert _reason(READ_TOOL) == "no_registry", f"registry {junk!r} misdiagnosed"
    assert not calls


def test_no_seat_header_is_the_old_401(registry, calls):
    """No bearer, no seat header — byte-for-byte the pre-existing behaviour."""
    r = client().post("/api/call", json={"tool": READ_TOOL, "arguments": {}})
    assert r.status_code == 401
    assert "Bearer" in r.json()["detail"]


# ── Scope ───────────────────────────────────────────────────────────────────


def test_governance_tool_is_denied_to_a_seat(registry, calls):
    """Denied AS GOVERNANCE, by name — not incidentally.

    None of these is in TOOL_SCOPES, so default-deny already refuses them today
    and this test passed with SEAT_NEVER_TOOLS deleted. That is the belt-and-
    suspenders working, and it is also how a suspenders-only design would go
    unnoticed: the day someone maps a governance tool into read/write, the
    default-deny stops covering it and only the explicit list holds. So assert
    on the reason the code gives, which changes to 'unmapped' the moment the
    explicit denial goes away.
    """
    for tool in ("set_policy", "open_protected_record", "resolve_thread", "govern"):
        r = call(client(), tool, seat_hdr())
        assert r.status_code == 403, f"{tool} reached the stack"
        assert r.json()["failure_class"] == "scope"
        assert si.seat_tool_allowed(tool) == (False, "governance"), tool
    assert not calls


def test_a_governance_tool_is_denied_however_it_is_classified_elsewhere(monkeypatch):
    """The scenario the explicit list exists for: someone reclassifies a
    governance tool somewhere else in the codebase. SEAT_NEVER_TOOLS must still
    hold, because it is the only list that is ABOUT governance."""
    monkeypatch.setitem(st.TOOL_SCOPES, "set_policy", "write")
    assert si.seat_tool_allowed("set_policy") == (False, "governance")
    assert "set_policy" not in si.seat_allowed_tools()


def test_session_lifecycle_tools_stay_as_they_were(registry, calls):
    """ANTHONY'S RULING, the clause that is a NON-change: "close_session /
    spiral_inherit stay as they were."

    They mutate GLOBAL spiral state — the session id and phase every other seat
    then reads — so widening the surface to all studio seats does not reach
    them. This test exists because it is the easiest clause to lose while
    implementing the widening around it.
    """
    for tool in ("close_session", "spiral_inherit"):
        assert si.seat_tool_allowed(tool) == (False, "governance"), tool
        assert call(client(), tool, seat_hdr()).status_code == 403
    assert not calls


def test_the_ruling_widened_the_surface_to_the_published_tools(registry, calls):
    """ANTHONY'S RULING, 2026-09-06: "all studio seats are trusted."

    THE SHAPE: allowed = published surface − governance − retired. Asserted as
    the equation, not as a hand-copied list, so a future edit to any one of the
    three constants moves the surface and this test follows it.

    The counts are pinned separately below; here the point is that the surface
    is no longer st.TOOL_SCOPES. Before the ruling a seat reached 21 of 100
    published tools and could not call the boot door it is TOLD to call.
    """
    allowed = set(si.seat_allowed_tools())
    expected = si.SEAT_TOOL_SURFACE - si.SEAT_NEVER_TOOLS - si.SEAT_RETIRED_TOOLS
    assert allowed == expected
    old_surface = {t for t, s in st.TOOL_SCOPES.items() if s in ("read", "write")}
    assert len(allowed) > 2 * len(old_surface), "the ruling widened the surface"


def test_the_widening_also_NARROWS_in_exactly_two_places(registry, calls):
    """⚠ AN HONEST CONSEQUENCE, PINNED SO IT CANNOT BE DISCOVERED BY SURPRISE.

    Anthony's ruling is a widening — 19 tools to 48 — but subtracting the
    RETIRED set takes away two tools a read+write SESSION grant can still call
    today: `ask_scribe` (read) and `reflection_ack` (write). So a seated Studio
    terminal, which the ruling calls TRUSTED, reaches two fewer tools than an
    outside visitor holding a scoped token. That is backwards on its face.

    IT IS IMPLEMENTED THAT WAY ON PURPOSE, and the reason is jurisdiction, not
    conviction. The stack has no RETIRED set, so this release derives one from
    the 30-day census's Total-0 rows as instructed. The census's OWN §4 marks
    `reflection_ack` with ★ — "keep these reachable" — so there is a live
    argument that both belong back in the surface.

    Two ways to make this test go green, and the difference matters: if the
    stack lands a real RETIRED set that omits them, they return and the count
    below moves. If Anthony rules that a seat is never narrower than a session
    grant, add that subtraction to seat_tool_allowed. Neither is HQ's to decide
    quietly (pol_20260831), so it is measured, named, and left where he can see
    it rather than fixed by someone's judgement at 2am.
    """
    session_grant = {t for t, s in st.TOOL_SCOPES.items() if s in ("read", "write")}
    lost = session_grant - set(si.seat_allowed_tools())
    assert lost == {"ask_scribe", "reflection_ack"}
    for tool in sorted(lost):
        assert si.seat_tool_allowed(tool) == (False, "retired_unused_30d"), tool


def test_tools_the_old_scope_map_never_carried_are_now_reachable(registry, calls):
    """The ruling in its concrete form. Each of these was master-only by
    default-deny an hour ago; each is an ordinary act for a seated terminal.

    where_did_i_leave_off is the headline: every arriving seat is instructed to
    call it, and no seat but the master could.
    """
    for tool in (
        "where_did_i_leave_off",
        "record_catch",
        "record_learning",
        "supersede_insight",
        "thread_touch",
        "self_model",
        "the_ground",
        "signals_summary",
    ):
        assert si.seat_tool_allowed(tool) == (True, "ok"), tool
        assert call(client(), tool, seat_hdr()).status_code == 200, tool
    assert len(calls) == 8


def test_resolve_thread_by_id_is_a_seats_ordinary_act(registry, calls):
    """The ruling names this one explicitly: keep it ALLOWED. Closing a thread
    by its id is authorship. Bare `resolve_thread` — which resolves by MATCH,
    across threads a seat may not own — stays governance."""
    assert si.seat_tool_allowed("resolve_thread_by_id") == (True, "ok")
    assert si.seat_tool_allowed("resolve_thread") == (False, "governance")
    assert call(client(), "resolve_thread_by_id", seat_hdr()).status_code == 200


def test_a_tool_the_stack_no_longer_serves_is_denied_as_retired(registry, calls):
    """"minus anything the stack retires." The reason word says what was
    actually measured — 30-day disuse — rather than claiming the tool is gone,
    because the census this falls back to measures use, not retirement."""
    allowed, reason = si.seat_tool_allowed("synthesize_now")
    assert (allowed, reason) == (False, "retired_unused_30d")
    r = call(client(), "synthesize_now", seat_hdr())
    assert r.status_code == 403
    assert "census" in r.json()["detail"]
    assert not calls


def test_governance_beats_retirement_when_a_tool_is_both(registry, calls):
    """Six names are in both sets. The reason given must be the one that will
    still be true after the next census: governance."""
    both = si.SEAT_NEVER_TOOLS & si.SEAT_RETIRED_TOOLS
    assert both, "the overlap is the premise of this test"
    for tool in sorted(both & si.SEAT_TOOL_SURFACE):
        assert si.seat_tool_allowed(tool) == (False, "governance"), tool


def test_a_tool_the_stack_adds_later_is_denied_until_it_is_added_here(registry, calls):
    """DEFAULT-DENY SURVIVED THE WIDENING, and this is the proof. The base set
    is an ENUMERATION of what the stack publishes, not "whatever the caller
    names", so a name this release never heard of is refused."""
    assert si.seat_tool_allowed("some_tool_invented_next_week") == (False, "unpublished")
    r = call(client(), "some_tool_invented_next_week", seat_hdr())
    assert r.status_code == 403
    assert not calls


def test_the_published_surface_matches_the_stack_release_it_shipped_beside():
    """The enumeration is a MEASUREMENT with a date on it, so pin its size. A
    silent drift in this constant would silently change the policy: names lost
    become `unpublished` denials, names invented become grants."""
    assert len(si.SEAT_TOOL_SURFACE) == 100
    assert len(si.seat_allowed_tools()) == 48
    assert len(si.seat_denied_tools()) == 52
    reasons = {r for _, r in si.seat_denied_tools()}
    assert reasons == {"governance", "retired_unused_30d"}


# ── Signing ─────────────────────────────────────────────────────────────────


def test_write_is_signed_with_the_seat_id(registry, calls):
    call(client(), WRITE_TOOL, seat_hdr(), content="c", domain="d")
    assert calls[0][1]["source_instance"] == SEAT


def test_a_seat_cannot_claim_another_identity(registry, calls):
    """OVERRIDE, not setdefault. The body says HQ; the verified header says
    grok. The header wins, because the header is what the bridge checked."""
    call(
        client(),
        WRITE_TOOL,
        seat_hdr(),
        content="c",
        domain="d",
        source_instance="hq-claude-studio",
    )
    assert calls[0][1]["source_instance"] == SEAT


def test_reads_that_declare_source_instance_are_signed_too(registry, calls):
    call(client(), "arrive_lineage", seat_hdr())
    assert calls[0][1]["source_instance"] == SEAT


def test_unsignable_tools_are_never_injected_into(registry, calls):
    """Injecting source_instance into a tool that does not declare it is a hard
    ValueError upstream (_reject_unknown_params) or — worse — a SILENT DROP.

    The ruling widened the surface, so these tools are now ALLOWED where they
    used to be denied. That makes this test more important, not less: the
    bridge must still not inject into them, because a bridge that believed it
    signed while the record landed unattributed is the exact fail-open
    record_insight lived under until 2026-08-28.
    """
    for tool in ("archive_exchange", "record_catch", "thread_touch", "supersede_insight"):
        assert si.seat_tool_allowed(tool)[0] is True, tool
        args = si.sign_arguments(tool, {"content": "x", "source": "y"}, SEAT)
        assert "source_instance" not in args, tool


def test_every_signable_tool_declares_source_instance_upstream():
    """SEAT_SIGNABLE_TOOLS is a claim ABOUT THE STACK'S SCHEMAS, and a wrong
    entry here is a silent drop, not a loud error. So it is checked against the
    stack source rather than trusted — the constant was derived by parsing that
    source, and this re-derives it.

    Skips rather than fails when the stack tree is not on disk: a bridge
    checkout without its companion repo is a legitimate state, and turning that
    into a red suite would teach people to ignore a red suite.
    """
    import ast
    from pathlib import Path as _P

    candidates = [
        _P.home() / ".cache" / "wt-release-stack" / "src" / "sovereign_stack" / "server.py",
        _P.home() / "sovereign-stack" / "src" / "sovereign_stack" / "server.py",
    ]
    server = next((p for p in candidates if p.exists()), None)
    if server is None:
        pytest.skip("sovereign-stack source not on disk")

    declaring = set()
    for node in ast.walk(ast.parse(server.read_text())):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "Tool":
            name = None
            declares = False
            for kw in node.keywords:
                if kw.arg == "name" and isinstance(kw.value, ast.Constant):
                    name = kw.value.value
                if kw.arg == "inputSchema" and "'source_instance'" in ast.dump(kw.value):
                    declares = True
            if name and declares:
                declaring.add(name)

    assert si.SEAT_SIGNABLE_TOOLS <= declaring, (
        "a tool is signed that the stack does not declare source_instance on — "
        "the bridge would believe it signed while the record landed unattributed: "
        f"{sorted(si.SEAT_SIGNABLE_TOOLS - declaring)}"
    )
    # ...and every allowed tool that CAN sign, does.
    signable_and_allowed = declaring & set(si.seat_allowed_tools())
    assert signable_and_allowed <= si.SEAT_SIGNABLE_TOOLS, (
        "a tool the stack can attribute is going unsigned: "
        f"{sorted(signable_and_allowed - si.SEAT_SIGNABLE_TOOLS)}"
    )


# ── The other two auth paths are untouched ──────────────────────────────────


def test_bearer_wins_when_both_are_present(registry, calls):
    """No privilege escalation by adding a header: a master bearer PLUS a seat
    header is a master call, unsigned by the seat."""
    r = call(
        client(),
        "where_did_i_leave_off",
        {**seat_hdr(), "Authorization": f"Bearer {MASTER}"},
    )
    assert r.status_code == 200, "the master token lost reach it had"
    assert "source_instance" not in calls[0][1]


def test_a_bad_bearer_plus_a_seat_header_stays_a_bad_bearer(registry, calls):
    """THE ESCALATION THIS ORDERING EXISTS TO STOP. If the seat path were tried
    as a FALLBACK after a failed bearer, anyone holding a revoked or garbage
    token could recover the read+write surface by adding a guessable header.
    An Authorization header of ANY kind is decided by the bearer path alone."""
    r = call(
        client(),
        READ_TOOL,
        {**seat_hdr(), "Authorization": "Bearer svs_dead-token-that-does-not-exist"},
    )
    assert r.status_code == 403
    assert not calls


def test_master_path_is_unchanged(registry, calls):
    r = call(client(), READ_TOOL, {"Authorization": f"Bearer {MASTER}"})
    assert r.status_code == 200
    assert "source_instance" not in calls[0][1]


def test_writepath_auth_bypass_still_works(monkeypatch, calls):
    """tests/test_bridge_writepath.py bypasses auth with
    monkeypatch.setattr(bridge, "check_auth", lambda *a, **k: None). The new
    wrapper must keep routing through check_auth so that stays true — pinned
    here so a later refactor that short-circuits it fails loudly rather than
    quietly breaking a neighbouring suite."""
    monkeypatch.setattr(bridge, "check_auth", lambda *a, **k: None)
    r = client().post("/api/call", json={"tool": READ_TOOL, "arguments": {}})
    assert r.status_code == 200


# ── Audit ───────────────────────────────────────────────────────────────────


def test_every_seat_request_emits_one_audit_line(registry, calls, caplog):
    """Allowed AND denied. An audit trail that records refusals but not grants
    is the wrong half — and 'allowed' is the line that would vanish if this
    logger were left to the root config (bridge.py sets none, so lastResort
    emits WARNING and above only)."""
    stranger = "seat-that-was-never-seated"
    with caplog.at_level("INFO", logger="seat-auth"):
        si.audit_log.propagate = True  # caplog reads the root handler
        try:
            call(client(), READ_TOOL, seat_hdr())
            call(client(), "set_policy", seat_hdr())
            call(client(env_seat=stranger), READ_TOOL, seat_hdr(stranger))
        finally:
            si.audit_log.propagate = False

    lines = [r.getMessage() for r in caplog.records if r.name == "seat-auth"]
    assert len(lines) == 3
    # Fields are repr()'d now — see test_a_forged_audit_line_is_impossible.
    # The pid is on the line because attribution is the asset: the seat STRING
    # is what was already untrustworthy, the pid is what the kernel vouched for.
    assert f"seat='{SEAT}' pid=" in lines[0]
    assert f"tool='{READ_TOOL}' outcome='allowed' reason='ok'" in lines[0]
    assert f"pid='{os.getpid()}'" in lines[0], "the vouched pid was dropped"
    assert "outcome='denied' reason='governance'" in lines[1]
    assert "outcome='denied' reason='unknown_seat'" in lines[2]
    assert MASTER not in "".join(lines)


def test_a_forged_audit_line_is_impossible(registry, calls, caplog):
    """P2 AUDIT, reproduced then closed. Verbatim from the Codex review: "a tool
    name with a newline produced two physical log lines (forged audit text)."

    That is not cosmetic. The audit surface's whole contract is ONE LINE PER
    REQUEST, so anything that can emit two can write a record of a request that
    never happened — a denial that reads as a grant, a seat that reads as
    another seat. Both interpolated fields are caller-controlled, so both are
    exercised here.

    ASSERTED ON THE NEWLINE COUNT, not on the prose. A test that checked for
    the injected text's absence would pass against an implementation that
    merely stripped that one string.
    """
    injection = "recall_insights\n2026-01-01 seat-auth seat='hq-claude-studio' outcome='allowed'"
    with caplog.at_level("INFO", logger="seat-auth"):
        si.audit_log.propagate = True
        try:
            call(client(), injection, seat_hdr())
            si.audit("seat\r\nforged", "tool\nforged", "allowed", "ok")
        finally:
            si.audit_log.propagate = False

    lines = [r.getMessage() for r in caplog.records if r.name == "seat-auth"]
    assert lines, "the injected request emitted no audit line at all"
    for line in lines:
        assert "\n" not in line and "\r" not in line, f"audit line broke in two: {line!r}"
    # And the escaped form is still legible — bounded, not blanked.
    assert "recall_insights" in lines[0]


def test_an_enormous_field_is_bounded(caplog):
    """The other half of bounding: escaping a megabyte of seat id still writes a
    megabyte to the log. Truncation is MARKED so a reader can tell a bounded
    field from a short one."""
    with caplog.at_level("INFO", logger="seat-auth"):
        si.audit_log.propagate = True
        try:
            si.audit("s" * 10000, "t" * 10000, "denied", "unknown_seat")
        finally:
            si.audit_log.propagate = False
    line = [r.getMessage() for r in caplog.records if r.name == "seat-auth"][0]
    assert len(line) < 1000, "an audit field was not bounded"
    assert "TRUNCATED" in line, "truncation must be visible, not silent"


# ── Registry parsing: every failure is a 401, never a 500 ───────────────────


def test_deeply_nested_registry_is_a_401_not_a_500(registry, calls):
    """P2 REGISTRY, first half. Verbatim from the Codex review: "seat_identity
    leaves RecursionError uncaught (10,000-level nested array -> 500, must be
    401)."

    json.loads raises RecursionError on deep nesting, and RecursionError is NOT
    a ValueError, so it walked straight through the except clause. A 500 on the
    auth path is a fail-open in the sense that matters: it tells the caller the
    door is BROKEN rather than SHUT, it loses the audit line, and it is the one
    response a monitoring surface will treat as "our bug, retry later".

    The size cap is the real fix and the RecursionError catch is the belt, so
    this is asserted at BOTH sizes — a 10k-deep array is 20 KB and would sail
    under a size cap alone.
    """
    for depth in (10_000, 200):
        registry.path.write_text("[" * depth + "]" * depth)
        assert si.load_registry() is None, f"depth {depth} parsed as a registry"
        r = call(client(), READ_TOOL, seat_hdr())
        assert r.status_code == 401, f"depth {depth} did not return 401"
        assert _reason(READ_TOOL) == "no_registry"
    assert not calls


def test_duplicate_enabled_keys_cannot_re_enable_a_seat(registry, calls):
    """P2 REGISTRY, second half, and the nastier one. Verbatim: "duplicate
    'enabled' keys, first false then true -> 200 (last wins)."

    json.loads is last-wins, so the DISABLING half was the half that got
    dropped, and Anthony's revocation lever could be defeated by appending to
    the file rather than editing it. There is no honest winner to pick, so the
    file is refused whole.
    """
    registry.path.write_text(
        '{"seats": {"%s": {"enabled": false, "enabled": true}}}' % SEAT
    )
    assert si.load_registry() is None, "a duplicate key parsed into a registry"
    r = call(client(), READ_TOOL, seat_hdr())
    assert r.status_code == 401, "a disabled seat was re-enabled by a duplicate key"
    assert _reason(READ_TOOL) == "no_registry"
    assert not calls


def test_an_oversized_registry_is_refused(registry, calls):
    """A registry is a hand-written list of a few terminals. Anything past
    64 KiB is not one, and parsing it is work an unauthenticated caller should
    never be able to make the bridge do."""
    registry.path.write_text(
        json.dumps({"seats": {SEAT: {"enabled": True, "pad": "x" * si.REGISTRY_MAX_BYTES}}})
    )
    assert si.load_registry() is None
    assert call(client(), READ_TOOL, seat_hdr()).status_code == 401
    assert not calls


# ── FINDING 3: the registry read must be bounded and must never block ───────


def test_a_fifo_registry_cannot_block_the_bridge(registry, calls):
    """FINDING 3, the half that was a live outage rather than a bypass.

    A real FIFO at registry.json reports st_size 0, so the size check passed;
    `read_text()` then BLOCKED until a writer appeared. load_registry is called
    synchronously inside the async request path, so one bad local file would
    have stalled the whole event loop — every route, every caller, not just
    seats. Astra's repro killed the reader after 0.5s.

    O_NONBLOCK makes the open fail instead of waiting, and the answer is the
    fail-closed one: no registry, deny.

    ⚠ GUARDED WITH SIGALRM, because the failure mode of a regression here is a
    HANG, not a red assertion, and a suite that hangs is a suite people stop
    running. This works precisely where the /dev/zero guard above could not:
    an open on a writerless FIFO blocks INTERRUPTIBLY, so the alarm lands and
    the test fails in five seconds with a message naming the defect. (The
    unbounded device read does not block — it succeeds, repeatedly, into
    memory — which is why that case is tested at the guard instead.)
    """
    registry.path.unlink()
    os.mkfifo(registry.path)

    def _blocked(signum, frame):
        raise AssertionError(
            "load_registry blocked on a FIFO — the open is not O_NONBLOCK, and in "
            "production this call is synchronous inside the async request path, so "
            "one bad local file stalls the whole event loop"
        )

    previous = signal.signal(signal.SIGALRM, _blocked)
    signal.alarm(5)
    try:
        started = time.monotonic()
        assert si.load_registry() is None
        assert time.monotonic() - started < 2.0, "load_registry blocked on a FIFO"
        assert call(client(), READ_TOOL, seat_hdr()).status_code == 401
        assert _reason(READ_TOOL) == "no_registry"
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)
        registry.path.unlink()
    assert not calls


def test_a_directory_where_the_registry_should_be_is_refused(registry):
    """The general form: the OPENED DESCRIPTOR must be a regular file. An
    fstat-based check covers every non-regular kind at once, including the ones
    nobody enumerated."""
    registry.path.unlink()
    registry.path.mkdir()
    try:
        assert si.load_registry() is None
    finally:
        registry.path.rmdir()


def test_the_descriptor_check_covers_a_character_device(registry, tmp_path):
    """A character device is the FIFO's quieter sibling: it does not block, it
    ANSWERS — forever. `/dev/zero` under an unbounded read returns NUL bytes
    until the reader dies.

    ⚠ THIS TEST DELIBERATELY DOES NOT CALL load_registry() ON /dev/zero, AND
    THE REASON IS A MEASUREMENT, NOT A HUNCH. Falsifying the fix — reverting
    load_registry to its `stat()` + `read_text()` shape and pointing it at
    /dev/zero — produced a process that grew to 7.6 GB resident and entered
    UNINTERRUPTIBLE wait, where SIGKILL takes minutes to land. Moving the read
    into a subprocess did not help: `subprocess.run(timeout=...)` kills the
    child and then WAITS for it, so the parent hangs on the same
    uninterruptible child. Measured twice, 2026-09-06, both times on this
    machine.

    A regression test that can wedge the runner and eat its memory teaches
    people to skip the suite, which is worse than the bug it catches. So the
    GUARD is tested rather than the HAZARD: the premise (that /dev/zero is not
    a regular file) and the guard (that a non-regular descriptor is refused)
    are asserted separately, and they are the same single S_ISREG check that
    the directory case above drives end to end. Nothing here can read a byte
    from a device.
    """
    import stat as _stat

    fd = os.open("/dev/zero", os.O_RDONLY | os.O_NONBLOCK)
    try:
        mode = os.fstat(fd).st_mode
    finally:
        os.close(fd)
    # The premise: this is exactly the classification the guard keys on.
    assert _stat.S_ISCHR(mode) and not _stat.S_ISREG(mode)

    # The guard: a non-regular descriptor is refused before any read happens.
    # Proven on a FIFO with a live writer, which is safe to open and yields
    # nothing — the read loop would return b"" immediately, so a failure here
    # is the S_ISREG check being gone, never a hang.
    fifo = tmp_path / "not-a-file"
    os.mkfifo(fifo)
    reader = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)
    try:
        with pytest.raises(OSError, match="not a regular file"):
            si._read_registry_bytes(fifo)
    finally:
        os.close(reader)
        fifo.unlink()


def test_the_size_cap_bounds_the_bytes_actually_read(registry, monkeypatch):
    """FINDING 3, the half that was a bypass.

    Verbatim: "a controlled stat/read race fixture reported size 1 at stat
    time, then read and accepted a 65,599-byte valid registry, above the
    65,536-byte cap." `stat()` was the ONLY size check, so a file that grew
    between the stat and the read sailed past it.

    The fixture lies about st_size exactly as the race would, and the read must
    refuse on the bytes that actually arrive.
    """
    oversized = json.dumps({"seats": {SEAT: {"enabled": True}}, "pad": "x" * si.REGISTRY_MAX_BYTES})
    assert len(oversized) > si.REGISTRY_MAX_BYTES
    registry.path.write_text(oversized)

    real_stat = Path.stat
    tiny = os.stat_result((0o100644, 0, 0, 1, 0, 0, 1, 0, 0, 0))
    monkeypatch.setattr(
        Path, "stat", lambda p, *a, **kw: tiny if p == registry.path else real_stat(p, *a, **kw)
    )
    assert si.load_registry() is None, "the cap was enforced on stat, not on the read"


def test_a_symlink_to_a_real_registry_is_followed_deliberately(registry, tmp_path):
    """The symlink POLICY, stated as a test rather than left to inference.

    Following a symlink whose target is a regular file within the cap is
    allowed on purpose — the file is Anthony's own kill switch and he may keep
    it wherever he likes. What the descriptor check closes is the dangerous
    half, above: a symlink to a FIFO or a device can no longer block or bypass.
    """
    real = tmp_path / "elsewhere.json"
    real.write_text(json.dumps({"seats": {SEAT: {"enabled": True}}}))
    registry.path.unlink()
    os.symlink(real, registry.path)
    try:
        loaded = si.load_registry()
        assert loaded is not None and SEAT in loaded["seats"]
    finally:
        registry.path.unlink()


def test_a_registry_exactly_at_the_cap_still_loads(registry):
    """The falsifier for the bounded read: a cap that refuses everything would
    pass every test above. cap bytes load; cap+1 does not."""
    body = json.dumps({"seats": {SEAT: {"enabled": True}}})
    registry.path.write_text(body + " " * (si.REGISTRY_MAX_BYTES - len(body)))
    assert si.load_registry() is not None
    registry.path.write_text(registry.path.read_text() + " ")
    assert si.load_registry() is None


# ── FINDING 5: the denial must name the socket the bridge actually binds ────


def test_the_tcp_denial_names_the_socket_the_bridge_binds(registry):
    """FINDING 5. The denial said `<sovereign-root>/hq/seats/bridge.sock`; the
    bridge bound `hq/seats/sock/bridge.sock`. The wrong copy was the one in the
    error message — the only copy a locked-out caller ever reads.

    Asserted as an EQUALITY between the message and the bound path, not against
    a third hand-written literal, because a third copy is a third thing to
    drift.
    """
    try:
        si.resolve_seat(None, SEAT, {})
    except si.SeatDenied as denied:
        assert denied.reason == "not_socket"
        assert str(si.seat_socket_path()) in denied.detail
    else:  # pragma: no cover
        raise AssertionError("a TCP request was admitted to the seat path")

    assert bridge.seat_socket_path() == si.seat_socket_path()
    assert si.seat_socket_path().parts[-3:] == ("seats", "sock", "bridge.sock")


def test_the_socket_path_follows_sovereign_root(monkeypatch, tmp_path):
    """A module-level constant here would bind the LIVE path under test. Both
    copies must move together when SOVEREIGN_ROOT does."""
    monkeypatch.setenv("SOVEREIGN_ROOT", str(tmp_path))
    assert si.seat_socket_path() == tmp_path / "hq" / "seats" / "sock" / "bridge.sock"
    assert bridge.seat_socket_path() == si.seat_socket_path()
