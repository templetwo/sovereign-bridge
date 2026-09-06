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
# The pinned surface lives in suite_support so every suite decides against the
# same one; see its module docstring for why it is not resolved live.
from suite_support import (  # noqa: E402
    PINNED_PUBLISHED,
    PINNED_RETIRED,
    release_stack_surface,
)
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


@pytest.fixture
def caller_channel(monkeypatch, calls):
    """A stand-in for `sovereign_stack.dispatch_context`, plus a tap on it.

    ⚠ A STUB, BECAUSE THE REAL MODULE DOES NOT EXIST YET. The stack round adds
    it; this bridge release must be provable before and after that lands, and a
    test that could only run against a deployed stack is a test nobody runs.
    The stub implements the exact contract the bridge uses —
    `set_caller_seat(seat) -> token` and `reset_caller_seat(token)` over a real
    `contextvars.ContextVar` — so what is exercised is the bridge's use of the
    channel, which is the half this repo owns.

    Records three things, each answering a different question:
      seen    — the seat the STACK would have observed, read inside dispatch.
      after   — the value in-context immediately after the reset. Read there
                because reading it from the test thread afterwards returns None
                whether or not the reset ran: a test that cannot fail.
      balance — set/reset pairing. Non-zero is a leak even if `after` is clean.
    """
    import contextvars

    var = contextvars.ContextVar("caller_seat_test", default=None)
    state = {"seen": [], "after": [], "balance": 0}

    class _Stub:
        @staticmethod
        def set_caller_seat(seat):
            state["balance"] += 1
            return var.set(seat)

        @staticmethod
        def reset_caller_seat(token):
            state["balance"] -= 1
            if token is not None:
                var.reset(token)
            state["after"].append(var.get())

    monkeypatch.setattr(si, "dispatch_context_module", lambda: _Stub)

    inner = bridge.call_mcp_tool

    async def recording(tool, args):
        state["seen"].append(var.get())
        return await inner(tool, args)

    monkeypatch.setattr(bridge, "call_mcp_tool", recording)
    return state


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


def test_governance_tool_is_denied_to_a_seat(registry, calls, surface):
    """Denied AS GOVERNANCE, by name — not incidentally.

    Assert on the REASON the code gives, not just the 403. Several rules refuse
    a tool, and a test that only reads the status code passes when the tool
    stops being published for an unrelated reason — which would mean the
    governance list had quietly stopped being load-bearing without anything
    going red.
    """
    for tool in ("set_policy", "open_protected_record", "resolve_thread", "govern"):
        r = call(client(), tool, seat_hdr())
        assert r.status_code == 403, f"{tool} reached the stack"
        assert r.json()["failure_class"] == "scope"
        assert si.seat_tool_allowed(tool, surface) == (False, "governance"), tool
    assert not calls


def test_governance_is_checked_before_publication(registry, calls, surface):
    """⚠ THE ORDER CHANGED IN THIS RELEASE, AND THE CHANGE IS THE TEST.

    `open_protected_record`, `resolve_thread`, `govern` and `retire_hypothesis`
    are governance names the stack RETIRED on 2026-09-06, so they are no longer
    published. Under the previous order (publication first) each would now be
    refused `unpublished` — a word that reads as "this tool does not exist"
    about tools that very much do and are RESERVED. The reason a caller reads
    must be the one still true after the next stack release.
    """
    for tool in ("open_protected_record", "resolve_thread", "govern", "retire_hypothesis"):
        assert tool not in surface.published, f"{tool} is published; premise gone"
        assert si.seat_tool_allowed(tool, surface) == (False, "governance"), tool


def test_a_governance_tool_is_denied_however_it_is_classified_elsewhere(monkeypatch, surface):
    """The scenario the explicit list exists for: someone reclassifies a
    governance tool somewhere else in the codebase. SEAT_NEVER_TOOLS must still
    hold, because it is the only list that is ABOUT governance."""
    monkeypatch.setitem(st.TOOL_SCOPES, "set_policy", "write")
    assert si.seat_tool_allowed("set_policy", surface) == (False, "governance")
    assert "set_policy" not in si.seat_allowed_tools(surface)


def test_session_lifecycle_tools_stay_as_they_were(registry, calls, surface):
    """ANTHONY'S RULING, the clause that is a NON-change: "close_session /
    spiral_inherit stay as they were."

    They mutate GLOBAL spiral state — the session id and phase every other seat
    then reads — so widening the surface to all studio seats does not reach
    them. This test exists because it is the easiest clause to lose while
    implementing the widening around it.
    """
    for tool in ("close_session", "spiral_inherit"):
        assert si.seat_tool_allowed(tool, surface) == (False, "governance"), tool
        assert call(client(), tool, seat_hdr()).status_code == 403
    assert not calls


def test_the_ruling_widened_the_surface_to_the_published_tools(registry, calls, surface):
    """ANTHONY'S RULING, 2026-09-06: "all studio seats are trusted."

    THE SHAPE, now with ONE subtraction: allowed = published - governance.
    Asserted as the equation, not as a hand-copied list, so a change to either
    input moves the surface and this test follows it.
    """
    allowed = set(si.seat_allowed_tools(surface))
    assert allowed == surface.published - si.SEAT_NEVER_TOOLS
    old_surface = {t for t, sc in st.TOOL_SCOPES.items() if sc in ("read", "write")}
    assert len(allowed) > 2 * len(old_surface), "the ruling widened the surface"


def test_a_seat_is_never_narrower_than_a_session_grant(registry, calls, surface):
    """⚠ THIS TEST USED TO ASSERT THE OPPOSITE, AND THAT IS THE POINT.

    The previous release pinned an honest defect under the name
    `test_the_widening_also_NARROWS_in_exactly_two_places`: subtracting a
    census-derived RETIRED set took `ask_scribe` and `reflection_ack` away from
    seats while a scoped session grant could still call them, so a seated
    Studio terminal - the thing Anthony called TRUSTED - reached two fewer
    tools than an outside visitor. Backwards on its face, and left visible
    rather than fixed by someone's judgement, because the census was not the
    stack's decision to make.

    Deleting the census closed it in the only honest direction: those two names
    are now denied because THE STACK retired them, and a session grant calling
    them gets a retired-tool error from the stack. The invariant that survives,
    and the one HQ decision D2 names: on any tool the stack actually PUBLISHES,
    a seat is never narrower than a read+write session grant.
    """
    session_grant = {t for t, sc in st.TOOL_SCOPES.items() if sc in ("read", "write")}
    published_grant = session_grant & surface.published
    assert published_grant, "the premise is gone: the grant map publishes nothing"
    lost = published_grant - set(si.seat_allowed_tools(surface))
    assert lost == set(), (
        "a seated Studio terminal reaches fewer PUBLISHED tools than a scoped "
        f"outside visitor: {sorted(lost)}"
    )
    # ...and the two names the old defect was about are gone from the grant's
    # reach for the stack's own reason, not this bridge's.
    assert {"ask_scribe", "reflection_ack"} <= session_grant
    assert {"ask_scribe", "reflection_ack"} <= surface.retired


def test_tools_the_old_scope_map_never_carried_are_now_reachable(registry, calls, surface):
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
        assert si.seat_tool_allowed(tool, surface) == (True, "ok"), tool
        assert call(client(), tool, seat_hdr()).status_code == 200, tool
    assert len(calls) == 8


def test_signal_ack_is_a_watch_seats_ordinary_act(registry, calls, surface, caller_channel):
    """HQ DECISION D1, 2026-09-06 - a REVERSAL of the previous release, pinned.

    `signal_ack` shipped DENIED as governance, on the stack's own `govern`
    intent label, flagged at Anthony's gate rather than decided quietly. HQ
    ruled the other way: acknowledging a signal is the watch seat's operational
    act, and Anthony's governance list is laws, policies, seat permissions,
    ring placement and deletes. Classifying it govern left the designated watch
    seat with no way to close anything it was seated to watch.
    """
    assert "signal_ack" not in si.SEAT_NEVER_TOOLS
    assert si.seat_tool_allowed("signal_ack", surface) == (True, "ok")
    r = call(client(), "signal_ack", seat_hdr(), signal_id="sig-1", state="acknowledged")
    assert r.status_code == 200, r.text
    assert calls[0][0] == "signal_ack"


def test_the_verified_seat_travels_in_process_not_as_an_argument(
    registry, calls, surface, caller_channel
):
    """D1 AS AMENDED, 2026-09-06 — and the amendment is the security property.

    The first implementation injected `actor_seat` into signal_ack's arguments
    and the stack trusted it "because the bridge overwrites it". An ARGUMENT is
    a channel every caller can write to, so that trust rested on the bridge
    being the only writer — not a property the stack can check. The identity
    now travels through `sovereign_stack.dispatch_context`, a contextvar
    nothing on the wire can reach, and the stack refuses the argument outright.

    Asserted BOTH ways: the seat is visible in the context at dispatch time,
    and no closer-shaped argument is on the call.
    """
    call(client(), "signal_ack", seat_hdr(), signal_id="sig-1", state="acted", reason="fixed")
    assert caller_channel["seen"] == [SEAT], "the stack could not see the calling seat"
    assert calls[0][1] == {"signal_id": "sig-1", "state": "acted", "reason": "fixed"}


def test_the_context_is_reset_after_the_call(registry, calls, surface, caller_channel):
    """⚠ A LEAKED CONTEXTVAR ATTRIBUTES THE NEXT CALLER'S WRITE TO THE LAST ONE.

    `after` is read INSIDE the request's own context, immediately after the
    reset — the only place the question can actually be asked. Reading the var
    from the test's thread afterwards would return None whether the reset
    happened or not, which is a test that cannot fail.
    """
    call(client(), "signal_ack", seat_hdr(), signal_id="sig-1", state="acknowledged")
    assert caller_channel["seen"] == [SEAT]
    assert caller_channel["after"] == [None], "the seat outlived its request"
    assert caller_channel["balance"] == 0, "set and reset are not paired"


def test_the_context_is_reset_even_when_the_stack_raises(
    registry, surface, caller_channel, monkeypatch
):
    """The `finally` earns its keep here. An upstream that raises is exactly
    where a leak is most likely and least noticed."""

    async def boom(tool, args):
        raise RuntimeError("upstream exploded")

    monkeypatch.setattr(bridge, "call_mcp_tool", boom)
    with pytest.raises(RuntimeError):
        call(client(), "signal_ack", seat_hdr(), signal_id="sig-1", state="acknowledged")
    assert caller_channel["after"] == [None], "the seat leaked past a failed call"
    assert caller_channel["balance"] == 0


def test_a_client_supplied_actor_is_refused_not_overwritten(
    registry, calls, surface, caller_channel
):
    """Five names, each an attempt to name the closer. Refused, not silently
    replaced: overwriting leaves the caller believing it named the actor, and
    the difference only surfaces later when the record says someone else."""
    for name in si.SEAT_ACTOR_FORBIDDEN_ARGS:
        r = call(
            client(), "signal_ack", seat_hdr(),
            signal_id="sig-1", state="acknowledged", **{name: "hq-claude-studio"},
        )
        assert r.status_code == 403, f"{name!r} was accepted"
        assert name in r.json()["detail"], name
    assert not calls, "a call carrying a forged actor reached the stack"


def test_signal_ack_is_refused_when_the_stack_has_no_caller_channel(
    registry, calls, surface, monkeypatch
):
    """FAIL CLOSED AGAINST AN OLDER STACK, rather than falling back.

    Without `dispatch_context` the closer would be stamped from the server's
    shared spiral session — the SERVER, not the seat — so the record would name
    the wrong actor while looking correct. Refusing is the honest answer, and
    the reason names the deploy order rather than blaming the caller.
    """
    monkeypatch.setattr(si, "dispatch_context_module", lambda: None)
    r = call(client(), "signal_ack", seat_hdr(), signal_id="sig-1", state="acknowledged")
    assert r.status_code == 403
    assert "dispatch_context" in r.json()["detail"]
    assert "Deploy the stack release first" in r.json()["detail"]
    assert not calls
    # ...and it is signal_ack ONLY. An absent channel must not take the rest of
    # the seat surface down with it.
    assert call(client(), "recall_insights", seat_hdr()).status_code == 200


def test_the_caller_channel_is_measured_in_the_WRONG_PROCESS(monkeypatch):
    """⚠ THE D1 RESIDUAL, PINNED. A PASSING TEST THAT DOCUMENTS A BOUND.

    The three tests above prove this bridge sets and resets the contextvar
    correctly around the dispatch. They cannot prove the STACK reads it,
    because the stub that stands in for `dispatch_context` lives in the pytest
    process and so does the fake upstream. The real dispatch does not:
    `call_mcp_tool` opens `sse_client(MCP_SSE_URL)` to another process, and a
    contextvar is per-process.

    Two assertions, and together they are the whole finding:

      1. the dispatch crosses a process boundary (an http:// SSE transport);
      2. the refusal lifts on a LOCAL IMPORT SUCCEEDING — a fact about this
         process, measured on a channel that terminates in this process.

    So the day `sovereign_stack/dispatch_context.py` becomes importable here,
    signal_ack starts returning 200 for seats whether or not the seat reaches
    the handler. That is a fail-open on a timer, and it is the stack's half of
    the contract to close (carry the seat across the SSE hop). This test exists
    so nobody reads the green suite as evidence the channel works, and so the
    day the assumption changes, something says so out loud.
    """
    import inspect

    assert bridge.MCP_SSE_URL.startswith(("http://", "https://")), (
        "the dispatch is no longer an out-of-process transport — re-derive this bound"
    )
    src = inspect.getsource(bridge.call_mcp_tool)
    assert "sse_client(MCP_SSE_URL" in src, (
        "call_mcp_tool no longer dispatches over SSE; if it now runs the tool "
        "IN-PROCESS the contextvar would actually reach it, and this whole "
        "residual should be re-measured rather than left as prose"
    )

    # The refusal keys on an import in THIS process, nothing more.
    monkeypatch.setattr(si, "dispatch_context_module", lambda: object())
    assert si.actor_channel_refusal("signal_ack") is None, (
        "a bare local import is what lifts the refusal — that is the bound"
    )
    monkeypatch.setattr(si, "dispatch_context_module", lambda: None)
    assert si.actor_channel_refusal("signal_ack")[0] == "no_caller_channel"


def test_a_bearer_call_carries_no_seat_and_no_actor(
    registry, calls, surface, caller_channel
):
    """THE GUARD D1 SAYS TO KEEP. A request with an Authorization header is
    decided by the bearer path and never reaches resolve_seat, so nothing is
    set: the context stays empty, no argument is injected, and the stack falls
    back to its own identity resolution. Adding X-Sovereign-Seat to a bearer
    call must not buy a verified-looking actor."""
    r = call(
        client(),
        "signal_ack",
        {**seat_hdr(), "Authorization": f"Bearer {MASTER}"},
        signal_id="sig-1",
        state="acknowledged",
    )
    assert r.status_code == 200, r.text
    assert "actor_seat" not in calls[0][1]
    assert caller_channel["seen"] == [None], "a bearer call named a seat to the stack"


def test_resolve_thread_by_id_is_a_seats_ordinary_act(registry, calls, surface):
    """The ruling names this one explicitly: keep it ALLOWED. Closing a thread
    by its id is authorship. Bare `resolve_thread` - which resolves by MATCH,
    across threads a seat may not own - stays governance."""
    assert si.seat_tool_allowed("resolve_thread_by_id", surface) == (True, "ok")
    assert si.seat_tool_allowed("resolve_thread", surface) == (False, "governance")
    assert call(client(), "resolve_thread_by_id", seat_hdr()).status_code == 200


def test_a_tool_the_stack_retired_is_denied_as_retired(registry, calls, surface):
    """"minus anything the stack retires" - and it is now the STACK saying so.

    The reason word changed from `retired_unused_30d` to `retired` because what
    is being reported changed: this bridge no longer measures 30-day disuse and
    calls it retirement. It reads `RETIRED_TOOLS` off the stack's own registry.
    """
    allowed, reason = si.seat_tool_allowed("synthesize_now", surface)
    assert (allowed, reason) == (False, "retired")
    r = call(client(), "synthesize_now", seat_hdr())
    assert r.status_code == 403
    assert "retired by the stack itself" in r.json()["detail"]
    assert not calls


def test_a_tool_the_stack_adds_later_is_denied_until_it_publishes_it(registry, calls, surface):
    """DEFAULT-DENY SURVIVED THE WIDENING, and this is the proof. The base set
    is what the stack PUBLISHES, so a name nothing publishes is refused."""
    assert si.seat_tool_allowed("some_tool_invented_next_week", surface) == (
        False,
        "unpublished",
    )
    r = call(client(), "some_tool_invented_next_week", seat_hdr())
    assert r.status_code == 403
    assert not calls


def test_the_pinned_surface_is_the_stack_release(registry, calls):
    """⚠ THE ONE TEST THAT CHECKS THE COPY. Everything above decides against
    PINNED_SURFACE; this asserts PINNED_SURFACE is what the stack release
    actually publishes, measured from its source in a subprocess.

    HQ decision D10: the test this replaces
    (`test_the_published_surface_matches_the_stack_release_it_shipped_beside`)
    asserted three CARDINALITIES - 100 / 48 / 52 - against a constant defined
    in the same repo. Three numbers agreeing with themselves is not an
    inventory comparison, and it would have stayed green through any rename
    that preserved the count.

    Skips rather than fails when the stack source is absent: a bridge checkout
    without its companion repo is a legitimate state, and a red suite for it
    teaches people to ignore a red suite.
    """
    published, retired, tree = release_stack_surface()
    assert published == PINNED_PUBLISHED, (
        f"the pinned published surface has drifted from {tree}: "
        f"missing {sorted(published - PINNED_PUBLISHED)}, "
        f"stale {sorted(PINNED_PUBLISHED - published)}"
    )
    assert retired == PINNED_RETIRED, (
        f"the pinned retired set has drifted from {tree}: "
        f"missing {sorted(retired - PINNED_RETIRED)}, "
        f"stale {sorted(PINNED_RETIRED - retired)}"
    )


def test_the_seat_reaches_49_of_the_52_published_tools(registry, calls, surface):
    """HQ decision D10's expected arithmetic, after admitting signal_ack:
    49 allowed / 3 governance-denied of 52 published.

    The three are named, not counted: a count alone would survive swapping one
    denial for another.
    """
    allowed = si.seat_allowed_tools(surface)
    denied = si.seat_denied_tools(surface)
    assert len(surface.published) == 52
    assert len(allowed) == 49, sorted(set(surface.published) - set(allowed))
    assert [t for t, _ in denied] == ["close_session", "set_policy", "spiral_inherit"]
    assert {r for _, r in denied} == {"governance"}


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


def test_unsignable_tools_are_never_injected_into(registry, calls, surface):
    """Injecting source_instance into a tool that does not declare it is a hard
    ValueError upstream (_reject_unknown_params) or — worse — a SILENT DROP.

    The ruling widened the surface, so these tools are now ALLOWED where they
    used to be denied. That makes this test more important, not less: the
    bridge must still not inject into them, because a bridge that believed it
    signed while the record landed unattributed is the exact fail-open
    record_insight lived under until 2026-08-28.
    """
    for tool in ("archive_exchange", "record_catch", "thread_touch", "supersede_insight"):
        assert si.seat_tool_allowed(tool, surface)[0] is True, tool
        args = si.sign_arguments(tool, {"content": "x", "source": "y"}, SEAT)
        assert "source_instance" not in args, tool
        # ...and the actor field is just as narrow: signal_ack only.
        assert "actor_seat" not in args, tool


def test_every_signable_tool_declares_source_instance_upstream(surface):
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
    signable_and_allowed = declaring & set(si.seat_allowed_tools(surface))
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


def _audit_lines(caplog, run):
    with caplog.at_level("INFO", logger="seat-auth"):
        si.audit_log.propagate = True
        try:
            run()
        finally:
            si.audit_log.propagate = False
    return [r.getMessage() for r in caplog.records if r.name == "seat-auth"]


def test_the_audit_line_names_all_three_pids(registry, calls, caplog, surface):
    """HQ DECISION D6, from review F2 — THE README PROMISED THIS AND THE CODE
    DID NOT KEEP IT.

    README.md said the connection's opener "is recorded only as `accept_pid` in
    the audit line". It was not. `accept_pid` and `seat_pid` survived in the
    protocol extension and died at the auth context; the audit line carried the
    sender's pid alone. A promise in the documentation that the code does not
    keep is worse than a missing field, because the next reader believes the
    forensics exist and does not go looking.

    The three answer different questions and only together tell the story:
      pid        — who SENT this request (decides the call).
      seat_pid   — whose ENVIRONMENT named the seat. Differs from pid when the
                   seat was INHERITED rather than declared.
      accept_pid — who OPENED the connection. Differs from pid exactly when the
                   descriptor changed hands, which is F2's signature.
    """
    verified = peer(SEAT, pid=4242, seat_pid=4200, accept_pid=4100)
    lines = _audit_lines(
        caplog, lambda: call(client(verified=verified), READ_TOOL, seat_hdr())
    )
    assert len(lines) == 1
    assert "pid='4242'" in lines[0], "the sender's pid was dropped"
    assert "seat_pid='4200'" in lines[0], "the environment-owning pid was dropped"
    assert "accept_pid='4100'" in lines[0], "the connection opener was dropped"
    assert "outcome='allowed'" in lines[0]


def test_a_denial_names_all_three_pids_too(registry, calls, caplog, surface):
    """⚠ THE DENIAL LINE IS WHERE THESE FIELDS EARN THEIR KEEP, so a forensic
    field that only appeared on success would be absent from every event worth
    investigating.

    `seat_mismatch` is precisely the case where accept_pid != pid is the
    explanation — a descriptor handed to a differently-seated process — and it
    is the one line a reader will come back to.
    """
    verified = peer("codex-astra-studio", pid=5555, seat_pid=5550, accept_pid=5500)
    lines = _audit_lines(
        caplog, lambda: call(client(verified=verified), READ_TOOL, seat_hdr(SEAT))
    )
    assert len(lines) == 1
    assert "outcome='denied' reason='seat_mismatch'" in lines[0]
    assert "pid='5555'" in lines[0]
    assert "seat_pid='5550'" in lines[0]
    assert "accept_pid='5500'" in lines[0]


def test_absent_pids_render_as_a_dash_not_as_a_guess(registry, calls, caplog, surface):
    """A TCP denial never resolved a peer, so there is nothing to name. `-` is
    the honest rendering; a zero or an empty string would read as a measured
    value of nothing."""
    lines = _audit_lines(
        caplog, lambda: tcp_client().post(
            "/api/call",
            json={"tool": READ_TOOL, "arguments": {}},
            headers=seat_hdr(),
        )
    )
    assert len(lines) == 1
    assert "pid=- seat_pid=- accept_pid=-" in lines[0]


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
