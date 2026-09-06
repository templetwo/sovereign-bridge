"""Seat identity — the third auth path on POST /api/call.

Anthony, 2026-09-05: *"Inside my network, meaning seats I've put on the Studio,
no tokens... Every Studio terminal gets its seat identity in its environment so
every write signs itself."*

EVERY TEST HERE IS A FAIL-CLOSED PROOF. The dangerous direction for this feature
is not "a seat is wrongly refused" — it is "something that is not a seat gets
the read+write surface." So the deny cases are the point, and each one is
written so that it FAILS if the corresponding guard is removed.

THREE HARNESS TRAPS, each of which would silently turn a real check into a
no-op:

  1. TestClient's default peer address is the STRING "testclient", not an IP.
     A loopback check written against it would pass in tests and gate nothing in
     production. Every client here passes an explicit `client=` tuple, and the
     deny-side test uses a real non-loopback address.

  2. The registry path must be resolved fresh per request or SOVEREIGN_ROOT
     redirection is a no-op (bridge is imported at collection time, so a
     module-level constant is already bound). `registry` below sets the env var
     and NEVER touches the live ~/.sovereign — this suite writes to tmp_path
     only.

  3. tests/test_bridge_writepath.py monkeypatches bridge.check_auth to bypass
     auth. The new wrapper still routes the bearer branch THROUGH check_auth, so
     that bypass keeps working; test_writepath_auth_bypass_still_works below
     pins that, because breaking it would break a passing suite silently.
"""

import json
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import bridge  # noqa: E402
import seat_identity as si  # noqa: E402
import session_tokens as st  # noqa: E402

MASTER = "test-master-token-0123456789abcdef-0123456789abcdef"
SEAT = "grok-build-studio"

# The peer address a seated Studio terminal actually presents.
LOOPBACK_PEER = ("127.0.0.1", 51234)
# Something on the LAN. Not a seat, however friendly.
REMOTE_PEER = ("10.0.0.5", 51234)

READ_TOOL = "recall_insights"
WRITE_TOOL = "record_insight"


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


def client(peer=LOOPBACK_PEER):
    return TestClient(bridge.app, client=peer)


def call(c, tool, headers, **args):
    return c.post("/api/call", json={"tool": tool, "arguments": args}, headers=headers)


def seat_hdr(seat=SEAT):
    return {"X-Sovereign-Seat": seat}


def _reason(tool=READ_TOOL, seat=SEAT, peer=LOOPBACK_PEER, extra=None):
    """The machine-readable denial reason, taken from resolve_seat directly.

    An HTTP 401 says only THAT the door was shut. Several guards shut it, and a
    test that asserts on prose can pass because two different messages happen to
    share a word — which is exactly how the registry-absence test passed with
    its guard deleted. This reads the reason the code itself named.
    """
    headers = dict(extra or {})
    try:
        si.resolve_seat(peer[0], seat, headers)
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


def test_non_loopback_peer_is_refused(registry, calls):
    """The seat header is not a credential. Off this machine, it buys nothing."""
    r = call(client(REMOTE_PEER), READ_TOOL, seat_hdr())
    assert r.status_code == 401
    assert _reason(peer=REMOTE_PEER) == "not_loopback"
    assert not calls, "a refused request must never reach the stack"


def test_tunneled_request_is_refused_despite_loopback_peer(registry, calls):
    """THE HOLE THIS FEATURE WOULD OTHERWISE HAVE, and it is not hypothetical.

    cloudflared runs on this machine and connects to 127.0.0.1:8100, so a
    request from the open internet arrives with a LOOPBACK peer. bridge.py
    already relies on this: its rate limiter treats CF-Connecting-IP as proof of
    tunnel origin, and the connector route notes request.client.host is ALWAYS
    127.0.0.1. Peer-address-only would therefore have published the read+write
    surface to anyone who guessed a seat id, and seat ids are not secrets.
    """
    for header in ("CF-Connecting-IP", "X-Forwarded-For", "X-Real-IP", "Forwarded"):
        r = client().post(
            "/api/call",
            json={"tool": READ_TOOL, "arguments": {}},
            headers={**seat_hdr(), header: "203.0.113.9"},
        )
        assert r.status_code == 401, f"{header} did not deny"
        assert _reason(extra={header.lower(): "203.0.113.9"}) == "relayed"
    assert not calls


def test_unknown_seat_is_refused(registry, calls):
    r = call(client(), READ_TOOL, seat_hdr("seat-that-was-never-seated"))
    assert r.status_code == 401
    assert _reason(seat="seat-that-was-never-seated") == "unknown_seat"
    assert not calls


def test_disabled_seat_is_refused(registry, calls):
    """Registered is not the same as enabled — this is the revocation lever."""
    r = call(client(), READ_TOOL, seat_hdr("retired-seat"))
    assert r.status_code == 401
    assert _reason(seat="retired-seat") == "seat_disabled"
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
    for tool in ("set_policy", "open_protected_record", "resolve_thread_by_id", "govern"):
        r = call(client(), tool, seat_hdr())
        assert r.status_code == 403, f"{tool} reached the stack"
        assert r.json()["failure_class"] == "scope"
        assert si.seat_tool_allowed(tool) == (False, "governance"), tool
    assert not calls


def test_a_governance_tool_mapped_into_write_is_still_denied(monkeypatch):
    """The scenario the explicit list exists for, simulated: someone adds a
    governance tool to TOOL_SCOPES as 'write'. Default-deny no longer covers it.
    SEAT_NEVER_TOOLS must."""
    monkeypatch.setitem(st.TOOL_SCOPES, "set_policy", "write")
    assert si.seat_tool_allowed("set_policy") == (False, "governance")
    assert "set_policy" not in si.seat_allowed_tools()


def test_session_scope_tools_are_denied_to_a_seat(registry, calls):
    """close_session / spiral_inherit mutate global spiral state and sit in the
    'session' scope, which a read+write grant does not carry. A seat is a
    read+write grant, so it does not carry it either."""
    for tool in ("close_session", "spiral_inherit"):
        assert not si.seat_tool_allowed(tool)[0]
        assert call(client(), tool, seat_hdr()).status_code == 403
    assert not calls


def test_unsignable_writes_are_denied(registry, calls):
    """Every write on this path must sign itself. A write tool with no field to
    sign into is refused rather than written unsigned — narrowing the surface,
    never widening it."""
    for tool in ("archive_exchange", "reflection_ack", "spiral_reflect"):
        r = call(client(), tool, seat_hdr())
        assert r.status_code == 403, f"{tool} was allowed to write unsigned"
        assert "sign" in r.json()["detail"]
    assert not calls


def test_master_only_tool_is_denied_to_a_seat(registry, calls):
    """Unmapped => master-only, by the same default-deny session tokens use.
    where_did_i_leave_off is the named example and stays master-only."""
    r = call(client(), "where_did_i_leave_off", seat_hdr())
    assert r.status_code == 403
    assert not calls


def test_seat_surface_is_derived_from_the_session_scope_map():
    """Not hand-listed. If TOOL_SCOPES grows a read/write tool, the seat surface
    follows it — and a new WRITE tool is denied until it can sign."""
    allowed = set(si.seat_allowed_tools())
    read_write = {t for t, s in st.TOOL_SCOPES.items() if s in ("read", "write")}
    assert allowed <= read_write, "the seat path widened beyond read+write"
    assert allowed >= {t for t, s in st.TOOL_SCOPES.items() if s == "read"}


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
    ValueError upstream (_reject_unknown_params) or a silent drop. Neither is
    acceptable, so the bridge must not inject — which it enforces by denying
    those tools outright. Belt: the signer itself refuses too."""
    args = si.sign_arguments("archive_exchange", {"content": "x", "source": "y"}, SEAT)
    assert "source_instance" not in args


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
    with caplog.at_level("INFO", logger="seat-auth"):
        si.audit_log.propagate = True  # caplog reads the root handler
        try:
            call(client(), READ_TOOL, seat_hdr())
            call(client(), "set_policy", seat_hdr())
            call(client(), READ_TOOL, seat_hdr("seat-that-was-never-seated"))
        finally:
            si.audit_log.propagate = False

    lines = [r.getMessage() for r in caplog.records if r.name == "seat-auth"]
    assert len(lines) == 3
    assert f"seat={SEAT} tool={READ_TOOL} outcome=allowed reason=ok" in lines[0]
    assert "outcome=denied reason=governance" in lines[1]
    assert "outcome=denied reason=unknown_seat" in lines[2]
    assert MASTER not in "".join(lines)
