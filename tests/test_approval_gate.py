"""Regression coverage for The Door That Asks — connector-authorize approval
(approval_gate.py), added post-verify (FIX 4). Before this file,
approval_gate.py — the atomic single-use flip, the rate caps, the 900s
expiry — had ZERO test coverage; the connector tests only mock the bridge.

Mirrors tests/test_arrival_gate.py's fixture shape (isolated tmp SQLite,
ntfy + call_mcp_tool monkeypatched) but exercises the approval-only sibling
path: request -> decide (POST-only, signed) -> confirm (atomic
approved->consumed, NO mint — a connector authorization is a yes/no gate,
never a session-token grant, HQ ruling #6/#8).

Also covers the three post-verify fixes on top of the original build:
  FIX 1 — status_approval() must NOT emit slow_down and must NOT
          force-expire a pending row on poll count; only the 900s
          pending-window expiry applies (master-gated path, see
          approval_gate.status_approval docstring).
  FIX 2 — the confirm-path provenance write is fire-and-forget
          (asyncio.create_task); not independently testable from here
          since it's detached from the response, so this file does not
          assert on its landing — only on confirm's own behavior.
  FIX 3 — the per-IP + global-backstop PENDING caps (create_approval takes
          requester_ip directly; the bridge route forwards it from the
          request body, not request.client.host).
"""

import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import approval_gate as apg  # noqa: E402
import bridge  # noqa: E402
import session_tokens as st  # noqa: E402

MASTER = "test-master-token-0123456789abcdef-0123456789abcdef"
SECRET = "test-decide-secret"
REDIRECT = "https://claude.ai/api/mcp/auth_callback"


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setattr(st, "DB_PATH", tmp_path / "session_tokens.db")
    monkeypatch.setattr(bridge, "BEARER_TOKEN", MASTER)
    monkeypatch.setenv("ARRIVAL_DECIDE_SECRET", SECRET)
    monkeypatch.setenv("ARRIVAL_GATE_ENABLED", "true")
    monkeypatch.delenv("NTFY_TOPIC", raising=False)

    async def no_ntfy(payload):
        return True

    monkeypatch.setattr(bridge, "_ntfy_publish", no_ntfy)

    recorded = []

    async def fake_tool(tool, args):
        recorded.append((tool, args))
        return {"ok": True, "result": "recorded"}

    monkeypatch.setattr(bridge, "call_mcp_tool", fake_tool)
    # Persistent portal — entering via `with` gives the whole test ONE event
    # loop for the client's lifetime, matching how a real server's loop lives
    # for the whole process rather than per-request. Without `with`,
    # TestClient opens and tears down a FRESH portal/loop around every single
    # .get()/.post() call; that per-call teardown blocks on any
    # asyncio.create_task-detached work still in flight, which would make
    # FIX 2's fire-and-forget provenance write look synchronous in tests even
    # though it is genuinely detached under uvicorn's persistent loop.
    with TestClient(bridge.app) as c:
        c.recorded = recorded
        yield c


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def _create(client, ip="9.9.9.9", **kw):
    body = {
        "client_id": "claude-ai",
        "redirect_uri": REDIRECT,
        "requester_ip": ip,
        **kw,
    }
    r = client.post("/api/approval/request", json=body, headers=_auth(MASTER))
    assert r.status_code == 201, r.text
    return r.json()


def _signed(aid, action, exp=None):
    exp = exp or int(time.time()) + 600
    return {"aid": aid, "action": action, "exp": exp, "sig": apg.sign_decide(aid, action, exp)}


def _status(client, aid):
    r = client.get(f"/api/approval/status/{aid}", headers=_auth(MASTER))
    assert r.status_code == 200, r.text
    return r.json()


def _confirm(client, aid):
    r = client.post(
        "/api/approval/confirm", json={"approval_id": aid}, headers=_auth(MASTER)
    )
    assert r.status_code == 200, r.text
    return r.json()


# === create_approval ========================================================

def test_create_returns_pending_with_two_word_code(client):
    created = _create(client)
    assert created["status"] == "pending"
    assert "-" in created["code"]
    assert created["approval_id"].startswith("apr_")


def test_duplicate_suppression_within_60s(client):
    first = _create(client, ip="1.2.3.4")
    second = _create(client, ip="1.2.3.4")
    assert second["approval_id"] == first["approval_id"]
    assert second.get("duplicate_of_recent_request") is True
    # Optional fix: dup path explicitly signals no NEW push fired, rather
    # than omitting the key (which let the SSE default it to True).
    assert second.get("notification_sent") is False


def test_per_ip_pending_cap_blocks_same_ip(client):
    ip = "203.0.113.5"
    for i in range(apg.MAX_PENDING_PER_IP):
        _create(client, ip=ip, client_id=f"client-{i}")
    over = client.post(
        "/api/approval/request",
        json={"client_id": "client-overflow", "redirect_uri": REDIRECT, "requester_ip": ip},
        headers=_auth(MASTER),
    )
    assert over.status_code == 429
    body = over.json()
    assert body["failure_class"] == "rate_limited"
    assert "per-IP" in body["detail"]


def test_per_ip_pending_cap_lets_a_different_ip_through(client):
    """FIX 3: the connector PENDING cap is per-IP, not global — an IP at its
    own cap must not lock out a different IP (this is the exact DoS the fix
    closes: an unauthenticated attacker filling the old global-3 cap and
    locking Anthony out with no break-glass, HQ ruling #6)."""
    ip_a = "203.0.113.5"
    ip_b = "198.51.100.7"
    for i in range(apg.MAX_PENDING_PER_IP):
        _create(client, ip=ip_a, client_id=f"a-client-{i}")
    blocked = client.post(
        "/api/approval/request",
        json={"client_id": "a-overflow", "redirect_uri": REDIRECT, "requester_ip": ip_a},
        headers=_auth(MASTER),
    )
    assert blocked.status_code == 429

    ok = client.post(
        "/api/approval/request",
        json={"client_id": "b-client", "redirect_uri": REDIRECT, "requester_ip": ip_b},
        headers=_auth(MASTER),
    )
    assert ok.status_code == 201, ok.text


def test_global_backstop_still_applies_across_many_ips(client, monkeypatch):
    """A multi-IP botnet is still bounded by the (much higher) global
    backstop, even though no single IP is at its own cap."""
    monkeypatch.setattr(apg, "MAX_PENDING_GLOBAL", 4)
    for i in range(4):
        _create(client, ip=f"10.0.0.{i}", client_id=f"g-client-{i}")
    over = client.post(
        "/api/approval/request",
        json={"client_id": "g-overflow", "redirect_uri": REDIRECT, "requester_ip": "10.0.0.99"},
        headers=_auth(MASTER),
    )
    assert over.status_code == 429
    assert "global" in over.json()["detail"]


def test_requester_ip_falls_back_when_sse_omits_it(client):
    """The bridge route must keep working even before the SSE-side forward
    ships (defense in depth / staged rollout) — omitting requester_ip must
    not error, it should fall back to header/loopback."""
    r = client.post(
        "/api/approval/request",
        json={"client_id": "no-ip-client", "redirect_uri": REDIRECT},
        headers=_auth(MASTER),
    )
    assert r.status_code == 201, r.text


# === decide_approval =========================================================

def test_decide_approve_then_deny_is_already_decided(client):
    aid = _create(client)["approval_id"]
    r1 = client.post("/api/approval/decide", params=_signed(aid, "approve"))
    assert r1.status_code == 200
    r2 = client.post("/api/approval/decide", params=_signed(aid, "deny"))
    assert "Already decided" in r2.text
    assert _status(client, aid)["status"] == "approved"


def test_deny_path(client):
    aid = _create(client)["approval_id"]
    client.post("/api/approval/decide", params=_signed(aid, "deny"))
    status = _status(client, aid)
    assert status["status"] == "denied"
    assert status["failure_class"] == "approval_denied"
    confirm = _confirm(client, aid)
    assert confirm["approved"] is False
    assert confirm["reason"] == "denied"


def test_decide_signature_discipline_and_get_never_decides(client):
    aid = _create(client)["approval_id"]
    bad = _signed(aid, "approve")
    bad["sig"] = "0" * 64
    assert client.post("/api/approval/decide", params=bad).status_code == 403
    stale = _signed(aid, "approve", exp=int(time.time()) - 10)
    assert client.post("/api/approval/decide", params=stale).status_code == 403

    good = _signed(aid, "approve")
    page = client.get("/api/approval/decide", params=good)
    assert page.status_code == 200
    assert "<form" in page.text
    # GET rendered a page but decided nothing.
    assert _status(client, aid)["status"] == "pending"


# === status_approval — FIX 1 (no slow_down, no force-expire on poll count) ==

def test_status_rapid_polls_never_slow_down_or_force_expire(client):
    """FIX 1: the connector status endpoint is MASTER-gated — the ONLY
    poller is the trusted SSE (~5s on behalf of one browser tab, which
    background-tab throttling routinely clusters under arrival's old 4.5s
    anti-abuse threshold). status_approval() must never emit `slow_down` and
    must never force-expire/void a pending row on poll count; only the 900s
    pending-window expiry may end it."""
    aid = _create(client)["approval_id"]
    statuses = []
    for _ in range(8):  # >= 6 rapid polls, back-to-back, no sleep
        r = client.get(f"/api/approval/status/{aid}", headers=_auth(MASTER))
        assert r.status_code == 200
        statuses.append(r.json())
    assert all(s["status"] == "pending" for s in statuses), statuses
    assert not any(s["status"] == "slow_down" for s in statuses), statuses
    assert not any(s["status"] == "expired" for s in statuses), statuses

    # The row must still be perfectly alive and approvable after the barrage.
    client.post("/api/approval/decide", params=_signed(aid, "approve"))
    assert _status(client, aid)["status"] == "approved"


def test_status_unknown_aid_reads_expired_not_500(client):
    r = client.get("/api/approval/status/apr_does_not_exist", headers=_auth(MASTER))
    assert r.status_code == 200
    assert r.json()["status"] == "expired"


# === confirm_approval — atomic single-use flip, no mint =====================

def test_confirm_exactly_once_no_session_token_minted(client, monkeypatch):
    # Live guard: session_tokens.mint must NEVER be called on this path — a
    # connector authorization is a yes/no gate, not a grant (HQ ruling
    # #6/#8). approval_gate.py doesn't import st.mint today; this fails
    # loudly if a future edit reintroduces it.
    def _forbidden_mint(*a, **kw):
        raise AssertionError("session_tokens.mint must never be called for connector-authorize")

    monkeypatch.setattr(st, "mint", _forbidden_mint)

    created = _create(client)
    aid = created["approval_id"]
    client.post("/api/approval/decide", params=_signed(aid, "approve"))

    first = _confirm(client, aid)
    assert first["approved"] is True
    assert "session_token" not in first
    assert "token" not in first
    assert first["client_id"] == "claude-ai"
    assert first["redirect_uri"] == REDIRECT
    assert first["code"] == created["code"]

    # Single-use: a second confirm on the same aid must not win again.
    second = _confirm(client, aid)
    assert second["approved"] is False
    assert second["reason"] == "consumed"

    assert _status(client, aid)["status"] == "consumed"


def test_confirm_before_approval_is_refused(client):
    aid = _create(client)["approval_id"]
    result = _confirm(client, aid)
    assert result["approved"] is False
    assert result["reason"] == "pending"


def test_confirm_unknown_aid(client):
    result = _confirm(client, "apr_never_existed")
    assert result["approved"] is False
    assert result["reason"] == "unknown_request"


def test_confirm_concurrency_exactly_one_winner(client):
    """The atomic UPDATE ... WHERE status='approved' must give rowcount==1 to
    exactly one caller under a genuine race — the proven technique lifted
    from arrival_gate.poll(), re-verified here for the connector path."""
    import threading

    aid = _create(client)["approval_id"]
    client.post("/api/approval/decide", params=_signed(aid, "approve"))

    n = 12
    barrier = threading.Barrier(n)
    results = [None] * n

    def _attempt(i):
        barrier.wait()  # force genuine concurrency, not accidental sequencing
        results[i] = apg.confirm_approval(aid)

    threads = [threading.Thread(target=_attempt, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    winners = [r for r in results if r.get("approved") is True]
    losers = [r for r in results if r.get("approved") is False]
    assert len(winners) == 1, results
    assert len(losers) == n - 1
    assert all(loser["reason"] in ("consumed", "approved") for loser in losers), losers


# === Confirm provenance write must never block the response (FIX 2) ========

def test_confirm_response_not_blocked_by_slow_provenance_write(client, monkeypatch):
    """FIX 2: the record_insight write must be detached (asyncio.create_task)
    so a slow/hanging chronicle write can never delay or break the confirm
    response — the atomic flip has already committed by then; the aid would
    otherwise be unrecoverably burned while the caller times out. Simulate
    'slow' with an event the write blocks on until AFTER we've already
    asserted the HTTP response returned."""
    import asyncio
    import threading

    write_may_finish = threading.Event()
    write_started = threading.Event()

    async def slow_tool(tool, args):
        write_started.set()
        # Block far longer than any sane request timeout, on a thread the
        # event loop can still schedule around — proves the response path
        # does not await this.
        await asyncio.get_event_loop().run_in_executor(
            None, write_may_finish.wait, 5
        )
        client.recorded.append((tool, args))
        return {"ok": True, "result": "recorded"}

    monkeypatch.setattr(bridge, "call_mcp_tool", slow_tool)

    aid = _create(client)["approval_id"]
    client.post("/api/approval/decide", params=_signed(aid, "approve"))

    started = time.monotonic()
    result = _confirm(client, aid)
    elapsed = time.monotonic() - started

    assert result["approved"] is True
    # The response must come back fast — nowhere near the write's 5s block.
    assert elapsed < 2.0, f"confirm blocked for {elapsed}s on the provenance write"

    write_may_finish.set()  # let the detached task finish so it doesn't leak


# === 900s pending-window expiry =============================================

def test_pending_window_expires_after_900s(client):
    created = _create(client)
    aid = created["approval_id"]
    with apg._connect() as conn:
        old = apg._now().timestamp() - apg.PENDING_WINDOW_SECONDS - 5
        old_iso = datetime.fromtimestamp(old, tz=timezone.utc).isoformat()
        conn.execute(
            "UPDATE approval_requests SET created_at = ? WHERE aid = ?", (old_iso, aid)
        )

    status = _status(client, aid)
    assert status["status"] == "expired"
    assert status["failure_class"] == "approval_expired"

    confirm = _confirm(client, aid)
    assert confirm["approved"] is False


def test_pending_window_not_yet_expired_stays_pending(client):
    created = _create(client)
    aid = created["approval_id"]
    with apg._connect() as conn:
        recent = apg._now().timestamp() - apg.PENDING_WINDOW_SECONDS + 30
        recent_iso = datetime.fromtimestamp(recent, tz=timezone.utc).isoformat()
        conn.execute(
            "UPDATE approval_requests SET created_at = ? WHERE aid = ?", (recent_iso, aid)
        )
    assert _status(client, aid)["status"] == "pending"


# === Gate disabled / fail-closed ============================================

def test_gate_disabled_flag_404s_approval_routes(client, monkeypatch):
    monkeypatch.setenv("ARRIVAL_GATE_ENABLED", "false")
    assert client.post(
        "/api/approval/request",
        json={"client_id": "x", "redirect_uri": REDIRECT},
        headers=_auth(MASTER),
    ).status_code == 404
    assert client.get("/api/approval/status/apr_x", headers=_auth(MASTER)).status_code == 404
    assert client.post(
        "/api/approval/confirm", json={"approval_id": "apr_x"}, headers=_auth(MASTER)
    ).status_code == 404
    # /api/call (the master surface) is unaffected.
    r = client.post(
        "/api/call", json={"tool": "recall_insights", "arguments": {}}, headers=_auth(MASTER)
    )
    assert r.status_code == 200


def test_gate_fail_closed_without_decide_secret(client, monkeypatch):
    monkeypatch.delenv("ARRIVAL_DECIDE_SECRET", raising=False)
    assert client.post(
        "/api/approval/request",
        json={"client_id": "x", "redirect_uri": REDIRECT},
        headers=_auth(MASTER),
    ).status_code == 404


# === Auth — request/status/confirm are master-only, decide is public =======

def test_request_status_confirm_require_master_token(client):
    assert client.post(
        "/api/approval/request", json={"client_id": "x", "redirect_uri": REDIRECT}
    ).status_code == 401
    aid = _create(client)["approval_id"]
    assert client.get(f"/api/approval/status/{aid}").status_code == 401
    assert client.post(
        "/api/approval/confirm", json={"approval_id": aid}
    ).status_code == 401


def test_session_token_cannot_use_master_only_approval_routes(client, monkeypatch):
    """Session tokens (Phase 1 grants) must not be able to drive the
    connector-authorize surface — it's master-only (HQ ruling #3)."""
    monkeypatch.setattr(
        st,
        "resolve",
        lambda token: {
            "status": "ok",
            "token_id": "tok_1",
            "scope": ["read"],
            "source_instance": "x",
        },
    )
    fake_session_token = st.TOKEN_PREFIX + "fake0123456789abcdef0123456789"
    r = client.post(
        "/api/approval/request",
        json={"client_id": "x", "redirect_uri": REDIRECT},
        headers=_auth(fake_session_token),
    )
    assert r.status_code == 403


# === XSS discipline on the phone-facing confirm page ========================

def test_decide_confirm_page_escapes_user_input(client):
    req = _create(
        client,
        client_id='<script>alert(1)</script>',
        redirect_uri='"><img src=x onerror=alert(2)>' + REDIRECT,
    )
    page = client.get(
        "/api/approval/decide", params=_signed(req["approval_id"], "approve")
    )
    assert page.status_code == 200
    assert "<script>" not in page.text
    assert "<img" not in page.text
    assert "&lt;script&gt;" in page.text
