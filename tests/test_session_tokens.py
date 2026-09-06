"""Phase-1 acceptance tests for The Door That Asks (spec §14, tests 1-8).

Scoped session tokens on the bridge: mint / resolve / scope enforcement /
revoke, with the master path byte-identical to before. The token store is
isolated to a tmp SQLite file; call_mcp_tool is monkeypatched so no live
stack is needed.
"""

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import bridge  # noqa: E402
import session_tokens as st  # noqa: E402

MASTER = "test-master-token-0123456789abcdef-0123456789abcdef"


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setattr(st, "DB_PATH", tmp_path / "session_tokens.db")
    monkeypatch.setattr(bridge, "BEARER_TOKEN", MASTER)
    return TestClient(bridge.app)


def _mock_tool(monkeypatch, recorder):
    async def fake(tool, args, seat=None):
        recorder.append((tool, args))
        return {"ok": True, "result": {"echo": tool}}

    monkeypatch.setattr(bridge, "call_mcp_tool", fake)


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def _mint(client, scope, ttl=12, **kw):
    r = client.post(
        "/api/admin/tokens/mint",
        json={"scope": scope, "ttl_hours": ttl, **kw},
        headers=_auth(MASTER),
    )
    assert r.status_code == 200
    return r.json()


# 1. Unauthenticated /api/call → 401 auth, body style unchanged.
def test_unauthenticated_call_401(client):
    r = client.post("/api/call", json={"tool": "recall_insights", "arguments": {}})
    assert r.status_code == 401
    assert r.json()["failure_class"] == "auth"
    assert "/api/heartbeat" in r.json()["detail"]


# 2. Master token → full behavior, unchanged.
def test_master_token_full_behavior(client, monkeypatch):
    calls = []
    _mock_tool(monkeypatch, calls)
    r = client.post(
        "/api/call",
        json={"tool": "set_policy", "arguments": {}},
        headers=_auth(MASTER),
    )
    assert r.status_code == 200 and r.json()["ok"] is True
    assert calls == [("set_policy", {})]


# 3. Read-only token: read tool works, write tool refused with 403 scope.
def test_read_scope_enforced(client, monkeypatch):
    calls = []
    _mock_tool(monkeypatch, calls)
    tok = _mint(client, ["read"])["session_token"]
    ok = client.post(
        "/api/call", json={"tool": "recall_insights", "arguments": {}}, headers=_auth(tok)
    )
    assert ok.status_code == 200
    denied = client.post(
        "/api/call", json={"tool": "record_insight", "arguments": {}}, headers=_auth(tok)
    )
    assert denied.status_code == 403
    assert denied.json()["failure_class"] == "scope"
    assert "record_insight" in denied.json()["detail"]


# 4. read+write token: record_insight succeeds, stamped with token_id +
#    source_instance so inspect_claim can trace the entry to its grant.
def test_write_stamped_with_grant(client, monkeypatch):
    calls = []
    _mock_tool(monkeypatch, calls)
    minted = _mint(client, ["read", "write"], source_instance="claude-test-seat")
    r = client.post(
        "/api/call",
        json={"tool": "record_insight", "arguments": {"content": "x", "domain": "d"}},
        headers=_auth(minted["session_token"]),
    )
    assert r.status_code == 200
    tool, args = calls[-1]
    assert tool == "record_insight"
    assert args["session_token_id"] == minted["token_id"]
    assert args["source_instance"] == "claude-test-seat"


# 5. Expired token → 403 auth saying expired; revoked → 403 auth saying revoked.
def test_expired_and_revoked_bodies(client, monkeypatch):
    _mock_tool(monkeypatch, [])
    minted = _mint(client, ["read"])
    # Force-expire directly in the store.
    import sqlite3

    with sqlite3.connect(st.DB_PATH) as conn:
        conn.execute(
            "UPDATE session_tokens SET expires_at = '2000-01-01T00:00:00+00:00' WHERE token_id = ?",
            (minted["token_id"],),
        )
    r = client.post(
        "/api/call", json={"tool": "recall_insights", "arguments": {}},
        headers=_auth(minted["session_token"]),
    )
    assert r.status_code == 403
    assert r.json()["failure_class"] == "auth"
    assert "expired" in r.json()["detail"].lower()

    minted2 = _mint(client, ["read"])
    client.post(
        "/api/admin/tokens/revoke", json={"token_id": minted2["token_id"]},
        headers=_auth(MASTER),
    )
    r2 = client.post(
        "/api/call", json={"tool": "recall_insights", "arguments": {}},
        headers=_auth(minted2["session_token"]),
    )
    assert r2.status_code == 403
    assert "revoked" in r2.json()["detail"].lower()


# 6. set_policy refused even with every grantable scope (never list).
def test_set_policy_never_grantable(client, monkeypatch):
    _mock_tool(monkeypatch, [])
    tok = _mint(client, ["read", "write", "session"])["session_token"]
    r = client.post(
        "/api/call", json={"tool": "set_policy", "arguments": {}}, headers=_auth(tok)
    )
    assert r.status_code == 403
    assert r.json()["failure_class"] == "scope"


# 7. Unmapped tool → 403 scope (default-deny proof).
def test_unmapped_tool_default_deny(client, monkeypatch):
    _mock_tool(monkeypatch, [])
    tok = _mint(client, ["read", "write", "session"])["session_token"]
    r = client.post(
        "/api/call",
        json={"tool": "some_future_tool_nobody_classified", "arguments": {}},
        headers=_auth(tok),
    )
    assert r.status_code == 403
    assert r.json()["failure_class"] == "scope"


# 8. revoke --all kills an active token mid-conversation on its next call.
def test_revoke_all_kills_active_token(client, monkeypatch):
    _mock_tool(monkeypatch, [])
    tok = _mint(client, ["read"])["session_token"]
    ok = client.post(
        "/api/call", json={"tool": "recall_insights", "arguments": {}}, headers=_auth(tok)
    )
    assert ok.status_code == 200
    r = client.post("/api/admin/tokens/revoke", json={"all": True}, headers=_auth(MASTER))
    assert r.json()["revoked"] >= 1
    dead = client.post(
        "/api/call", json={"tool": "recall_insights", "arguments": {}}, headers=_auth(tok)
    )
    assert dead.status_code == 403


# ── HQ review corrections, pinned by test ───────────────────────────────────


def test_session_token_master_only_routes(client, monkeypatch):
    """Correction #3: non-/api/call routes refuse session tokens (route
    default-deny), master keeps full reach."""
    _mock_tool(monkeypatch, [])
    tok = _mint(client, ["read", "write", "session"])["session_token"]
    r = client.get("/api/admin/tokens", headers=_auth(tok))
    assert r.status_code == 403
    assert r.json()["failure_class"] == "scope"
    r2 = client.post(
        "/api/batch", json={"calls": []}, headers=_auth(tok)
    )
    assert r2.status_code == 403


def test_scope_map_corrections():
    """Correction #2 pinned: check_mistakes is read; where_did_i_leave_off is
    not grantable at all; close_session/spiral_inherit live in 'session'."""
    assert st.TOOL_SCOPES["check_mistakes"] == "read"
    assert "where_did_i_leave_off" not in st.TOOL_SCOPES
    assert st.TOOL_SCOPES["close_session"] == "session"
    assert st.TOOL_SCOPES["spiral_inherit"] == "session"
    assert not st.tool_allowed("close_session", ["read", "write"])
    assert st.tool_allowed("close_session", ["session"])


def test_protected_drawer_hard_denied():
    """Spec §6/§10: the entire protected drawer is out of session reach,
    reads included, regardless of scope."""
    for tool in ("designate_protected", "open_protected_record", "list_protected_thresholds"):
        assert not st.tool_allowed(tool, ["read", "write", "session"])


def test_mint_clamps_ttl_and_scope(client, monkeypatch):
    _mock_tool(monkeypatch, [])
    out = _mint(client, ["read", "admin", "root"], ttl=999)
    assert out["scope"] == ["read"]  # ungrantable silently reduced (spec §4.1)
    assert out["ttl_hours"] == st.TTL_MAX_HOURS


def test_plaintext_never_stored(client, monkeypatch):
    _mock_tool(monkeypatch, [])
    minted = _mint(client, ["read"])
    listing = client.get("/api/admin/tokens", headers=_auth(MASTER)).json()
    assert minted["session_token"].startswith("svs_")
    blob = str(listing)
    assert minted["session_token"] not in blob
