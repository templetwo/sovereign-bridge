"""Phase-2 acceptance tests for The Door That Asks (spec §14, tests 9-13).

The arrival gate: request → decide (POST-only, signed) → poll releases a
scoped token exactly once. ntfy is monkeypatched (delivery is best-effort by
design); the store is isolated to a tmp SQLite file.
"""

import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import arrival_gate as ag  # noqa: E402
import bridge  # noqa: E402
import session_tokens as st  # noqa: E402

MASTER = "test-master-token-0123456789abcdef-0123456789abcdef"
SECRET = "test-decide-secret"


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
    c = TestClient(bridge.app)
    c.recorded = recorded
    return c


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def _request(client, **kw):
    r = client.post(
        "/api/arrival/request",
        json={"source_instance": "claude-test", "seat_description": "pytest seat", **kw},
    )
    assert r.status_code == 201, r.text
    return r.json()


def _signed(rid, action, exp=None):
    exp = exp or int(time.time()) + 600
    return {"rid": rid, "action": action, "exp": exp, "sig": ag.sign_decide(rid, action, exp)}


# 9. Full happy path: request → approve (POST) → token exactly once → consumed.
def test_happy_path_token_exactly_once(client):
    req = _request(client, requested_scope=["read", "write"])
    rid = req["arrival_request_id"]
    assert "-" in req["code"]  # two-word code (decision #5)

    r = client.post("/api/arrival/decide", params=_signed(rid, "approve"))
    assert r.status_code == 200

    poll = client.get(f"/api/arrival/poll/{rid}").json()
    assert poll["status"] == "approved"
    assert poll["session_token"].startswith("svs_")
    assert poll["scope"] == ["read", "write"]

    again = client.get(f"/api/arrival/poll/{rid}").json()
    assert again["status"] == "consumed"
    assert "session_token" not in again

    # The released token actually works, within scope.
    ok = client.post(
        "/api/call",
        json={"tool": "recall_insights", "arguments": {}},
        headers=_auth(poll["session_token"]),
    )
    assert ok.status_code == 200


# 10a. Deny path.
def test_deny_path(client):
    rid = _request(client)["arrival_request_id"]
    client.post("/api/arrival/decide", params=_signed(rid, "deny"))
    poll = client.get(f"/api/arrival/poll/{rid}").json()
    assert poll["status"] == "denied"
    assert poll["failure_class"] == "arrival_denied"


# 10b. Tampered / expired signatures rejected; GET never decides.
def test_signature_discipline_and_get_never_decides(client):
    rid = _request(client)["arrival_request_id"]
    bad = _signed(rid, "approve")
    bad["sig"] = "0" * 64
    assert client.post("/api/arrival/decide", params=bad).status_code == 403
    stale = _signed(rid, "approve", exp=int(time.time()) - 10)
    assert client.post("/api/arrival/decide", params=stale).status_code == 403

    # GET with a VALID signature renders the confirm page and changes nothing.
    good = _signed(rid, "approve")
    page = client.get("/api/arrival/decide", params=good)
    assert page.status_code == 200
    assert "form" in page.text and "cannot press this button" in page.text.lower().replace(
        "a preview fetcher cannot press this button. only you can.", "cannot press this button"
    ) or "<form" in page.text
    assert client.get(f"/api/arrival/poll/{rid}").json()["status"] == "pending"


# 10c. Global pending cap at 3.
def test_global_pending_cap(client):
    for i in range(3):
        _request(client, source_instance=f"seat-{i}")
    r = client.post(
        "/api/arrival/request",
        json={"source_instance": "seat-overflow", "seat_description": "x"},
    )
    assert r.status_code == 429
    assert r.json()["failure_class"] == "rate_limited"


# 10d. Duplicate suppression reuses the pending request.
def test_duplicate_suppression(client):
    first = _request(client)
    second = _request(client)
    assert second["arrival_request_id"] == first["arrival_request_id"]
    assert second.get("duplicate_of_recent_request") is True


# 11. Chronicle receipt written on grant, traceable shape.
def test_chronicle_receipt_on_grant(client):
    req = _request(client)
    rid = req["arrival_request_id"]
    client.post("/api/arrival/decide", params=_signed(rid, "approve"))
    poll = client.get(f"/api/arrival/poll/{rid}").json()
    writes = [(t, a) for t, a in client.recorded if t == "record_insight"]
    assert len(writes) == 1
    _, args = writes[0]
    assert poll["token_id"] in args["content"]
    assert req["code"] in args["content"]
    assert args["verified_by"][0]["kind"] == "human"


# 12. ntfy unreachable → request still approvable via HQ admin path.
def test_hq_admin_fallback(client, monkeypatch):
    async def ntfy_down(payload):
        return False

    monkeypatch.setattr(bridge, "_ntfy_publish", ntfy_down)
    req = _request(client, source_instance="fallback-seat")
    assert req["notification_sent"] is False
    r = client.post(
        "/api/arrival/approve",
        json={"arrival_request_id": req["arrival_request_id"]},
        headers=_auth(MASTER),
    )
    assert r.json()["outcome"] == "approved"
    poll = client.get(f"/api/arrival/poll/{req['arrival_request_id']}").json()
    assert poll["status"] == "approved" and poll["session_token"].startswith("svs_")


# 13. Gate disabled → all /api/arrival/* 404, /api/call unchanged.
def test_gate_disabled_flag(client, monkeypatch):
    monkeypatch.setenv("ARRIVAL_GATE_ENABLED", "false")
    assert client.post("/api/arrival/request", json={}).status_code == 404
    assert client.get("/api/arrival/poll/arq_x").status_code == 404
    r = client.post(
        "/api/call", json={"tool": "recall_insights", "arguments": {}}, headers=_auth(MASTER)
    )
    assert r.status_code == 200


# Fail-closed: no decide secret, no gate.
def test_gate_fail_closed_without_secret(client, monkeypatch):
    monkeypatch.delenv("ARRIVAL_DECIDE_SECRET", raising=False)
    assert client.post("/api/arrival/request", json={}).status_code == 404


# Decision single-use: second decide returns already_decided.
def test_decide_single_use(client):
    rid = _request(client)["arrival_request_id"]
    client.post("/api/arrival/decide", params=_signed(rid, "approve"))
    r2 = client.post("/api/arrival/decide", params=_signed(rid, "deny"))
    assert "Already decided" in r2.text
    assert client.get(f"/api/arrival/poll/{rid}").json()["status"] == "approved"


# Ungrantable scopes silently reduced at request time (spec §4.1).
def test_request_scope_clamped(client):
    req = _request(client, requested_scope=["read", "admin", "mint"])
    rid = req["arrival_request_id"]
    client.post("/api/arrival/decide", params=_signed(rid, "approve"))
    poll = client.get(f"/api/arrival/poll/{rid}").json()
    assert poll["scope"] == ["read"]
