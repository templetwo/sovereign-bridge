"""Write-path improvements on /api/call (idempotency, failure-class, validate-only).

All three are additive/opt-in: a request with neither idempotency_key nor
validate_only must behave exactly as before. Tests monkeypatch call_mcp_tool so
no live stack is needed, and isolate the idempotency cache to a tmp path.
"""

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import bridge  # noqa: E402


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setattr(bridge, "check_auth", lambda *a, **k: None)  # bypass auth
    monkeypatch.setattr(bridge, "_IDEM_PATH", tmp_path / "idem.json")  # isolate cache
    return TestClient(bridge.app)


def _mock_tool(monkeypatch, recorder):
    async def fake(tool, args):
        recorder.append((tool, args))
        return {"ok": True, "result": {"echo": tool}}

    monkeypatch.setattr(bridge, "call_mcp_tool", fake)


def test_plain_call_unchanged(client, monkeypatch):
    calls = []
    _mock_tool(monkeypatch, calls)
    r = client.post("/api/call", json={"tool": "recall_insights", "arguments": {}})
    assert r.status_code == 200
    b = r.json()
    assert b["ok"] is True and b["result"] == {"echo": "recall_insights"}
    assert "idempotent_replay" not in b
    assert "duration_ms" in b
    assert len(calls) == 1


def test_idempotent_replay(client, monkeypatch):
    calls = []
    _mock_tool(monkeypatch, calls)
    p = {"tool": "record_insight", "arguments": {"content": "x", "domain": "d"}, "idempotency_key": "k1"}
    r1 = client.post("/api/call", json=p)
    r2 = client.post("/api/call", json=p)
    assert "idempotent_replay" not in r1.json()
    assert r2.json().get("idempotent_replay") is True
    assert r2.json()["result"] == {"echo": "record_insight"}
    assert len(calls) == 1  # tool executed exactly once; retry replayed the cache


def test_failure_class_stack(client, monkeypatch):
    async def fail(tool, args):
        return {"ok": False, "error": "tool blew up"}

    monkeypatch.setattr(bridge, "call_mcp_tool", fail)
    r = client.post("/api/call", json={"tool": "record_insight", "arguments": {}})
    assert r.json()["failure_class"] == "stack"


def test_failure_class_egress(client, monkeypatch):
    async def fail(tool, args):
        return {"ok": False, "error": "Connection refused", "failure_class": "egress"}

    monkeypatch.setattr(bridge, "call_mcp_tool", fail)
    r = client.post("/api/call", json={"tool": "x", "arguments": {}})
    assert r.json()["failure_class"] == "egress"


def test_failure_class_auth(monkeypatch):
    monkeypatch.setattr(bridge, "BEARER_TOKEN", "correct-token-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    c = TestClient(bridge.app)
    r = c.post(
        "/api/call",
        json={"tool": "x", "arguments": {}},
        headers={"Authorization": "Bearer wrong-token-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
    )
    assert r.status_code == 403
    assert r.json()["failure_class"] == "auth"


def test_failure_class_malformed_batch(monkeypatch):
    monkeypatch.setattr(bridge, "check_auth", lambda *a, **k: None)
    c = TestClient(bridge.app)
    calls = [{"tool": "x", "arguments": {}} for _ in range(11)]
    r = c.post("/api/batch", json={"calls": calls})
    assert r.status_code == 400
    assert r.json()["failure_class"] == "malformed"


def test_validate_only_reflection_flagged(client, monkeypatch):
    calls = []
    _mock_tool(monkeypatch, calls)
    r = client.post(
        "/api/call",
        json={"tool": "record_insight", "arguments": {"layer": "reflection", "content": "x"}, "validate_only": True},
    )
    b = r.json()
    assert b["valid"] is False
    assert any("reflection" in p for p in b["problems"])
    assert len(calls) == 0  # nothing committed


def test_schema_signature():
    s = {
        "type": "object",
        "properties": {"domain": {}, "content": {}, "layer": {}, "intensity": {}},
        "required": ["domain", "content"],
    }
    assert bridge._schema_signature(s) == {
        "required": ["domain", "content"],
        "optional": ["layer", "intensity"],
    }
    assert bridge._schema_signature(None) is None
    assert bridge._schema_signature({}) == {"required": [], "optional": []}


def test_validate_only_valid_shape(client, monkeypatch):
    calls = []
    _mock_tool(monkeypatch, calls)
    r = client.post(
        "/api/call",
        json={"tool": "record_insight", "arguments": {"layer": "hypothesis", "content": "x"}, "validate_only": True},
    )
    b = r.json()
    assert b["valid"] is True and b["problems"] == []
    assert len(calls) == 0
