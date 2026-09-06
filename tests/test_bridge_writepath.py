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


# ── Idempotency is scoped to the CALLER, the tool and the arguments ─────────
#
# Codex review 2026-09-06 (P1 CACHE), verbatim: "bridge.py:1342 retrieves
# idempotency-cached results by the supplied key alone; a seat requesting an
# allowed tool received a cached master-only result (200, idempotent_replay=
# true, zero upstream calls); entries lack caller/tool/request binding, and a
# colliding key can suppress another seat's write."


def _ctx_client(monkeypatch, tmp_path, ctx):
    """A client whose /api/call runs as a chosen principal. check_auth is
    replaced rather than a real token minted, because what is under test is the
    CACHE's use of the principal, not how the principal was established."""
    monkeypatch.setattr(bridge, "check_auth", lambda *a, **k: ctx)
    monkeypatch.setattr(bridge, "_IDEM_PATH", tmp_path / "idem.json")
    return TestClient(bridge.app)


def test_a_cached_result_never_crosses_principals(monkeypatch, tmp_path):
    """THE REVIEWER'S SCENARIO. Principal A caches a result under key 'k'.
    Principal B presents the SAME key and must MISS — reaching the stub
    upstream instead of being handed A's answer.

    This is the half that a scope check cannot cover: every authz check in
    /api/call ran and passed for B, and then the cache answered from A's entry
    before the tool was ever consulted. A cache in front of an authz boundary
    that does not know about the boundary IS the boundary's hole.
    """
    calls = []
    _mock_tool(monkeypatch, calls)
    body = {"tool": "recall_insights", "arguments": {}, "idempotency_key": "k"}

    a = _ctx_client(monkeypatch, tmp_path, None)  # master
    assert a.post("/api/call", json=body).status_code == 200
    assert len(calls) == 1
    # ...and A itself still replays, so the feature is not simply broken.
    assert a.post("/api/call", json=body).json().get("idempotent_replay") is True
    assert len(calls) == 1

    b = _ctx_client(
        monkeypatch, tmp_path, {"status": "ok", "kind": "seat", "seat_id": "grok-build-studio",
                                "scope": ["read", "write"]}
    )
    r = b.post("/api/call", json=body)
    assert r.status_code == 200
    assert "idempotent_replay" not in r.json(), "a seat replayed another principal's cached result"
    assert len(calls) == 2, "the seat's call never reached the stack"


def test_a_colliding_key_cannot_suppress_a_different_write(client, monkeypatch):
    """The half that verifying-on-read would NOT fix. Two different writes, same
    key: the second must still execute. Under the old flat keying it silently
    received the first one's result and its own write never happened — and
    'silently' is the whole problem, since the caller got a 200."""
    calls = []
    _mock_tool(monkeypatch, calls)
    first = {"tool": "record_insight", "arguments": {"content": "FIRST", "domain": "d"},
             "idempotency_key": "same-key"}
    second = {"tool": "record_insight", "arguments": {"content": "SECOND", "domain": "d"},
              "idempotency_key": "same-key"}
    assert client.post("/api/call", json=first).status_code == 200
    r = client.post("/api/call", json=second)
    assert "idempotent_replay" not in r.json(), "a different write was swallowed by a key collision"
    assert [a["content"] for _, a in calls] == ["FIRST", "SECOND"]


def test_a_colliding_key_cannot_cross_tools(client, monkeypatch):
    """Same principal, same key, different tool. The review named tool binding
    explicitly, and a replay across tools would return one tool's payload under
    another tool's name — a lie the caller has no way to detect."""
    calls = []
    _mock_tool(monkeypatch, calls)
    key = {"idempotency_key": "k"}
    assert client.post("/api/call", json={"tool": "recall_insights", "arguments": {}, **key}).status_code == 200
    r = client.post("/api/call", json={"tool": "get_open_threads", "arguments": {}, **key})
    assert r.json().get("result") == {"echo": "get_open_threads"}
    assert "idempotent_replay" not in r.json()
    assert len(calls) == 2


def test_an_identical_retry_still_replays(client, monkeypatch):
    """The point of the feature, kept. Same principal, same tool, same
    arguments, same key: exactly one upstream call. Scoping must not become
    'never replay', which would quietly restore the double-write this cache
    exists to prevent."""
    calls = []
    _mock_tool(monkeypatch, calls)
    body = {"tool": "record_insight", "arguments": {"content": "c", "domain": "d"},
            "idempotency_key": "retry-1"}
    assert client.post("/api/call", json=body).status_code == 200
    assert client.post("/api/call", json=body).json().get("idempotent_replay") is True
    assert len(calls) == 1


def test_an_old_flat_cache_entry_is_not_replayed(client, monkeypatch):
    """Forward compatibility, failing CLOSED. A cache file written by the
    pre-fix build has entries keyed by the raw user key and no principal field.
    Those must be ignored, not trusted — the file on the live machine right now
    is exactly such a file."""
    import json as _json
    import time as _time
    calls = []
    _mock_tool(monkeypatch, calls)
    bridge._IDEM_PATH.parent.mkdir(parents=True, exist_ok=True)
    bridge._IDEM_PATH.write_text(
        _json.dumps({"k": {"result": {"ok": True, "result": "STALE"}, "ts": _time.time()}})
    )
    r = client.post("/api/call", json={"tool": "recall_insights", "arguments": {}, "idempotency_key": "k"})
    assert r.json().get("result") != "STALE", "a pre-fix cache entry was replayed"
    assert len(calls) == 1


def test_a_hash_collision_still_fails_closed(client, monkeypatch):
    """The BELT behind the keying, falsified directly.

    test_an_old_flat_cache_entry_is_not_replayed does NOT reach this check —
    an old flat key never collides with a sha256 key, so that test passes with
    the verify deleted. Found by deleting the guard and watching nothing fail.
    So this writes an entry AT the exact storage key the next request will
    compute, carrying somebody else's principal, and requires a miss.
    """
    import json as _json
    import time as _time
    calls = []
    _mock_tool(monkeypatch, calls)
    key = bridge._idem_storage_key("master", "recall_insights", {}, "k")
    bridge._IDEM_PATH.parent.mkdir(parents=True, exist_ok=True)
    bridge._IDEM_PATH.write_text(
        _json.dumps({key: {"result": {"ok": True, "result": "NOT-YOURS"},
                           "ts": _time.time(),
                           "principal": "seat:somebody-else", "tool": "recall_insights"}})
    )
    r = client.post("/api/call", json={"tool": "recall_insights", "arguments": {}, "idempotency_key": "k"})
    assert r.json().get("result") != "NOT-YOURS", "a colliding entry replayed another principal's result"
    assert len(calls) == 1
