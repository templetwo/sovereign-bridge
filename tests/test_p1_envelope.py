"""P1 — the bridge envelope tells the truth (mesh-20260719).

Per standing law #2, the two fail-closed gates here demonstrably FAIL on
unfixed code (main @ 3e153c8): the MCP SDK converts a tool-handler
exception into a NORMAL wire result carrying isError=True
(mcp.server.lowlevel Server.call_tool -> _make_error_result), and
ClientSession.call_tool RETURNS that result rather than raising — so the
bridge's `except` never fires, `.content[0].text` holds the error string,
and call_mcp_tool reports {"ok": true, "result": "[Errno 2] ..."} on a
write that recorded nothing. Live reproducer 2026-07-19, shard
mesh-20260719. The fix is one check: honor result.isError.
"""

import asyncio
from contextlib import asynccontextmanager

import mcp.types as mcp_types
import pytest

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import bridge  # noqa: E402


def _run(coro):
    return asyncio.run(coro)


def _fake_transport(monkeypatch, result):
    """Stand in for the SSE transport: call_tool returns `result` verbatim,
    exactly as ClientSession does for isError results (it does not raise)."""

    @asynccontextmanager
    async def fake_sse(url, headers=None):
        yield (None, None)

    class FakeSession:
        def __init__(self, read, write):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def initialize(self):
            pass

        async def call_tool(self, name, arguments=None):
            return result

    monkeypatch.setattr(bridge, "sse_client", fake_sse)
    monkeypatch.setattr(bridge, "ClientSession", FakeSession)


def _error_result(text):
    return mcp_types.CallToolResult(
        content=[mcp_types.TextContent(type="text", text=text)], isError=True
    )


def test_iserror_result_fails_closed(monkeypatch):
    """UNFIXED: ok:true with the error string in `result` — the exact
    envelope that lost 4 of 93 records on 2026-07-19. FIXED: ok:false,
    error text preserved verbatim, failure_class 'tool'."""
    _fake_transport(
        monkeypatch,
        _error_result("[Errno 2] No such file or directory: '/x/insights/feat/y'"),
    )
    out = _run(bridge.call_mcp_tool("record_insight", {"domain": "feat/y", "content": "x"}))
    assert out["ok"] is False
    assert "Errno 2" in out["error"]
    assert out["failure_class"] == "tool"


def test_iserror_batch_fails_closed(monkeypatch):
    """Same defect in call_mcp_tools_batch. UNFIXED: ok:true per entry."""
    _fake_transport(monkeypatch, _error_result("record_insight rejected: receipt #2"))
    out = _run(
        bridge.call_mcp_tools_batch(
            [bridge.ToolCall(tool="record_insight", arguments={"domain": "d", "content": "c"})]
        )
    )
    assert len(out) == 1
    assert out[0]["ok"] is False
    assert "rejected" in out[0]["error"]


def test_success_result_unchanged(monkeypatch):
    """Regression guard, passes on both sides: a healthy result still comes
    back ok:true with JSON decoded."""
    _fake_transport(
        monkeypatch,
        mcp_types.CallToolResult(
            content=[mcp_types.TextContent(type="text", text='{"a": 1}')], isError=False
        ),
    )
    out = _run(bridge.call_mcp_tool("recall_insights", {}))
    assert out == {"ok": True, "result": {"a": 1}}


def test_transport_exception_still_fails_closed(monkeypatch):
    """Regression guard for the path that already worked: a raising
    transport keeps ok:false with a failure_class."""

    @asynccontextmanager
    async def broken_sse(url, headers=None):
        raise ConnectionError("Connection refused")
        yield  # pragma: no cover

    monkeypatch.setattr(bridge, "sse_client", broken_sse)
    out = _run(bridge.call_mcp_tool("recall_insights", {}))
    assert out["ok"] is False
    assert out["failure_class"] == "egress"
