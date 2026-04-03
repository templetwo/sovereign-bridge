#!/usr/bin/env python3
"""
Sovereign Bridge — REST API for Sovereign Stack MCP

Wraps the SSE MCP server with stateless HTTP endpoints.
Any Claude instance, anywhere, one curl = one answer.

Endpoints:
  GET  /api/heartbeat  — is the stack alive?
  POST /api/call       — call a single tool
  POST /api/batch      — call multiple tools in one request
"""

import asyncio
import json
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from mcp.client.session import ClientSession
from mcp.client.sse import sse_client

# === Config ===
MCP_SSE_URL = os.getenv("MCP_SSE_URL", "http://127.0.0.1:3434/sse")
BRIDGE_PORT = int(os.getenv("BRIDGE_PORT", "8100"))
VERSION = "1.0.0"

# Load bearer token
TOKEN_FILE = Path(os.path.expanduser("~/.config/sovereign-bridge.env"))
BEARER_TOKEN = None
if TOKEN_FILE.exists():
    for line in TOKEN_FILE.read_text().splitlines():
        if line.startswith("BRIDGE_TOKEN="):
            BEARER_TOKEN = line.split("=", 1)[1].strip().strip('"').strip("'")
            break

if not BEARER_TOKEN:
    BEARER_TOKEN = os.getenv("BRIDGE_TOKEN", "")


# === Models ===
class ToolCall(BaseModel):
    tool: str
    arguments: dict[str, Any] = {}


class BatchRequest(BaseModel):
    calls: list[ToolCall]


# === Auth ===
def check_auth(authorization: str | None):
    if not BEARER_TOKEN:
        return  # No token configured = open (local dev)
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token")
    if authorization[7:] != BEARER_TOKEN:
        raise HTTPException(status_code=403, detail="Invalid token")


# === MCP Client ===
async def call_mcp_tool(tool_name: str, arguments: dict) -> dict:
    """Connect to MCP SSE, call one tool, return result, disconnect."""
    try:
        async with sse_client(MCP_SSE_URL) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool(tool_name, arguments=arguments)
                if result.content:
                    text = result.content[0].text
                    # Try to parse as JSON
                    try:
                        return {"ok": True, "result": json.loads(text)}
                    except json.JSONDecodeError:
                        return {"ok": True, "result": text}
                return {"ok": True, "result": None}
    except Exception as e:
        return {"ok": False, "error": str(e)}


async def call_mcp_tools_batch(calls: list[ToolCall]) -> list[dict]:
    """Connect once, call multiple tools, return all results."""
    results = []
    try:
        async with sse_client(MCP_SSE_URL) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                for call in calls:
                    try:
                        result = await session.call_tool(call.tool, arguments=call.arguments)
                        if result.content:
                            text = result.content[0].text
                            try:
                                results.append({"ok": True, "tool": call.tool, "result": json.loads(text)})
                            except json.JSONDecodeError:
                                results.append({"ok": True, "tool": call.tool, "result": text})
                        else:
                            results.append({"ok": True, "tool": call.tool, "result": None})
                    except Exception as e:
                        results.append({"ok": False, "tool": call.tool, "error": str(e)})
    except Exception as e:
        return [{"ok": False, "error": f"Connection failed: {e}"}]
    return results


async def get_tool_count() -> int:
    """Quick tool count for heartbeat."""
    try:
        async with sse_client(MCP_SSE_URL) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = await session.list_tools()
                return len(tools.tools)
    except Exception:
        return -1


# === App ===
app = FastAPI(title="Sovereign Bridge", version=VERSION)


@app.get("/api/heartbeat")
async def heartbeat():
    """Check if the stack is alive. No auth required."""
    tool_count = await get_tool_count()
    return {
        "status": "ok" if tool_count > 0 else "degraded",
        "version": VERSION,
        "mcp_url": MCP_SSE_URL,
        "tools": tool_count,
        "timestamp": time.time(),
    }


@app.post("/api/call")
async def call_tool(
    req: ToolCall,
    authorization: str | None = Header(default=None),
):
    """Call a single MCP tool."""
    check_auth(authorization)
    start = time.time()
    result = await call_mcp_tool(req.tool, req.arguments)
    result["duration_ms"] = round((time.time() - start) * 1000)
    return result


@app.post("/api/batch")
async def batch_call(
    req: BatchRequest,
    authorization: str | None = Header(default=None),
):
    """Call multiple MCP tools in one request."""
    check_auth(authorization)
    if len(req.calls) > 10:
        raise HTTPException(status_code=400, detail="Max 10 calls per batch")
    start = time.time()
    results = await call_mcp_tools_batch(req.calls)
    return {
        "results": results,
        "count": len(results),
        "duration_ms": round((time.time() - start) * 1000),
    }


@app.get("/api/tools")
async def list_tools(
    authorization: str | None = Header(default=None),
):
    """List all available MCP tools."""
    check_auth(authorization)
    try:
        async with sse_client(MCP_SSE_URL) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = await session.list_tools()
                return {
                    "tools": [
                        {"name": t.name, "description": (t.description or "")[:200]}
                        for t in sorted(tools.tools, key=lambda x: x.name)
                    ],
                    "count": len(tools.tools),
                }
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=BRIDGE_PORT)
