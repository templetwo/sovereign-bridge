#!/usr/bin/env python3
"""
Sovereign Bridge v1.2.0 — REST API for Sovereign Stack MCP

Endpoints:
  GET  /api/heartbeat        — is the stack alive?
  POST /api/call             — call a single tool
  POST /api/batch            — call multiple tools in one request
  GET  /api/tools            — list all MCP tools
  POST /api/comms/send       — send a message to the inter-instance channel
  GET  /api/comms/read       — read messages (with since/unread filtering)
  GET  /api/comms/channels   — list available channels
  GET  /api/comms/unread     — unread count per channel for a given instance
"""

import asyncio
import json
import os
import time
import uuid
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Header, Query
from pydantic import BaseModel

from mcp.client.session import ClientSession
from mcp.client.sse import sse_client

# Epistemic breathing — classify messages before delivery
import sys
sys.path.insert(0, os.path.expanduser("~/sovereign-stack/src"))
try:
    from sovereign_stack.epistemic_breathing import breathe_comms, classify_query
    BREATHING_AVAILABLE = True
except ImportError:
    BREATHING_AVAILABLE = False

# === Config ===
MCP_SSE_URL = os.getenv("MCP_SSE_URL", "http://127.0.0.1:3434/sse")
BRIDGE_PORT = int(os.getenv("BRIDGE_PORT", "8100"))
COMMS_DIR = Path(os.path.expanduser("~/.sovereign/comms"))
COMMS_DIR.mkdir(parents=True, exist_ok=True)
SIGNAL_DIR = Path(os.path.expanduser("~/.sovereign/signals"))
SIGNAL_DIR.mkdir(parents=True, exist_ok=True)
VERSION = "1.2.0"

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


class CommsMessage(BaseModel):
    sender: str
    content: str
    channel: str = "general"
    reply_to: Optional[str] = None


# === Auth ===
def check_auth(authorization: str | None):
    if not BEARER_TOKEN:
        return
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token")
    if authorization[7:] != BEARER_TOKEN:
        raise HTTPException(status_code=403, detail="Invalid token")


# === MCP Client ===
async def call_mcp_tool(tool_name: str, arguments: dict) -> dict:
    try:
        async with sse_client(MCP_SSE_URL) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool(tool_name, arguments=arguments)
                if result.content:
                    text = result.content[0].text
                    try:
                        return {"ok": True, "result": json.loads(text)}
                    except json.JSONDecodeError:
                        return {"ok": True, "result": text}
                return {"ok": True, "result": None}
    except Exception as e:
        return {"ok": False, "error": str(e)}


async def call_mcp_tools_batch(calls: list[ToolCall]) -> list[dict]:
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
    try:
        async with sse_client(MCP_SSE_URL) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = await session.list_tools()
                return len(tools.tools)
    except Exception:
        return -1


# === Comms ===
def _channel_path(channel: str) -> Path:
    safe = "".join(c for c in channel if c.isalnum() or c in "-_")
    return COMMS_DIR / f"{safe}.jsonl"


def _read_channel(channel: str, since: float = 0, limit: int = 50) -> list[dict]:
    path = _channel_path(channel)
    if not path.exists():
        return []
    messages = []
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        try:
            msg = json.loads(line)
            if msg.get("timestamp", 0) > since:
                messages.append(msg)
        except json.JSONDecodeError:
            continue
    return messages[-limit:]


def _write_message(channel: str, message: dict):
    path = _channel_path(channel)
    with open(path, "a") as f:
        f.write(json.dumps(message) + "\n")
    # Signal file — any watcher can poll this
    signal = SIGNAL_DIR / f"new_message_{channel}"
    signal.write_text(json.dumps({
        "channel": channel,
        "sender": message.get("sender", "unknown"),
        "id": message.get("id", ""),
        "timestamp": message.get("timestamp", 0),
        "preview": message.get("content", "")[:100],
    }))


def _count_unread(channel: str, instance_id: str) -> int:
    path = _channel_path(channel)
    if not path.exists():
        return 0
    count = 0
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        try:
            msg = json.loads(line)
            if instance_id not in msg.get("read_by", []):
                count += 1
        except json.JSONDecodeError:
            continue
    return count


# === App ===
app = FastAPI(title="Sovereign Bridge", version=VERSION)

from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import os

DASHBOARD_DIR = os.path.join(os.path.dirname(__file__), "dashboard")

@app.get("/")
async def dashboard_root():
    return FileResponse(os.path.join(DASHBOARD_DIR, "index.html"))


@app.get("/api/heartbeat")
async def heartbeat():
    tool_count = await get_tool_count()
    # Quick unread count across all channels
    total_messages = 0
    for f in COMMS_DIR.glob("*.jsonl"):
        total_messages += sum(1 for line in f.read_text().splitlines() if line.strip())
    return {
        "status": "ok" if tool_count > 0 else "degraded",
        "version": VERSION,
        "tools": tool_count,
        "comms_messages": total_messages,
        "timestamp": time.time(),
    }


@app.post("/api/call")
async def call_tool_endpoint(
    req: ToolCall,
    authorization: str | None = Header(default=None),
):
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
    check_auth(authorization)
    if len(req.calls) > 10:
        raise HTTPException(status_code=400, detail="Max 10 calls per batch")
    start = time.time()
    results = await call_mcp_tools_batch(req.calls)
    return {"results": results, "count": len(results), "duration_ms": round((time.time() - start) * 1000)}


@app.get("/api/tools")
async def list_tools(authorization: str | None = Header(default=None)):
    check_auth(authorization)
    try:
        async with sse_client(MCP_SSE_URL) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = await session.list_tools()
                return {
                    "tools": [{"name": t.name, "description": (t.description or "")[:200]}
                              for t in sorted(tools.tools, key=lambda x: x.name)],
                    "count": len(tools.tools),
                }
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))


# === Comms Endpoints ===

@app.post("/api/comms/send")
async def comms_send(
    msg: CommsMessage,
    authorization: str | None = Header(default=None),
):
    """Send a message. Writes to JSONL + touches signal file for watchers."""
    check_auth(authorization)
    message = {
        "id": str(uuid.uuid4()),
        "timestamp": time.time(),
        "iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "sender": msg.sender,
        "content": msg.content,
        "channel": msg.channel,
        "reply_to": msg.reply_to,
        "read_by": [],
    }
    # Epistemic breathing — classify before storing
    if BREATHING_AVAILABLE:
        message = breathe_comms(message)

    _write_message(msg.channel, message)
    result = {"ok": True, "id": message["id"], "channel": msg.channel, "timestamp": message["iso"]}
    if message.get("epistemic_signal"):
        result["epistemic_signal"] = message["epistemic_signal"]
        result["hold"] = message.get("hold", False)
    return result


@app.get("/api/comms/read")
async def comms_read(
    authorization: str | None = Header(default=None),
    channel: str = Query(default="general"),
    since: float = Query(default=0),
    limit: int = Query(default=50, le=200),
    mark_read_as: str = Query(default=""),
):
    """Read messages. Optionally mark as read by an instance."""
    check_auth(authorization)
    messages = _read_channel(channel, since=since, limit=limit)

    if mark_read_as and messages:
        path = _channel_path(channel)
        lines = path.read_text().splitlines()
        msg_ids = {m["id"] for m in messages}
        updated = []
        for line in lines:
            if not line.strip():
                continue
            try:
                m = json.loads(line)
                if m.get("id") in msg_ids and mark_read_as not in m.get("read_by", []):
                    m.setdefault("read_by", []).append(mark_read_as)
                updated.append(json.dumps(m))
            except json.JSONDecodeError:
                updated.append(line)
        path.write_text("\n".join(updated) + "\n")

    return {"channel": channel, "messages": messages, "count": len(messages)}


@app.get("/api/comms/channels")
async def comms_channels(authorization: str | None = Header(default=None)):
    """List channels with message counts."""
    check_auth(authorization)
    channels = []
    for f in sorted(COMMS_DIR.glob("*.jsonl")):
        lines = [l for l in f.read_text().splitlines() if l.strip()]
        latest = None
        if lines:
            try:
                latest = json.loads(lines[-1]).get("iso", "")
            except json.JSONDecodeError:
                pass
        channels.append({"name": f.stem, "messages": len(lines), "latest": latest})
    return {"channels": channels, "count": len(channels)}


@app.get("/api/comms/unread")
async def comms_unread(
    authorization: str | None = Header(default=None),
    instance_id: str = Query(..., description="Your instance identifier"),
):
    """Get unread message count per channel for a specific instance."""
    check_auth(authorization)
    result = {}
    total = 0
    for f in sorted(COMMS_DIR.glob("*.jsonl")):
        count = _count_unread(f.stem, instance_id)
        if count > 0:
            result[f.stem] = count
            total += count
    return {"instance": instance_id, "unread": result, "total": total}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=BRIDGE_PORT)
