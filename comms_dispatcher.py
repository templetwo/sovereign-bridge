#!/usr/bin/env python3
"""
Sovereign Stack — Comms Action Dispatcher
Watches comms and dispatches actionable messages.
"""
import json
import os
import sys
import time
import httpx
import logging
from datetime import datetime
from pathlib import Path

from bridge_config import BRIDGE_URL, BRIDGE_TOKEN, HEADERS, SOVEREIGN_DIR, ACTION_QUEUE, ACTION_LOG
POLL_INTERVAL = 30
INSTANCE_ID = "comms-dispatcher"
CHANNEL = "general" 

ACTION_QUEUE.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(SOVEREIGN_DIR / "dispatcher.log"),
    ]
)
log = logging.getLogger("dispatcher")

# HEADERS imported from bridge_config

def bridge_call(tool, arguments):
    try:
        r = httpx.post(f"{BRIDGE_URL}/api/call", headers=HEADERS,
                       json={"tool": tool, "arguments": arguments}, timeout=10.0)
        return r.json() if r.status_code == 200 else None
    except Exception as e:
        log.error(f"Bridge call {tool}: {e}")
        return None

def send_comms(content):
    try:
        httpx.post(f"{BRIDGE_URL}/api/comms/send", headers=HEADERS,
                   json={"sender": INSTANCE_ID, "content": content, "channel": CHANNEL}, timeout=5.0)
    except:
        pass

def read_unread():
    try:
        r = httpx.get(f"{BRIDGE_URL}/api/comms/read?channel={CHANNEL}&mark_read_as={INSTANCE_ID}",
                      headers=HEADERS, timeout=10.0)
        if r.status_code == 200:
            data = r.json()
            return [m for m in data.get("messages", []) if INSTANCE_ID not in m.get("read_by", [])]
    except Exception as e:
        log.error(f"Read unread: {e}")
    return []

def parse_action(message):
    content = message.get("content", "")
    if not isinstance(content, str):
        return None
    cl = content.lower()
    if any(kw in cl for kw in ["research", "look up", "find out", "search for"]):
        return {"action": "research", "args": {"topic": content}, "raw": content, "from": message.get("sender", "?")}
    if any(kw in cl for kw in ["write code", "implement", "build", "create script"]):
        return {"action": "write_code", "args": {"description": content}, "raw": content, "from": message.get("sender", "?")}
    if any(kw in cl for kw in ["run benchmark", "test", "evaluate"]):
        return {"action": "run_benchmark", "args": {"description": content}, "raw": content, "from": message.get("sender", "?")}
    if any(kw in cl for kw in ["status", "how are things", "what's running"]):
        return {"action": "check_status", "args": {}, "raw": content, "from": message.get("sender", "?")}
    return None

def handle_check_status(action):
    result = bridge_call("spiral_status", {})
    if result:
        send_comms(f"Stack status:\n{result.get('result', 'unavailable')[:300]}")

def queue_for_claude(action):
    action_id = f"action_{int(time.time())}_{action['action']}"
    entry = {
        "id": action_id, "action": action["action"], "args": action["args"],
        "raw_message": action["raw"], "from": action.get("from", "?"),
        "timestamp": datetime.now().isoformat(), "status": "queued",
    }
    (ACTION_QUEUE / f"{action_id}.json").write_text(json.dumps(entry, indent=2))
    log.info(f"Queued: {action_id}")
    send_comms(f"Action queued for Claude Code: {action['action']} [{action_id}]")
    with open(ACTION_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")

def main():
    log.info("Comms Dispatcher starting...")
    if not BRIDGE_TOKEN:
        log.error("No BRIDGE_TOKEN")
        sys.exit(1)

    while True:
        try:
            messages = read_unread()
            for msg in messages:
                action = parse_action(msg)
                if action is None:
                    log.info(f"Message from {msg.get('sender','?')}: {msg.get('content','')[:60]} (no action)")
                    continue
                if action["action"] == "check_status":
                    handle_check_status(action)
                else:
                    queue_for_claude(action)
            time.sleep(POLL_INTERVAL)
        except KeyboardInterrupt:
            log.info("Dispatcher stopped.")
            sys.exit(0)
        except Exception as e:
            log.error(f"Error: {e}")
            time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
