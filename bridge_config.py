"""Shared bridge config — single source of truth for all sovereign-bridge tools."""
import os
from pathlib import Path

BRIDGE_URL = os.getenv("BRIDGE_URL", "http://127.0.0.1:8100")
BRIDGE_PORT = int(os.getenv("BRIDGE_PORT", "8100"))
BRIDGE_TOKEN = ""

TOKEN_FILE = Path.home() / ".config" / "sovereign-bridge.env"
if TOKEN_FILE.exists():
    for line in TOKEN_FILE.read_text().splitlines():
        if line.startswith("BRIDGE_TOKEN="):
            BRIDGE_TOKEN = line.split("=", 1)[1].strip().strip('"').strip("'")
            break

if not BRIDGE_TOKEN:
    BRIDGE_TOKEN = os.getenv("BRIDGE_TOKEN", "")

HEADERS = {"Authorization": f"Bearer {BRIDGE_TOKEN}", "Content-Type": "application/json"}

SOVEREIGN_DIR = Path.home() / ".sovereign"
CHRONICLE_DIR = SOVEREIGN_DIR / "chronicle"
COMMS_DIR = SOVEREIGN_DIR / "comms"
COMMS_INBOX = SOVEREIGN_DIR / "comms_inbox.txt"
ACTION_QUEUE = SOVEREIGN_DIR / "action_queue"
ACTION_LOG = SOVEREIGN_DIR / "action_log.jsonl"
