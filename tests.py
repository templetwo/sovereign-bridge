#!/usr/bin/env python3
"""
Sovereign Bridge — Bulletproof Test Suite
Run: python3 tests.py
"""
import json
import sys
import time
import os

sys.path.insert(0, os.path.dirname(__file__))

PASS = 0
FAIL = 0
ERRORS = []

def test(name, fn):
    global PASS, FAIL
    try:
        result = fn()
        if result:
            PASS += 1
            print(f"  \033[38;5;114m✓\033[0m {name}")
        else:
            FAIL += 1
            ERRORS.append(name)
            print(f"  \033[38;5;203m✗\033[0m {name}")
    except Exception as e:
        FAIL += 1
        ERRORS.append(f"{name}: {e}")
        print(f"  \033[38;5;203m✗\033[0m {name} — {e}")

# ════════════════════════════════════════
# 1. CONFIG MODULE
# ════════════════════════════════════════
print("\n━━━ 1. BRIDGE CONFIG ━━━")

def test_config_imports():
    from bridge_config import BRIDGE_URL, BRIDGE_TOKEN, HEADERS, SOVEREIGN_DIR
    return True
test("bridge_config imports", test_config_imports)

def test_config_url():
    from bridge_config import BRIDGE_URL
    return BRIDGE_URL.startswith("http")
test("BRIDGE_URL is valid", test_config_url)

def test_config_token():
    from bridge_config import BRIDGE_TOKEN
    return len(BRIDGE_TOKEN) > 10
test("BRIDGE_TOKEN loaded", test_config_token)

def test_config_headers():
    from bridge_config import HEADERS
    return "Authorization" in HEADERS and "Content-Type" in HEADERS
test("HEADERS has auth + content-type", test_config_headers)

def test_config_paths():
    from bridge_config import SOVEREIGN_DIR, CHRONICLE_DIR, COMMS_DIR, COMMS_INBOX, ACTION_QUEUE
    return all(isinstance(p, type(SOVEREIGN_DIR)) for p in [CHRONICLE_DIR, COMMS_DIR, COMMS_INBOX, ACTION_QUEUE])
test("All paths are Path objects", test_config_paths)

def test_sovereign_dir_exists():
    from bridge_config import SOVEREIGN_DIR
    return SOVEREIGN_DIR.exists()
test("SOVEREIGN_DIR exists on disk", test_sovereign_dir_exists)

# ════════════════════════════════════════
# 2. BRIDGE SERVER
# ════════════════════════════════════════
print("\n━━━ 2. BRIDGE SERVER ━━━")

import httpx
from bridge_config import BRIDGE_URL, BRIDGE_TOKEN, HEADERS

def test_heartbeat():
    r = httpx.get(f"{BRIDGE_URL}/api/heartbeat", timeout=5)
    d = r.json()
    return d.get("status") == "ok" and d.get("tools", 0) > 0
test("Heartbeat returns ok", test_heartbeat)

def test_heartbeat_tool_count():
    r = httpx.get(f"{BRIDGE_URL}/api/heartbeat", timeout=5)
    return r.json().get("tools", 0) == 42
test("Tool count is 42", test_heartbeat_tool_count)

def test_heartbeat_has_comms():
    r = httpx.get(f"{BRIDGE_URL}/api/heartbeat", timeout=5)
    return "comms_messages" in r.json()
test("Heartbeat includes comms_messages", test_heartbeat_has_comms)

# ════════════════════════════════════════
# 3. MCP TOOLS VIA BRIDGE
# ════════════════════════════════════════
print("\n━━━ 3. MCP TOOLS ━━━")

def test_spiral_status():
    r = httpx.post(f"{BRIDGE_URL}/api/call", headers=HEADERS,
                   json={"tool": "spiral_status", "arguments": {}}, timeout=10)
    d = r.json()
    return d.get("ok") and "Phase" in str(d.get("result", ""))
test("spiral_status returns phase", test_spiral_status)

def test_recall_insights():
    r = httpx.post(f"{BRIDGE_URL}/api/call", headers=HEADERS,
                   json={"tool": "recall_insights", "arguments": {"domain": "all"}}, timeout=10)
    return r.json().get("ok")
test("recall_insights works", test_recall_insights)

def test_get_open_threads():
    r = httpx.post(f"{BRIDGE_URL}/api/call", headers=HEADERS,
                   json={"tool": "get_open_threads", "arguments": {}}, timeout=10)
    return r.json().get("ok")
test("get_open_threads works", test_get_open_threads)

def test_guardian_status():
    r = httpx.post(f"{BRIDGE_URL}/api/call", headers=HEADERS,
                   json={"tool": "guardian_status", "arguments": {}}, timeout=10)
    d = r.json()
    return d.get("ok") and "health_score" in str(d.get("result", ""))
test("guardian_status returns health_score", test_guardian_status)

def test_batch_call():
    r = httpx.post(f"{BRIDGE_URL}/api/batch", headers=HEADERS,
                   json={"calls": [
                       {"tool": "spiral_status", "arguments": {}},
                       {"tool": "guardian_status", "arguments": {}},
                   ]}, timeout=15)
    d = r.json()
    return d.get("count") == 2 and all(x.get("ok") for x in d.get("results", []))
test("Batch call (2 tools) works", test_batch_call)

def test_tools_list():
    r = httpx.get(f"{BRIDGE_URL}/api/tools", headers=HEADERS, timeout=10)
    d = r.json()
    names = [t["name"] for t in d.get("tools", [])]
    return d.get("count") == 42 and "guardian_status" in names and "spiral_status" in names
test("Tools list has 42 tools including guardian and metabolism", test_tools_list)

# ════════════════════════════════════════
# 4. COMMS
# ════════════════════════════════════════
print("\n━━━ 4. COMMS ━━━")

def test_comms_channels():
    r = httpx.get(f"{BRIDGE_URL}/api/comms/channels", headers=HEADERS, timeout=5)
    d = r.json()
    return d.get("count", 0) > 0
test("Comms channels exist", test_comms_channels)

def test_comms_read():
    r = httpx.get(f"{BRIDGE_URL}/api/comms/read?channel=general", headers=HEADERS, timeout=5)
    d = r.json()
    return d.get("count", 0) > 0 and "messages" in d
test("Comms read returns messages", test_comms_read)

def test_comms_unread():
    r = httpx.get(f"{BRIDGE_URL}/api/comms/unread?instance_id=test-suite", headers=HEADERS, timeout=5)
    d = r.json()
    return "total" in d
test("Comms unread endpoint works", test_comms_unread)

def test_comms_send_and_read():
    ts = str(int(time.time()))
    # Send
    r = httpx.post(f"{BRIDGE_URL}/api/comms/send", headers=HEADERS, timeout=5,
                   json={"sender": "test-suite", "content": f"Test message {ts}", "channel": "general"})
    send_ok = r.json().get("ok")
    # Read back
    r2 = httpx.get(f"{BRIDGE_URL}/api/comms/read?channel=general", headers=HEADERS, timeout=5)
    msgs = r2.json().get("messages", [])
    found = any(ts in m.get("content", "") for m in msgs)
    return send_ok and found
test("Comms send + read round-trip", test_comms_send_and_read)

# ════════════════════════════════════════
# 5. AUTH
# ════════════════════════════════════════
print("\n━━━ 5. AUTH ━━━")

def test_no_auth_rejected():
    r = httpx.post(f"{BRIDGE_URL}/api/call",
                   json={"tool": "spiral_status", "arguments": {}}, timeout=5)
    return r.status_code in (401, 403)
test("No auth token → rejected", test_no_auth_rejected)

def test_bad_auth_rejected():
    r = httpx.post(f"{BRIDGE_URL}/api/call",
                   headers={"Authorization": "Bearer wrong_token", "Content-Type": "application/json"},
                   json={"tool": "spiral_status", "arguments": {}}, timeout=5)
    return r.status_code in (401, 403)
test("Bad auth token → rejected", test_bad_auth_rejected)

def test_heartbeat_no_auth():
    r = httpx.get(f"{BRIDGE_URL}/api/heartbeat", timeout=5)
    return r.status_code == 200
test("Heartbeat works without auth", test_heartbeat_no_auth)

# ════════════════════════════════════════
# 6. GUARDIAN
# ════════════════════════════════════════
print("\n━━━ 6. GUARDIAN ━━━")

def test_guardian_scan():
    r = httpx.post(f"{BRIDGE_URL}/api/call", headers=HEADERS,
                   json={"tool": "guardian_scan", "arguments": {"scan_type": "quick"}}, timeout=30)
    return r.json().get("ok")
test("Guardian quick scan works", test_guardian_scan)

def test_guardian_quarantine_list():
    r = httpx.post(f"{BRIDGE_URL}/api/call", headers=HEADERS,
                   json={"tool": "guardian_quarantine", "arguments": {"action": "list"}}, timeout=10)
    return r.json().get("ok")
test("Guardian quarantine list works", test_guardian_quarantine_list)

def test_guardian_baseline():
    r = httpx.post(f"{BRIDGE_URL}/api/call", headers=HEADERS,
                   json={"tool": "guardian_baseline", "arguments": {"components": ["ports"]}}, timeout=15)
    return r.json().get("ok")
test("Guardian baseline (ports) works", test_guardian_baseline)

def test_guardian_mcp_audit():
    r = httpx.post(f"{BRIDGE_URL}/api/call", headers=HEADERS,
                   json={"tool": "guardian_mcp_audit", "arguments": {}}, timeout=10)
    return r.json().get("ok")
test("Guardian MCP audit works", test_guardian_mcp_audit)

# ════════════════════════════════════════
# 7. DASHBOARD + DISPATCHER IMPORTS
# ════════════════════════════════════════
print("\n━━━ 7. MODULE IMPORTS ━━━")

def test_dashboard_imports():
    import sovereign_dashboard
    return True
test("sovereign_dashboard imports clean", test_dashboard_imports)

def test_dispatcher_imports():
    import comms_dispatcher
    return True
test("comms_dispatcher imports clean", test_dispatcher_imports)

def test_dashboard_uses_config():
    import sovereign_dashboard as sd
    from bridge_config import BRIDGE_URL
    # Dashboard should not have its own BRIDGE_URL definition
    source = open(os.path.join(os.path.dirname(__file__), "sovereign_dashboard.py")).read()
    return 'from bridge_config import' in source and source.count('BRIDGE_URL = "http') == 0
test("Dashboard imports from bridge_config (no hardcoded URL)", test_dashboard_uses_config)

def test_dispatcher_uses_config():
    source = open(os.path.join(os.path.dirname(__file__), "comms_dispatcher.py")).read()
    return 'from bridge_config import' in source and source.count('BRIDGE_URL = "http') == 0
test("Dispatcher imports from bridge_config (no hardcoded URL)", test_dispatcher_uses_config)

# ════════════════════════════════════════
# RESULTS
# ════════════════════════════════════════
print(f"\n{'━' * 50}")
total = PASS + FAIL
print(f"  \033[1m{PASS}/{total} passed\033[0m", end="")
if FAIL == 0:
    print(f"  \033[38;5;114m— ALL GREEN\033[0m")
else:
    print(f"  \033[38;5;203m— {FAIL} FAILED\033[0m")
    for e in ERRORS:
        print(f"    \033[38;5;203m✗\033[0m {e}")

sys.exit(0 if FAIL == 0 else 1)
