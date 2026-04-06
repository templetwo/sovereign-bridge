#!/usr/bin/env python3
"""
Sovereign Stack Dashboard — Real-Time Activity Monitor
"""
import asyncio
import json
import os
import sys
import time
import httpx
import signal
from datetime import datetime
from pathlib import Path
from collections import deque

from bridge_config import BRIDGE_URL, BRIDGE_TOKEN, HEADERS, SOVEREIGN_DIR, CHRONICLE_DIR, COMMS_INBOX

POLL_INTERVAL = 3
ACTIVITY_LOG_MAX = 50

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
GOLD = "\033[38;5;220m"
PURPLE = "\033[38;5;141m"
TEAL = "\033[38;5;80m"
RED = "\033[38;5;203m"
GREEN = "\033[38;5;114m"
BLUE = "\033[38;5;111m"
WHITE = "\033[38;5;255m"
GRAY = "\033[38;5;245m"
BG_HEADER = "\033[48;5;236m"

activity_log = deque(maxlen=ACTIVITY_LOG_MAX)
last_chronicle_mtime = {}
last_comms_check = None
services_status = {}
unread_messages = []
stats = {
    "tool_calls": 0, "uptime": "unknown", "phase": "unknown",
    "reflection_depth": 0, "services_up": 0, "services_total": 5,
    "comms_unread": 0,
}

def log_activity(category, message, color=GRAY):
    ts = datetime.now().strftime("%H:%M:%S")
    activity_log.appendleft({"time": ts, "category": category, "message": message, "color": color})

def clear_screen():
    os.system("clear" if os.name != "nt" else "cls")

async def get_spiral_status():
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.post(f"{BRIDGE_URL}/api/call",
                headers=HEADERS,
                json={"tool": "spiral_status", "arguments": {}})
            if r.status_code == 200:
                result = r.json().get("result", "")
                for line in result.split("\n"):
                    line = line.strip()
                    if line.startswith("Phase:"):
                        stats["phase"] = line.split(":", 1)[1].strip()
                    elif line.startswith("Tool Calls:"):
                        tc = int(line.split(":", 1)[1].strip())
                        if stats["tool_calls"] > 0 and tc > stats["tool_calls"]:
                            log_activity("TOOLS", f"+{tc - stats['tool_calls']} tool calls", TEAL)
                        stats["tool_calls"] = tc
                    elif line.startswith("Reflection Depth:"):
                        stats["reflection_depth"] = int(line.split(":", 1)[1].strip())
                    elif line.startswith("Duration:"):
                        secs = float(line.split(":", 1)[1].strip().replace("s", ""))
                        days = int(secs // 86400)
                        hours = int((secs % 86400) // 3600)
                        stats["uptime"] = f"{days}d {hours}h"
    except Exception as e:
        log_activity("ERROR", f"spiral_status: {e}", RED)

async def get_comms():
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(f"{BRIDGE_URL}/api/comms/unread?instance_id=dashboard",
                headers=HEADERS)
            if r.status_code == 200:
                data = r.json()
                stats["comms_unread"] = data.get("total", 0)
    except:
        pass

def scan_chronicle_changes():
    if not CHRONICLE_DIR.exists():
        return
    for jsonl_file in CHRONICLE_DIR.rglob("*.jsonl"):
        mtime = jsonl_file.stat().st_mtime
        key = str(jsonl_file)
        if key in last_chronicle_mtime and mtime > last_chronicle_mtime[key]:
            domain = jsonl_file.parent.name
            log_activity("CHRONICLE", f"Write to {domain}/{jsonl_file.name}", PURPLE)
            try:
                lines = jsonl_file.read_text().splitlines()
                if lines:
                    last = json.loads(lines[-1])
                    content = last.get("content", "")[:100]
                    layer = last.get("layer", "?")
                    log_activity("INSIGHT", f"[{layer}] {content}...", BLUE)
            except:
                pass
        last_chronicle_mtime[key] = mtime

def scan_comms_inbox():
    global last_comms_check
    if not COMMS_INBOX.exists():
        return
    mtime = COMMS_INBOX.stat().st_mtime
    if last_comms_check is None or mtime > last_comms_check:
        try:
            lines = COMMS_INBOX.read_text().strip().split("\n")
            if lines and lines[-1].strip():
                log_activity("LISTENER", f"Inbox: {lines[-1][:80]}", GREEN)
        except:
            pass
        last_comms_check = mtime

def check_launchd_services():
    svc_names = [
        ("com.templetwo.sovereign-sse", "SSE Server"),
        ("com.templetwo.sovereign-bridge", "REST Bridge"),
        ("com.templetwo.cloudflared-tunnel", "Tunnel"),
        ("com.templetwo.sovereign-tunnel", "Legacy Tunnel"),
        ("com.templetwo.comms-listener", "Comms Listener"),
    ]
    up = 0
    for svc_id, label in svc_names:
        result = os.popen(f"launchctl list 2>/dev/null | grep {svc_id}").read().strip()
        if result:
            pid = result.split()[0]
            if pid != "-":
                services_status[label] = f"UP (PID {pid})"
                up += 1
            else:
                services_status[label] = "LOADED (no PID)"
        else:
            services_status[label] = "NOT LOADED"
    stats["services_up"] = up
    stats["services_total"] = len(svc_names)

def render():
    clear_screen()
    width = min(os.get_terminal_size().columns, 120)
    print(f"{BG_HEADER}{BOLD}{GOLD}  {'†⟡† SOVEREIGN STACK DASHBOARD':^{width-4}}  {RESET}")
    print()
    phase_color = TEAL if stats["phase"] != "unknown" else RED
    print(f"  {BOLD}{WHITE}Phase:{RESET} {phase_color}{stats['phase']}{RESET}"
          f"  {GRAY}|{RESET}  {WHITE}Tools:{RESET} {TEAL}{stats['tool_calls']}{RESET}"
          f"  {GRAY}|{RESET}  {WHITE}Up:{RESET} {GRAY}{stats['uptime']}{RESET}"
          f"  {GRAY}|{RESET}  {WHITE}Depth:{RESET} {PURPLE}{stats['reflection_depth']}{RESET}"
          f"  {GRAY}|{RESET}  {WHITE}Comms:{RESET} "
          f"{GOLD if stats['comms_unread'] > 0 else GRAY}{stats['comms_unread']} unread{RESET}")
    print()
    print(f"  {BOLD}{WHITE}SERVICES ({stats['services_up']}/{stats['services_total']}){RESET}")
    print(f"  {GRAY}{'─' * (width - 4)}{RESET}")
    for label, status in services_status.items():
        color = GREEN if "UP" in status else RED if "DOWN" in status or "NOT" in status else GRAY
        icon = "●" if "UP" in status else "○"
        print(f"  {color}{icon}{RESET} {WHITE}{label:<22}{RESET} {color}{status}{RESET}")
    print()
    print(f"  {BOLD}{WHITE}LIVE ACTIVITY{RESET}")
    print(f"  {GRAY}{'─' * (width - 4)}{RESET}")
    if not activity_log:
        print(f"  {DIM}Watching...{RESET}")
    else:
        cat_colors = {"TOOLS": TEAL, "CHRONICLE": PURPLE, "INSIGHT": BLUE,
                      "COMMS": GOLD, "LISTENER": GREEN, "ERROR": RED, "STARTUP": GREEN, "HEALTH": GRAY}
        for entry in list(activity_log)[:15]:
            color = cat_colors.get(entry["category"], GRAY)
            print(f"  {DIM}{entry['time']}{RESET} {color}{BOLD}{entry['category']:<12}{RESET} {WHITE}{entry['message']}{RESET}")
    print(f"\n  {DIM}Refresh: {POLL_INTERVAL}s | Ctrl+C to exit | {datetime.now().strftime('%H:%M:%S')}{RESET}")

async def main():
    log_activity("STARTUP", "Dashboard starting...", GREEN)
    check_launchd_services()
    log_activity("HEALTH", f"{stats['services_up']}/{stats['services_total']} services", GREEN)
    if CHRONICLE_DIR.exists():
        for f in CHRONICLE_DIR.rglob("*.jsonl"):
            last_chronicle_mtime[str(f)] = f.stat().st_mtime
    log_activity("STARTUP", "Ready. Monitoring sovereign-stack.", GREEN)
    cycle = 0
    while True:
        try:
            scan_chronicle_changes()
            scan_comms_inbox()
            if cycle % 3 == 0:
                await get_spiral_status()
            if cycle % 5 == 0:
                await get_comms()
            if cycle % 10 == 0:
                check_launchd_services()
            render()
            cycle += 1
            await asyncio.sleep(POLL_INTERVAL)
        except KeyboardInterrupt:
            print(f"\n{GOLD}Dashboard stopped. Stack continues to breathe.{RESET}")
            sys.exit(0)
        except Exception as e:
            log_activity("ERROR", str(e)[:80], RED)
            await asyncio.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, lambda s, f: sys.exit(0))
    asyncio.run(main())
