#!/bin/bash
# Sovereign Comms Listener — checks for unread messages every 5 minutes
# Writes new messages to ~/.sovereign/comms_inbox.txt
# Designed to run as launchd service

BRIDGE_URL="http://127.0.0.1:8100"
TOKEN=$(grep BRIDGE_TOKEN ~/.config/sovereign-bridge.env | cut -d= -f2)
INBOX="$HOME/.sovereign/comms_inbox.txt"
INSTANCE="mac-studio-listener"

# Check for unread
UNREAD=$(curl -s "$BRIDGE_URL/api/comms/unread?instance_id=$INSTANCE" \
  -H "Authorization: Bearer $TOKEN" 2>/dev/null)

COUNT=$(echo "$UNREAD" | python3 -c "import json,sys; print(json.load(sys.stdin).get('total',0))" 2>/dev/null)
COUNT=${COUNT:-0}   # default to 0 when bridge is down or returns non-JSON

if [ "$COUNT" -gt 0 ]; then
    # Fetch and log new messages
    MESSAGES=$(curl -s "$BRIDGE_URL/api/comms/read?channel=general&mark_read_as=$INSTANCE" \
      -H "Authorization: Bearer $TOKEN" 2>/dev/null)

    echo "$(date '+%Y-%m-%d %H:%M') — $COUNT unread message(s):" >> "$INBOX"
    echo "$MESSAGES" | python3 -c "
import json, sys
d = json.load(sys.stdin)
for m in d.get('messages', []):
    if '$INSTANCE' not in m.get('read_by', []):
        print(f'  [{m.get(\"iso\",\"?\")}] {m.get(\"sender\",\"?\")}: {m.get(\"content\",\"\")[:200]}')
" >> "$INBOX" 2>/dev/null
    echo "" >> "$INBOX"
fi

# Heartbeat: always touch stdout so monitoring tools have a reliable
# "last run" signal regardless of whether unread messages were found.
# Without this the stdout log file's mtime never updates and the
# connectivity manager's stale check fires false positives.
echo "[$(date '+%Y-%m-%dT%H:%M:%SZ')] tick — count=$COUNT"
