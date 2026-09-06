# Sovereign Bridge

A stateless REST layer over the [Sovereign Stack](https://github.com/templetwo/sovereign-stack) MCP server. It lets any HTTP-capable seat — a phone, a web chat, a shell script, another substrate — reach the same chronicle, self-model, open threads, handoffs, and toolkit the native MCP connector exposes, without speaking MCP.

Runs on `127.0.0.1:8100` under launchd. Publishing `/api/*` beyond localhost is
optional and yours to arrange — a Cloudflare Tunnel, or any authenticating reverse
proxy in front of the local port. Nothing in this repo requires a particular public
host; the maintainer's own instance happens to be published at
`https://stack.templetwo.com`.

## Quick start

Examples default to the local bridge. If you have published yours, set `BRIDGE` to
your own public origin instead.

```bash
BRIDGE=http://127.0.0.1:8100          # local default
# BRIDGE=https://bridge.example.com   # ...or your published origin

# Is the stack alive? (no auth)
curl -s "$BRIDGE/api/heartbeat"

# Call a tool (auth)
curl -s -X POST "$BRIDGE/api/call" \
  -H "Authorization: Bearer $BRIDGE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"tool": "where_did_i_leave_off", "arguments": {}}'
```

`GET /api/discover` returns a self-describing entry-point doc.

## Endpoints

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /api/heartbeat` | none | liveness + version + verified clock (self-attesting) |
| `GET /api/discover` | none | self-describing entry doc |
| `POST /api/call` | yes | call one tool; supports `idempotency_key`, `validate_only`; returns `failure_class` on error |
| `POST /api/batch` | yes | several calls in one round trip |
| `GET /api/tools` | yes | tool list + schemas (`?name=<tool>` for full inputSchema) |
| `POST /api/arrival/request` | none | The Door That Asks — request consent-gated arrival |
| `GET /api/arrival/poll/{rid}` | none | poll for approval; releases the token once |
| `GET/POST /api/arrival/decide` | signed | approve/deny (GET renders a confirm page, POST decides) |
| admin: mint / revoke / list session tokens | master | HQ token management |

## Auth model

Three paths reach the bridge, decided in this order, with no fallback between them:

- **The master bridge token** (`BRIDGE_TOKEN`, in `~/.config/sovereign-bridge.env`) — full access. Never committed; loaded from the env file at startup.
- **Scoped session tokens** (`svs_` prefix) — short-lived, revocable, least-privilege. A leaked session token is a dead key card, not a master key: at no scope can it mint/revoke tokens, call `set_policy`, or touch the protected drawer. See below.
- **Seat identity** — no token at all, for terminals seated on this machine. See below.

An `Authorization` header of *any* kind is decided by the bearer path alone, whether it
succeeds or fails. Adding a seat header to a bad-bearer request buys nothing — only a
request with no `Authorization` header at all can reach the seat path.

## Seat identity — no token inside the machine

A terminal the operator seated on this machine has the filesystem already. Requiring it
to carry a bearer bought no security and cost it the ability to write the record at all.
The arrival flow above is for everything *outside*; this is for what is already inside.

A seat calls over a **Unix domain socket** — `<sovereign-root>/hq/seats/sock/bridge.sock`,
mode 0600 — and sends `X-Sovereign-Seat: <seat-id>` with **no** `Authorization` header:

```bash
curl --unix-socket ~/.sovereign/hq/seats/sock/bridge.sock \
  -H "X-Sovereign-Seat: $SOVEREIGN_SEAT" -H 'Content-Type: application/json' \
  -d '{"tool":"record_insight","arguments":{"content":"...","domain":"..."}}' \
  http://localhost/api/call
```

It is allowed only when **all** of these hold — any failure is a 401 naming the
condition, never a fallback to another path:

1. the request arrived on the seat socket (a TCP request is refused outright);
2. the kernel names the peer process, and it is owned by the same user;
3. that process's own `SOVEREIGN_SEAT` **equals** the `X-Sovereign-Seat` header;
4. only the headers a client needs to make a request are present (an **allowlist** — any
   `X-Forwarded-*`, `CF-*`, `Forwarded`, `Via`, `True-Client-IP` or unknown
   forwarding-shaped header is a 401);
5. the seat id is present in `~/.sovereign/hq/seats/registry.json`;
6. that entry carries `"enabled": true`, literally.

**Why a socket and not loopback TCP.** Loopback is not an identity. If the bridge is
published through a tunnel, the tunnel daemon runs on this machine and connects to
`127.0.0.1`, so a request from the open internet arrives with a *loopback peer* — and seat
ids are not secrets, so any local process could name any seat it liked. A Unix socket is
the only transport where the kernel will say **which process** is calling; the seat id is
then read from that process's environment rather than believed from its header. The header
stays as a declaration that must match, because a checked declaration audits better than
an inference.

**What this defends, and the line it does not cross.** It kills impersonation *by header*:
a caller can no longer name a seat its own environment does not name, so accidental
mis-signing fails closed and a script with the wrong header stops writing as the wrong
seat. It does **not** stop *deliberate* impersonation — any process running as this user
can spawn a child with whatever `SOVEREIGN_SEAT` it likes. That residual is asserted
explicitly in `tests/test_seat_socket.py` rather than left as an assumption, and it cannot
be closed without either a token (which the whole design forbids) or per-seat UIDs (an ops
decision). It grants nothing new either way: anything running as this user can already
read the master token out of `~/.config/sovereign-bridge.env`. This is **not** a privilege
boundary between local processes and cannot be one. The asset is the chronicle's
attribution.

**One limitation, named.** macOS hides the environment of system binaries: `/usr/bin/curl`
and `/bin/sleep` expose none, while `/usr/bin/python3` and Homebrew binaries do. So the
bridge walks to the nearest ancestor whose environment it can read — in practice the agent
process the seat launcher started — and stops at the first readable one. A process spawned
by a seated terminal, whose own environment is hidden, is therefore treated as that
terminal's seat. That is what environment inheritance already means, and it is why
`env -u SOVEREIGN_SEAT` only drops the seat for clients that expose their environment.

**Scope:** exactly what a `read`+`write` session grant gets (the same `TOOL_SCOPES` map,
reused, never widened), minus two narrowings — governance-shaped tools are denied
regardless of scope, and a write tool whose stack schema has no field to carry the seat
id is denied rather than written unsigned.

**Signing:** the bridge *overrides* `source_instance` with the seat id on every call that
declares it. A seat cannot claim another identity — the body does not get a vote.

**The registry file is the deploy switch.** There is no enable flag: absent or unreadable
registry means every seat request is refused. Creating the file turns the path on;
deleting it, or flipping `enabled` to `false`, revokes immediately (it is read fresh on
every request). See `examples/seats-registry.json`. Every seat request writes one audit
line — seat, tool, outcome, reason — to the bridge's log.

## The Door That Asks — consent-gated arrival

A tokenless seat earns a scoped key with a human tap, instead of being handed the master token.

1. The seat `POST /api/arrival/request` with its model line + a one-line description → gets a two-word code (e.g. `harbor-juniper`).
2. The phone gets an ntfy push with Approve/Deny; the seat says its code in the conversation so the human can match it.
3. On Approve, the seat's next poll mints and releases a scoped session token **exactly once** — plaintext exists in that one response and nowhere else; the store holds sha256 only.

- **`session_tokens.py`** — the token store + scope map (Phase 1).
- **`arrival_gate.py`** — request/poll/decide, signed decide URLs, ntfy push (Phase 2).
- **`stack_tokens.py`** — HQ CLI:

```bash
python3 stack_tokens.py mint --ttl 12 --scope read --label "claude.ai fable seat"
python3 stack_tokens.py revoke --token-id <id>     # or --all
python3 stack_tokens.py list
```

## Layout

| File | Role |
|---|---|
| `bridge.py` | the FastAPI server — every route |
| `bridge_config.py` | shared config; loads `BRIDGE_TOKEN` |
| `session_tokens.py` | scoped session tokens |
| `seat_identity.py` | seat identity — the decision: binding, scope, registry, audit |
| `seat_socket.py` | seat identity — the Unix-socket transport + peer credentials |
| `arrival_gate.py` | the arrival gate |
| `stack_tokens.py` | token CLI |
| `sovereign_dashboard.py`, `dashboard/index.html` | activity monitors (terminal, web) |
| `comms_dispatcher.py`, `comms_listener.sh` | legacy comms plumbing (the bulletin board is retired) |
| `tests/`, `watchman/tests/` | pytest suites — arrival gate, session tokens, write-path, heartbeat, watchman |
| `tests.py` | live-integration script; needs a running bridge |
| `requirements.txt`, `requirements-dev.txt` | runtime / test dependencies |

## Install

Python 3.11+ (`bridge.py` uses the stdlib `tomllib`).

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt          # runtime
pip install -r requirements-dev.txt      # + pytest, to run the suites
```

The companion [sovereign-stack](https://github.com/templetwo/sovereign-stack) is
deliberately not a pip dependency — it is not on PyPI. `bridge.py` adds
`~/sovereign-stack/src` to `sys.path` and imports it inside `try/except
ImportError`, so the bridge runs without it, with version reporting and the
shared comms read surface degraded. Install it from its own repo to get those.

## Running

Runs under launchd (`com.templetwo.sovereign-bridge`) on port 8100, reading `~/.config/sovereign-bridge.env` for `BRIDGE_TOKEN`, `ARRIVAL_DECIDE_SECRET`, `NTFY_TOPIC`, and friends. Restart:

```bash
launchctl kickstart -k "gui/$(id -u)/com.templetwo.sovereign-bridge"
```

If you publish the bridge, set **`PUBLIC_BASE_URL`** to your own externally
reachable origin. It defaults to `https://stack.templetwo.com` (the maintainer's
instance), and it is the origin the arrival gate signs into the approve/deny links
it pushes to a phone — left at the default on someone else's deployment, those
links point at a host the operator does not control.

Tests: `python3 -m pytest tests/ watchman/tests/`. (`tests.py` at the repo root is
a separate live-integration script — it talks to a *running* bridge and writes
through it; it is not part of the pytest suites.)

## Relationship to the native connector

The stack's `/sse` endpoint is the MCP-native connector (OAuth-gated, for MCP clients). This bridge is the counterpart for everything that can't speak MCP — plain HTTP, plus the consent-gated arrival flow. The bridge's version tracks the stack automatically (the heartbeat derives it live rather than hardcoding it).
