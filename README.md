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
a caller whose own environment is readable can no longer name a seat that environment does
not name, so accidental mis-signing fails closed and a script with the wrong header stops
writing as the wrong seat. **That claim carries three qualifiers, all of them narrowings
required by the second review (2026-09-06), and none of them optional when this feature is
described to anyone:**

1. **Readable environment only.** See the limitation below. A child that hides its own
   environment is attributed to its nearest readable ancestor, which is inheritance, not
   proof of the immediate caller's identity.
2. **A connection is not an identity either, and neither is a request — quite.** A process
   can fork, or pass its connected descriptor over `SCM_RIGHTS`, and a later request on the
   same socket comes from a different process. The review demonstrated exactly that against
   the first version and got a 200 under the parent's seat. Identity is therefore resolved
   **per request**, not per connection, and that scenario is now a 401.
   **The exact claim, corrected 2026-09-06: identity is the kernel-reported peer at ASGI
   entry — not every process that contributed bytes to the stream.** Entry is after the
   headers and before the body, so a parent that sends only the headers can hand the
   descriptor to a differently-seated child which sends the body, and the request is
   dispatched under the parent's seat (measured: parent pid 75471, child pid 75480, HTTP
   200). The previous wording here — "the sender of each request is the process it is
   attributed to" — was too strong. The bound is asserted by a passing test,
   `test_a_body_sent_by_a_child_mid_request_is_attributed_to_the_ASGI_ENTRY_PEER`; closing
   it needs identity resampled per body chunk plus a policy for a mid-stream change, which
   is an architectural decision, not a patch.
   Every seat audit line carries **three** pids: `pid` (who sent it, and decided the call),
   `seat_pid` (whose environment named the seat — differs when the seat was inherited), and
   `accept_pid` (who opened the connection — differs exactly when the descriptor changed
   hands). They are on the **denial** line too, which is where they matter most. Until
   2026-09-06 this README claimed `accept_pid` was recorded and it was not; it survived in
   the protocol extension and died at the auth context.
3. **Deliberate impersonation is not stopped.** Any process running as this user can spawn
   a child with whatever `SOVEREIGN_SEAT` it likes. That residual is asserted explicitly in
   `tests/test_seat_socket.py` rather than left as an assumption, and it cannot be closed
   without either a token (which the whole design forbids) or per-seat UIDs (an ops
   decision).

It grants nothing new either way: anything running as this user can already read the master
token out of `~/.config/sovereign-bridge.env`. This is **not** a privilege boundary between
local processes and cannot be one. The asset is the chronicle's attribution.

**One limitation, named.** macOS hides the environment of system binaries: `/usr/bin/curl`
and `/bin/sleep` expose none, while `/usr/bin/python3` and Homebrew binaries do. So the
bridge walks to the nearest ancestor whose environment it can read — in practice the agent
process the seat launcher started — and stops at the first readable one. A process spawned
by a seated terminal, whose own environment is hidden, is therefore treated as that
terminal's seat. That is what environment inheritance already means, and it is why
`env -u SOVEREIGN_SEAT` only drops the seat for clients that expose their environment.

**Scope — widened 2026-09-06 by Anthony's ruling, *"all studio seats are trusted."***
A seat is not a scoped visitor; it is a terminal the operator started on his own machine.
The surface is

    what the stack PUBLISHES right now  −  governance

which against the 2026-09-06 stack release is **49 of the 52 published tools**, up from the
19 a `read`+`write` session grant reaches. `where_did_i_leave_off` — the boot door every
arriving seat is *told* to call, and which no seat but the master could reach — is among the
tools this opens.

**One source, resolved at request time.** The published list is read from the stack's own
registry (`RETIRED_TOOLS` + `list_tools`) when that module is importable, and otherwise
fetched once per cache window through the bridge's own credential. This release deleted the
two constants that used to stand in for it: a hand-copied 100-name surface and a 48-name
"retired" set derived from a 30-day usage census, because the stack had no retirement of its
own. It has one now, and a census measures disuse, not retirement. **If neither route
answers, a seat request is a 503, never an allow-all and never a deny-all dressed as
policy** — an authorization decision needs the published set, and the two defaults available
without it are both lies. **Consequence worth stating: run this bridge against a stack that
has retired nothing and a seat reaches everything that stack publishes minus governance.
The seat surface is the stack's surface minus Anthony's, which is one more reason the stack
deploys first.**

**Governance is still Anthony's, and being trusted is not being him:** `set_policy`,
`govern`, the protected drawer (`designate_protected`, `open_`/`decline_`/
`list_protected_thresholds`), `resolve_thread` (by match), `retire_hypothesis`,
`mint_token`, `revoke_token`, `audit_decoupling`, and the session-lifecycle pair
`close_session` / `spiral_inherit`, which mutate global spiral state and stay as they were.
`resolve_thread_by_id` is **allowed** — closing a thread by its id is a seat's ordinary act,
and so is `signal_ack`: acknowledging a signal is what a watch seat exists to do, and
denying it left the designated watch seat with no closure path at all. Default-deny survives
the widening: a name the stack does not publish is denied `unpublished`, never trusted by
silence.

**Protected material never reaches a seat.** Blocking `open_protected_record` by name was
not the boundary it looked like — the drawer is a *designation*, not a door, and the review
pulled a designated record's body and its archived stakes back through `inspect_claim`,
`recall_insights` and `archive_exchange`. On the seat path the bridge now reads
`<chronicle>/protected.jsonl` fresh per request and (a) refuses `inspect_claim` /
`archive_exchange` for any designated claim or stakes-archive id, **including a prefix of
one**, since both resolve prefixes upstream; (b) drops designated entries from every seat
response and states the subtraction as `withheld_protected: <n>` — reported even when zero,
because "the filter ran and removed nothing" and "the filter did not run" are different
facts. An index that cannot be parsed shuts the whole seat path, exactly as an unreadable
registry does. The master-token path is untouched.

**`post_fix_verify` is classified by its arguments, not by its name.** For seats: no
`command` probes (regardless of `POST_FIX_ALLOW_COMMAND` on the host — a boundary that holds
only while another component is configured a certain way is not a boundary), `http` probes
limited to GET/HEAD, `file_hash` probes confined to the sovereign root, an unknown probe type
refused, and a `watch_id` must be one plain path segment.

**The closer identity travels on the transport, never as an argument.** `signal_ack`
stamps who closed a signal. The bridge merges `X-Sovereign-Seat: <kernel-verified seat>`
into the headers of the per-call SSE session it already opens; the stack's `handle_sse`
reads it off the ASGI scope on the plain local `/sse` endpoint, validates it, and binds
`CALLER_SEAT` before `server.run`. A client supplying `actor`, `actor_seat`, `closed_by`,
`owner` or `source_seat` is refused rather than overwritten — a field trusted because of
*who usually sets it* is not verified, it is assumed.

The same header name arrives inbound and means something weaker: **inbound it is a client
DECLARATION** checked against the kernel-verified peer, **outbound it is this bridge
ASSERTING** an identity it already verified. The outbound value is built from the verified
seat and never copied from the request, and the module-level header dict is never mutated,
so one seat's header cannot leak onto the next call.

**A seat is served `signal_ack` only when the stack says it reads that channel.** The guard
asks the stack's own heartbeat for `caller_identity_channel` (over the tool route the bridge
already has, cached 60 s) and admits the tool only on an exact match with
`x-sovereign-seat-sse-header`. Anything else — an older stack, a heartbeat that will not
answer, a field of the wrong shape, a channel by another name — is `403
stack_has_no_caller_channel`, and **the detail names what was actually read** rather than
asserting an absence. Without that confirmation the stack falls back to its own shared
spiral session and the ledger would name **the server** as the closer while the call
returned 200.

> ⚠ **WHY THE GUARD ASKS THE FAR END, WRITTEN DOWN BECAUSE THE OBVIOUS GUARD WAS UNSAFE.**
> The first design carried the seat in a `contextvars.ContextVar`
> (`sovereign_stack.dispatch_context`) and refused when that module was absent. Measured:
> `call_mcp_tool` dispatches over SSE to 127.0.0.1:3434 — the **sovereign-sse process**, and
> it is this bridge's only dispatch (`bridge_core`, the in-process shim, is not used here).
> A contextvar is per-process, so the identity never arrived. And the stack does not leave
> the gap empty: its dispatch entry sets `CALLER_SEAT` from its own spiral session when it
> arrives unset. Refusing on *module absent* keyed on importability **in a process that does
> not dispatch**, so it would have lifted itself on the next stack deploy with nothing here
> changing and no test going red. The lesson kept in the code: **measure the contract at the
> far end of the hop, never infer it at the near end.**

**Signing:** the bridge *overrides* `source_instance` with the seat id on every call whose
stack schema **declares** that field (`arrive`, `arrive_lineage`, `handoff`,
`record_insight`, `record_open_thread`, `where_did_i_leave_off`). A seat cannot claim
another identity — the body does not get a vote. **For every other write the seat is in the
audit line and not in the record**: injecting `source_instance` into a schema that does not
declare it is either a hard error upstream or, worse, a silent drop that would leave the
bridge believing it signed. The way to move a tool into the signed set is to add the field
to its stack schema, never to inject harder.

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
| `tests/`, `watchman/tests/` | pytest suites — arrival gate, session tokens, write-path, heartbeat, seat identity/socket/surface/protected/probes, watchman |
| `conftest.py` | suite-wide isolation: synthetic credential file, no upstream transport, no live store, no TCP |
| `suite_support.py` | the pinned seat surface + the measurement that checks it against the stack source |
| `tests/isolation_audit.py` | proves the isolation above, by instrumenting a whole suite run |
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
