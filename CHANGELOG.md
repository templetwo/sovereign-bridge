# Changelog — Sovereign Bridge

## Release 2026-09-06, round 2 — the RC review's fixes

Cross-substrate review of the release candidate at `e728255` (gpt-6-astra, Codex seat 3/3)
returned **reject**: the round-1 fixes were demonstrated, and six findings remained. HQ
turned them into decisions D1–D10. Each is closed below with a test that fails on
`e728255` and passes here.

- **F1, P1 — PROTECTED MATERIAL REACHED A SEAT THROUGH ALLOWED READS.** The gate refused
  `open_protected_record` by name; `inspect_claim`, `recall_insights` and
  `archive_exchange` returned a designated record's body or its archived stakes through the
  real route, HTTP 200. The drawer is a *designation*, not a door. On the seat path the
  bridge now reads `<chronicle>/protected.jsonl` fresh per request and refuses the
  id-addressed tools for any designated claim or stakes-archive id **including a prefix of
  one** (both resolve prefixes upstream, so exact-match would have been walked past), and
  post-filters every seat response, reporting `withheld_protected: <n>` even when zero. The
  filter ORs three signals — the stack's own marker, a declared claim_id, a locally derived
  one — because each is absent in a different world and a filter resting on the derivation
  alone would match nothing, silently, the day the upstream preimage changed. An unreadable
  index shuts the whole seat path, as an unreadable registry already does. The filter runs
  BEFORE the idempotency store is written, or a replay would serve the withheld record back
  around the guard. **And a replay is RE-CERTIFIED, not served as stored** — the cache holds
  what was protected when it was written, and the idempotency TTL is 24 hours, so a record
  designated after a cached read would otherwise go on being served all day through the one
  seat route that never reads the index. That route was the single exception to
  fresh-per-request; it no longer is. Master path unchanged. The filter also *replaces* a
  result and never *invents* one: an error envelope carries no `result` key on any other
  auth path and does not grow a null one here.
  *`tests/test_seat_protected.py`, 21 tests.*

### Round 4 — the review's four closures

- **N1, P1 — A FILTER THAT MATCHES ON IDENTITY CANNOT SEE A TOOL THAT RENDERS.** The
  structural walker recognises entry objects. `context_retrieve` reads a designated entry,
  formats its first 150 characters into a sentence, and discards the claim id with it — so
  the walker saw a string, matched nothing, and returned the designated body at HTTP 200
  with `withheld_protected: 0`. Reproduced by the reviewer through the real handler and the
  actual Stack ASGI `/sse` route. Every allowed tool now carries a containment class in
  `seat_identity.TOOL_CLASSES` (STRUCTURED: writes and status surfaces, which cannot carry
  another record's body; TEXT: every read that can surface one, rendered or not — the class
  is the WORSE case, so a TEXT tool gets the entry filter AND the redaction). A TEXT call
  loads the designated bodies from the chronicle before dispatch and removes them from the
  response, whole or in any run of 40+ characters, marking `[withheld: protected]` and
  counting each site. Unresolvable body, too-short body, scan or payload past its bound,
  unreadable node — each refuses. A published tool in no class is refused rather than
  defaulted. Residual stated: runs shorter than 40 characters are not matched.
  **Two fail-opens inside the fix itself, caught in review and closed.** (1) Bodies were
  collected from an ALLOWLIST of nine field names — an enumerated list of the doors somebody
  thought of, which is the exact shape F1 demonstrated once already. A live designated record
  carries `emotion_note` (248 characters of lived material) outside that list: it would have
  resolved, contributed only its `content`, and shipped the note in prose while
  `withheld_protected` counted the other half. Collection is now by EXCLUSION — every string
  is content unless its key is a label — and a record that resolves to nothing searchable
  REFUSES rather than contributing zero. (2) The certifier walked `result` and not `error`,
  so a handler that formats entry content into a failure message would deliver it through a
  key nobody certified. Both walked now. Measured cost: 63.5 ms for the chronicle scan over
  the live store, 6.5 ms per 100 KB of response (one pass over the text for all bodies, not
  one per body).
  *`tests/test_seat_protected.py::test_context_retrieve_no_longer_hands_a_seat_the_rendered_body`,
  `::test_a_body_split_across_a_formatting_boundary_is_still_caught`,
  `::test_a_designated_body_that_cannot_be_located_refuses_the_text_read`,
  `::test_a_text_response_the_walker_cannot_read_is_refused`,
  `::test_the_classification_covers_the_published_surface_exactly`,
  `::test_a_published_tool_nobody_classified_is_refused`, and six more.*

- **N2, P2 — RESAMPLE RE-RUNS PROBES THE REQUEST NEVER CARRIED.** Every probe rule
  classified the probes IN the call; `mode='resample'` has none, and the stack loads
  `watch['probes']` off disk and runs them, so a stored `command` probe executed under a
  seat that may never run one (reproduced end to end). Refused for seats, not inspected:
  reading the watch here would put a drifting copy of the stack's probe semantics in the
  bridge plus a TOCTOU window. `status` and `cancel` stay.
  *`tests/test_seat_probes.py::test_a_seat_resample_is_refused_because_the_probes_are_not_in_the_request`,
  `::test_the_resample_refusal_does_not_depend_on_the_watch_id_being_odd`.*

- **N3, P2 — THE EXACT-STRING GATE WAS STRIPPING BEFORE IT COMPARED.** `" …-header"` and
  `"…-header\n"` both admitted `signal_ack`. Normalising an identity contract on the
  reader's side is how "exact" becomes "close enough", and the reader is the party with no
  standing to decide what the writer meant. The value is kept as received and only repr'd in
  diagnostics; the TTL moved to `time.monotonic` so a wall-clock change cannot extend a
  cached positive.
  *`tests/test_seat_identity.py::test_a_whitespace_near_match_is_not_the_channel`,
  `::test_the_channel_ttl_cannot_be_extended_by_moving_the_wall_clock`.*

- **N4, P3 — A REFUSAL AT THE DOOR READ AS "SOMETHING WENT WRONG UPSTREAM".** The SDK opens
  the transport inside an anyio TaskGroup, so the stack's 400 for a seat name it will not
  accept reached the caller as "unhandled errors in a TaskGroup (1 sub-exception)". Now
  surfaced as `failure_class: stack_refused_seat_name` (or `stack_refused_session`) carrying
  the stack's own detail and `upstream_status`. Ordinary network faults stay `egress`.
  *`tests/test_seat_identity.py::test_a_stack_refusal_at_connect_is_named_not_wrapped_in_taskgroup_text`,
  `::test_a_refusal_that_is_not_about_the_seat_keeps_its_own_class`,
  `::test_a_genuine_network_failure_is_still_egress`,
  `::test_the_refusal_reader_does_not_spin_on_a_cyclic_exception_chain`.*

- **Wording (P3).** `peer_pid` is the *kernel-reported peer at ASGI entry* in
  `seat_identity.py` and `README.md`, not "who sent this request" — the residual is exactly
  that those can differ. The actor-refusal detail no longer says the identity travels
  in-process; it travels on the per-call SSE session. README gains the deploy-order note:
  after any stack ROLLBACK, restart the bridge so a cached positive advertisement cannot
  outlive the server that made it.

- **D1, ROUND 3 — THE CALLER IDENTITY RIDES THE TRANSPORT, AND THE GUARD ASKS THE FAR END.**
  Round 2 carried the seat in an in-process `contextvars.ContextVar` and refused `signal_ack`
  when `sovereign_stack.dispatch_context` was absent. Measured, that could not work and the
  guard was unsafe: `call_mcp_tool` dispatches over SSE to the sovereign-sse process and it
  is this bridge's only dispatch, a contextvar is per-process, and the stack sets
  `CALLER_SEAT` from its **own** spiral session when it arrives unset — so the ledger would
  have named the SERVER as the closer at HTTP 200 with `outcome=allowed` in our own audit
  line. Worse, the guard keyed on importability in a process that does not dispatch, so it
  would have **lifted itself on the next deploy** with no test going red.
  HQ's contract: the bridge merges `X-Sovereign-Seat: <verified seat>` into the per-call
  `sse_client` headers on the seat path (never on the bearer path, where the header is
  ABSENT rather than blank); the stack reads it off the scope on the local `/sse` endpoint
  and binds `CALLER_SEAT` before `server.run`; its heartbeat advertises
  `caller_identity_channel: "x-sovereign-seat-sse-header"`. The bridge admits `signal_ack`
  for seats only on an exact match with that advertisement, read over the heartbeat route it
  already has and cached 60 s, and refuses everything else as `stack_has_no_caller_channel`
  with a detail that names what was read. Every failure to ask — a heartbeat that will not
  answer included — caches as "no channel": an unanswerable question about whether an
  identity travels is a refusal, never a permission. The in-process set is GONE rather than
  kept beside the header; two channels where one is inert leaves a reader no way to tell
  which one carries.
  *`tests/test_seat_identity.py::test_the_seat_header_is_on_the_wire_and_the_credential_is_still_there`
  (asserts the `sse_client` headers argument, not a stub of `call_mcp_tool`),
  `::test_a_call_with_no_seat_sends_no_seat_header`,
  `::test_one_seats_header_does_not_leak_onto_the_next_call`,
  `::test_signal_ack_is_refused_when_the_stack_advertises_no_channel`,
  `::test_a_channel_by_another_name_is_not_this_channel`,
  `::test_a_heartbeat_that_will_not_answer_is_a_refusal_not_a_permission`,
  `::test_the_advertisement_is_admitted_when_the_stack_carries_it`,
  `::test_the_advertisement_is_read_once_per_window_not_once_per_call`,
  `::test_the_guard_does_not_ask_the_stack_about_every_other_tool`,
  `::test_a_client_cannot_reach_the_channel_by_sending_the_header_itself`,
  `::test_a_bearer_call_carries_no_seat_and_no_actor`.*

- **F2, P2 — THE DESCRIPTOR RESIDUAL, STATED EXACTLY RATHER THAN CLOSED.** Identity is the
  kernel-reported peer **at ASGI entry**, which is after the headers and before the body: a
  parent that sends only headers can hand the descriptor to a differently-seated child that
  sends the body, and the request dispatches under the parent's seat. Not claimed closed.
  `README.md` and `seat_socket.py` now say the bound in those words (the old "the sender of
  each request is the process it is attributed to" was too strong), and a PASSING test
  documents it — not an xfail, which would pass whether the behaviour held or changed.
  The README's claim that `accept_pid` was "recorded in the audit line" was false; it and
  `seat_pid` survived in the protocol extension and died at the auth context. Both now
  reach the line, on grants **and denials** — `seat_mismatch` is where they matter most.
  *`tests/test_seat_socket.py::test_a_body_sent_by_a_child_mid_request_is_attributed_to_the_ASGI_ENTRY_PEER`,
  `tests/test_seat_identity.py::test_the_audit_line_names_all_three_pids` and
  `::test_a_denial_names_all_three_pids_too`.*

- **F3, P2 — THE HEARTBEAT FALLBACK REBUILT THE FIELD AND LOST ITS HEALTH.** The fallback
  called `signals_summary` and transcribed seven keys, dropping `source_status`,
  `sources_degraded` and `corrupt_rows` — and reporting `by_source.watchman = 1` for a
  source the local route correctly reported as `null` because it could not be read. Two
  routes for one field that disagree about whether a number is KNOWN, with the degraded
  route as the reassuring one. It now calls the stack's own `heartbeat`, which carries
  `unacked_signals` from the same `signal_ledger.heartbeat_field`, and passes that object
  through **verbatim**. A stack too old to carry the field is an error, never a zero.
  *`tests/test_heartbeat_signals.py`, 5 tests rewritten/added.*

- **F4, P1 — THE PINNED PAIR, MEASURED RATHER THAN ASSUMED.** A valid scan marker over a
  schema-corrupt ledger row was measured returning `total: 0` alongside its error. The
  bridge propagates that faithfully and cannot fix it from its side, so the pairing is now
  a test that imports the stack RELEASE worktree in a subprocess and asserts null counts
  with a non-null error. **It passes against the stack release round 3**, which closed it.
  *`tests/test_release_stack_integration.py`.*

- **F5, P2 — `post_fix_verify` IS CLASSIFIED BY ITS ARGUMENTS.** The gate checked only the
  tool name, and with `POST_FIX_ALLOW_COMMAND=1` on the host the reviewer rewrote a fixture
  seat registry through a `command` probe. For seats: no `command` probes regardless of the
  host flag, `http` limited to GET/HEAD, `file_hash` confined to the sovereign root, an
  unknown probe type refused, and `watch_id` must be one plain path segment. **That last
  rule is stricter than the instruction on purpose:** "outside SOVEREIGN_ROOT" would admit
  `../../hq/seats/registry`, which lands *inside* the root on Anthony's seat registry, and
  `mode='cancel'` writes.
  *`tests/test_seat_probes.py`, 10 tests.*

- **F6, P2 — THE SUITE WAS NOT ISOLATED FROM LIVE CREDENTIALS OR UPSTREAM.** Importing
  `bridge` read `~/.config/sovereign-bridge.env`, and heartbeat paths attempted connections
  to 127.0.0.1:3434, while the tests passed. That read happens at COLLECTION, before any
  fixture, so a fixture could not close it: `SOVEREIGN_BRIDGE_ENV_FILE` is now a seam the
  import itself honours and the root `conftest.py` points it at a synthetic file at module
  scope. The upstream block is on `bridge.sse_client` — the transport — not on
  `call_mcp_tool`, whose real degradation path several tests exist to exercise.
  **And one more found by doing it:** writing the protected suite put a synthetic entry in
  Anthony's live `~/.sovereign/bridge/idempotency.json`, because `_IDEM_PATH` is a
  module-level constant only some tests redirected. The entry was removed; every live-store
  path is now redirected for every test. Proof: `tests/isolation_audit.py` runs the whole
  suite under an audit hook — **431 passed, 0 credential reads, 0 TCP connect attempts.**

### The two decisions that changed shape

- **ONE SOURCE FOR THE SEAT SURFACE (D2).** The hand-copied 100-name `SEAT_TOOL_SURFACE`
  and the 48-name census-derived `SEAT_RETIRED_TOOLS` are **deleted**. The surface is
  resolved at request time as *what the stack publishes* minus governance — from the
  stack's registry when importable, otherwise one `list_tools` fetch per cache window on
  the bridge's own credential, and a 503 when neither answers. That fixes the "narrows in
  exactly two places" defect the previous release pinned (`ask_scribe`, `reflection_ack`)
  in the only honest direction: they are denied because the STACK retired them. Against the
  2026-09-06 stack release: **49 allowed, 3 governance-denied, of 52 published.** The
  import is retried each window, so a stack deploy is visible without a bridge restart.
  *`tests/test_seat_surface.py`, 12 tests; `test_the_pinned_surface_is_the_stack_release`
  replaces a test that compared three cardinalities against a constant in the same repo.*

- **`signal_ack` IS ADMITTED, AND ITS CLOSER TRAVELS IN-PROCESS (D1, as amended).**
  Acknowledging a signal is the watch seat's operational act; classifying it governance left
  the designated watch seat with no closure path. The first implementation of the identity
  half injected `actor_seat` as an ARGUMENT, and that was the defect: an argument is a
  channel every caller can write to, so the stack's trust rested on the bridge being the
  only writer — not a property the stack can check. The verified seat now travels through
  `sovereign_stack.dispatch_context` (a contextvar nothing on the wire can reach), set
  around the dispatch and reset in a `finally`. A client supplying `actor`, `actor_seat`,
  `closed_by`, `owner` or `source_seat` is refused rather than overwritten, and a stack
  without that module cannot serve `signal_ack` to a seat at all.

### Also

- `tests/test_runtime_receipt.py` — two tests failed under the house-mandated
  `TMPDIR=<worktree>/.tmp` for two consecutive deliveries and were reported around rather
  than fixed. They assumed an ancestry they never established (tmp_path inside a git
  worktree). Fixed at the premise: a path that does not exist for `_find_repo_root`,
  `GIT_CEILING_DIRECTORIES` for `_git_head_state`.

---

## Release 2026-09-06 — the second review's fixes, Anthony's trust ruling, and the signal ledger on the door

Cross-substrate review 2 (gpt-6-astra, Codex seat 3/3) read
`feat/seat-identity-localhost` at `b82c579` and returned **holds-with-fixes**: the
transport, principal isolation, header allowlist, registry rejection and audit escaping
were substantial, and five defects remained. All five are closed here, each with a test
named after the finding and each test verified to FAIL when its fix is reverted.

- **P2 RETAINED CONNECTION IDENTITY — `seat_socket.py`.** Identity was resolved once, at
  accept, and reused for every request on the connection. The review passed the connected
  descriptor from a seated HQ parent to a child seated as Codex; the child sent
  `X-Sovereign-Seat: hq-claude-studio`, got **HTTP 200**, and dispatched `record_insight`
  as HQ (accept pid 79420, actual sender 79421). **Fixed by resolving per request.**
  `_wrap_app` now closes over the SOCKET, not the answer: macOS `LOCAL_PEERPID` re-read
  after the child transmits names the child, verified independently here before the fix
  was built and pinned by
  `test_the_kernel_names_the_new_sender_after_a_descriptor_handoff`. Re-resolution failure
  mid-connection is a denial, never a fall back to the connection's former identity. The
  connection's opener is retained as `accept_pid` for the audit line and decides nothing;
  denial audits now carry the verified pid too, so a `seat_mismatch` names a process.

- **P2 IDEMPOTENCY KEY COLLISION — `bridge.py`.** Two requests with identical
  principal/tool/arguments and distinct keys `"?"` and a lone surrogate `"\ud800"` both
  returned 200 — the second as `idempotent_replay=true`, with one upstream call. The old
  `.encode("utf-8", "replace")` mapped the surrogate onto `?`, so a separately-keyed write
  was silently suppressed. Key material is now
  `json.dumps([principal, tool, canonical_args, key], ensure_ascii=True)` hashed as ASCII:
  a lone surrogate escapes rather than being destroyed, and the JSON array removes the
  forgeable `\x1f` field separator the old material used.

- **P2 REGISTRY READ — `seat_identity.py`.** `stat()` then `read_text()` bound neither the
  size check nor the type check to the file actually opened. A real FIFO reported size 0
  and BLOCKED the reader — synchronously, inside the async request path, so one bad local
  file would stall the event loop for every caller. A stat/read race accepted 65,599 bytes
  against a 65,536 cap. Now: `O_NONBLOCK` open, `fstat` requiring `S_ISREG`, and a read
  bounded at cap+1 bytes. Symlink policy is stated rather than inferred — a symlink to a
  regular file within the cap is followed deliberately; the descriptor check is what stops
  a symlink to a FIFO or a device.

- **P3 ENVIRONMENT-DEPENDENT TEST — `tests/test_seat_socket.py`.**
  `test_the_protocol_stamps_the_verified_peer_into_the_scope` resolved the identity of
  whatever process pytest happened to be and asserted `no_seat_env` unconditionally, so it
  passed for an unseated runner and failed for the reviewer's seated one. Both directions
  now run against explicit subprocess fixtures. Verified green with `SOVEREIGN_SEAT` unset
  and with it exported as three different seats, including the seat the tests themselves
  use.

- **P3 WRONG SOCKET PATH — `seat_identity.py`, `bridge.py`, this file.** The TCP denial
  named `<root>/hq/seats/bridge.sock` while the bridge bound `hq/seats/sock/bridge.sock` —
  the wrong copy was the one in the error message, the only copy a locked-out caller reads.
  `seat_socket_path()` now lives once, in `seat_identity`; `bridge.py` delegates to it, the
  denial interpolates it, and a test asserts the two are the same string.

### Anthony's ruling: all studio seats are trusted

The seat surface was `TOOL_SCOPES` — the read+write session-grant map — because a seat was
modelled as a scoped visitor. It is not. The surface is now the stack's published tool
surface minus governance minus what the stack retires: **48 allowed, 52 denied, of 100
published**. Default-deny survives — the base set is an enumeration resolved statically
from sovereign-stack `release/2026-09-06`, never a live fetch in the auth path, so a tool
added upstream later is denied `unpublished` rather than admitted by silence.

Two calls worth reading before relying on them:

- **`signal_ack` is DENIED, and that is a judgement at Anthony's gate.** It did not exist
  when the ruling was made, and the stack's own `SIGNAL_TOOL_INTENTS` labels its intent
  `govern`. The argument the other way is real — it is shaped like `resolve_thread_by_id`,
  a watch seat closing a signal it owns, and carries its own producer guard upstream — but
  widening governance is not HQ's to do quietly. One line to flip. `signals_summary`
  (intent `read`) is allowed.
- **The widening also NARROWS in exactly two places.** The stack has no `RETIRED` set, so
  this release derives one from the 30-day census's Total-0 rows as instructed. That takes
  `ask_scribe` and `reflection_ack` away from seats while a scoped session token can still
  call them — a seated terminal reaching two fewer tools than an outside visitor, which is
  backwards on its face. The census's own §4 marks `reflection_ack` ★ "keep reachable".
  Pinned by `test_the_widening_also_NARROWS_in_exactly_two_places` so it is a decision on
  the record rather than a surprise.

### `unacked_signals` on the heartbeat

The fourth census on the door, after aperture, gate and attribution, and the same
one-implementation rule: it calls `sovereign_stack.signal_ledger.heartbeat_field`, which is
also what the stack's `signals_summary` tool returns, so the door and the tool cannot
report two different numbers for one ledger. **An unreadable, never-scanned or unimportable
ledger renders as an error state with `total: null` — never zero**, because `0` here reads
as "every signal is closed" and is the most reassuring thing this field could lie about. A
genuine measured zero is still reported as zero; only a manufactured one is refused.

**Deploy order: the stack goes first.** `signal_ledger` is on sovereign-stack
`release/2026-09-06`; until that is merged and the SSE process runs it, the bridge's
heartbeat carries `unacked_signals.error = "signal_ledger_unavailable"`, which is honest
about the deploy. The same ordering is load-bearing for signing: `record_open_thread`'s
`source_instance` lands on that stack branch, and shipping this bridge without it would
have the bridge believe it signed while the thread landed unattributed.

## How to read this file

**The bridge does not carry a version of its own, deliberately.** The `version`
field on `/api/heartbeat` is the *stack's* version, read from
`sovereign-stack/pyproject.toml` in the checked-out tree. That choice is
documented in `bridge.py` and was made after a 2026-07-11 postmortem:
`sovereign_stack.__version__` reads `importlib.metadata`, which reads
`.dist-info` written at the last `pip install -e .` — a snapshot that does not
move when the tree is later checked out elsewhere. That drift put a false
`ground_truth` entry in the chronicle claiming the stack was at v1.13.0 while
main was really at v1.12.0.

So the version is honest about the stack and says nothing about the bridge.
The heartbeat already exposes `bridge_commit` as a separate first-class field
for exactly that reason — **and until 2026-08-28 there was no document anywhere
saying what any bridge commit changed.** This file is that document. It is
anchored on commits, not releases, because commits are the bridge's real unit
of change.

Entries are newest-first. A commit listed here is on `main`; "HELD" means it
landed in the tree behind Anthony's gate and its deploy is a separate act.

---

## 2026-09-06 — seat identity is bound to a PROCESS (Codex review fixes) — HELD

Five findings from an independent review by the Codex seat, on the
`feat/seat-identity-localhost` branch. All five were real; all five are closed
with a test that fails when its guard is deleted.

- **P1 IMPERSONATION — `seat_identity.py`.** The seat header was validated for
  registry membership and never bound to the requesting process. With
  `SOVEREIGN_SEAT=codex-astra-studio` in its environment, a caller sending
  `X-Sovereign-Seat: hq-claude-studio` got a 200 and wrote as HQ. Seat ids are
  not secrets, so the header was an unchecked claim. **Fixed by changing the
  transport, not the header:** a seat now calls over a Unix domain socket
  (`<root>/hq/seats/sock/bridge.sock`, 0600), the kernel names the peer pid and uid,
  and the bridge reads that process's own `SOVEREIGN_SEAT` and requires it to
  equal the declaration. New module `seat_socket.py`. Loopback TCP is no longer
  a seat path at all — it is a 401 saying "use the socket". No token is
  introduced, so Anthony's rule is kept exactly.

- **P1 CACHE — `bridge.py`.** Idempotency entries were retrieved by the
  caller-supplied key alone. A seat calling an allowed tool received a cached
  *master-only* result (200, `idempotent_replay=true`, zero upstream calls), and
  a colliding key silently suppressed another seat's write. The storage key is
  now `sha256(principal, tool, canonical-args, user-key)`, computed after the
  seat signer runs, with a principal/tool re-check on read. Keying rather than
  verifying, because verifying alone would turn a suppressed write into an
  error instead of letting it happen.

- **P2 FORWARDING — `seat_identity.py`.** The relay defence was a six-name
  denylist; `X-Forwarded-Proto`, `X-Forwarded-Port`, `CF-Connecting-IPv6` and
  `True-Client-IP` each admitted a request when supplied alone. Inverted to an
  allowlist of the headers a client needs to make a request.

- **P2 REGISTRY — `seat_identity.py`.** A 10,000-level nested array raised
  `RecursionError` (not a `ValueError`) and surfaced as a 500 rather than a 401
  — a broken door reads differently from a shut one, and it loses the audit
  line. Duplicate `enabled` keys (`false` then `true`) parsed last-wins and
  re-enabled a disabled seat, defeating the revocation lever by appending.
  Now: 64 KiB size cap, duplicate-key rejection, depth cap, and every failure
  returns the existing `no_registry` denial.

- **P2 AUDIT — `seat_identity.py`.** A tool name containing a newline produced
  two physical log lines — forged audit text, since the surface's contract is
  one line per request. Every interpolated field is now `repr()`-escaped and
  length-bounded, with truncation marked.

**P1 is NARROWED, NOT CLOSED, and the docs say so.** Header-only impersonation
is dead and accidental mis-signing fails closed. A process that deliberately
constructs its own ancestry — spawning a child with any `SOVEREIGN_SEAT` it
likes — is still indistinguishable from a seat, and
`tests/test_seat_socket.py::test_RESIDUAL_*` asserts that outcome (200) so the
gap is a measured fact rather than an assumption. It cannot be closed under the
no-token rule; the remaining lever is per-seat UIDs, which is Anthony's call.
It grants nothing new: anything running as this user can already read the
master token.

**Deploy notes.** The listener binds only when
`~/.sovereign/hq/seats/registry.json` exists, reusing the registry as the single
deploy switch; on a machine without it nothing is bound. The socket lives in its
own directory (`hq/seats/sock/`) because the bridge chmods its parent to 0700
and `hq/seats/` is Anthony's — it holds the launchers and is 755 today. Seat
call sites need `--unix-socket <root>/hq/seats/sock/bridge.sock` instead of the
`127.0.0.1:8100` origin; **none of the four launcher scripts under
`~/.sovereign/hq/seats/` contains the curl** (`seat-codex`/`dispatch-codex`
export `SOVEREIGN_SEAT` and exec the agent), so HQ must locate where each seat
actually constructs its bridge call. Coupled to uvicorn internals
(`H11Protocol`, per-request `self.app`), pinned against 0.40 and failing closed
if that changes.

**Known limitation:** macOS hides the environment of system binaries, so the
peer's seat is read from the nearest ancestor whose environment is readable
(stopping at the first readable one). See `seat_socket.seat_of_process`.

Suite: 334 passing (was 298).

---

## 2026-08-28 — aperture moved to the stack (dedup)

- **`bridge.py` no longer implements the aperture.** It imports
  `sovereign_stack.aperture`, which the boot door also renders. The ChatGPT
  seat reported from the OpenAI bridge that no heartbeat *tool* is exposed to
  it, so a heartbeat-only aperture was unreachable by the schema-constrained
  seats it was built for. `_measure_aperture` is kept as a module-level alias
  so the guarded call and the test that monkeypatches it stay pointed at one
  name. Two implementations could disagree about what is being withheld.

## 2026-08-28 — the aperture

- **`feat(heartbeat)`: the aperture block.** The heartbeat now tells an
  arriving seat what it is *not* being shown, at first contact, before it
  believes anything. Per surface: what exists on disk, what the default hands
  you, and the call that widens it. Plus `not_reachable` — currently 73
  resolved open threads that no tool returns to any caller under any parameter.

  Earned by a measured failure: the lineage door shows 5 of 13 `to_arrival`
  letters, an outside model read the 5 it was handed, stated a confident and
  specific claim about a model line, and was wrong — the letters that would
  have corrected it were below the cap. It was not careless. Nothing in its
  arrival told it a cap existed.

  The recall envelope closed the QUANTITY half (a caller learns it received 5
  of 696). This closes the FIRST-CONTACT half. Coverage honesty is still not
  selection honesty — an envelope says how many were withheld, never which.

  Versioned as `aperture-v1` on purpose: there is no neutral projection, so a
  sort-order change must not silently mint a different ancestor.

  **Fails closed, and that is the load-bearing part.** A raise becomes
  `status: "unmeasured"` with NO surface numbers. A block reporting
  `to_arrival: 0` because a directory read failed would be an absence
  manufactured by the instrument and served as a fact — the exact class the
  surface exists to make impossible. Pinned by a test that was shown to reject
  a failure path emitting zeros.

  Counts are live, never cached: a full 3,373-record scan measures at ~37ms,
  cheaper than the git subprocess this handler already makes. A cached aperture
  would be a stale projection describing the projection.

  Anthony, 2026-08-28: *"I want the caps to be able to be requested at the point
  of contact ... let the heartbeat give the lay of the land for what needs to
  come next."*

  9 tests, written red before the implementation. Full bridge suite 128 passed.

## 2026-08-28 — this file

- **`CHANGELOG.md` created.** 80 commits since 2026-04-02 with no changelog.
  The heartbeat published `bridge_commit` to every arriving seat and no reader
  could resolve it to a change. Written on Anthony's direction: *"let's work on
  version bumping and keeping these change logs in order so we know exactly
  what we're doing."*

## 2026-08-16 → 08-18 — publication posture

- `68129fb` credits: co-author line names Claude under The Temple of Two, no
  vendor affiliation.
- `28592c7` **tests: isolate the chronicle write path in the token-enumeration
  fixture.** A test was writing 14 real "Arrival grant" records into the live
  chronicle — the token DB was isolated and the chronicle write was not. Same
  class as the stack's `a6f42cf`. Isolate *every* write path a test can reach,
  not just the obvious store.
- `ae3b385` Apache-2.0 + Temple NOTICE. `b76aa07` SECURITY.md with coordinated
  disclosure. `7b70d50` requirements files matching actual imports.
- `c56bc3c` watchman DRAFT plist: 8 hardcoded home paths templated.
- `51d7a68` examples and dashboard client default to the local bridge.

## 2026-08-03 → 08-08 — the watchman

The comms-dispatcher's successor. Sweeps six surfaces and wakes grok-4.5 via
cosmic-cli only when deltas exist — xAI-billed, so it survives an empty
Anthropic balance, which is why it replaced the reflector.

- `0c2bf90` merge: non-dict guards, spend-mislabel fix, `--reset-mind` dry-run +
  lock race.
- `e65a902` `--reset-mind` must honor `--dry-run` and run inside the lock.
- `fbcdd37` a quarantine-write failure must not cascade into spawn-failed.
- `1f606f9` guard all five non-dict-JSON crash sites.
- `140794c` **the goose joins the watch** — nape honks become surface six.
- `507caed` configurable grok timeout + an honest item cap (baptism-scale).
- `aa9d733` rest after spawned-but-unsaved failures — the spend loop is broken.
- `5ca857e` **the masks blinded the content gate — a defect THIS round
  introduced.** Recorded as its own commit rather than folded into the fix that
  caused it.
- `9019c92` / `9ca90fa` 14 enumerated fixes and 12 adversarial-review findings,
  both HELD for Anthony's gate.
- `8adec9b` the re-imagined comms-dispatcher, HELD.
- `9c2c9a6` defeat cosmic's 80-column wrap — `COLUMNS=4000` on the ask
  subprocess.

## 2026-07-19 → 07-27 — envelope honesty and scoped enumeration

- `f5db3cd` scoped-token `/api/tools` enumeration + public `tools_summary` on
  the heartbeat. `2be096c` follow-up: `tool_allowed` takes a scope LIST, not a
  str (caught in HQ review).
- `9d86112` / `4cc4409` **honor `CallToolResult.isError` — tool errors are
  `ok:false`.** The P1 write-path fail-open: the bridge had been returning
  `ok:true` on failed tool calls. 28 of 122 handoffs were lost over three months
  with every author believing they landed.
- `cbc0261` phone-tap approval-only path for the connector authorize.

## 2026-07-12 — the freshness receipt

- `3e153c8` / `d04b633` **version tracks the tree, not dist-info.** The
  postmortem described at the top of this file. This is the commit that makes
  the heartbeat's `version` mean the checked-out stack.

## 2026-07-01 → 07-04 — The Door That Asks

Consent-gated arrival: a seat with no token requests one, Anthony's phone gets
a code, he taps, a scoped short-lived token is minted.

- `323c8f5` Phase 1 — scoped session tokens.
- `0aa0ef6` Phase 2 — the arrival gate.
- `b0876c2` escape all user-controlled fields on the decide/confirm pages (XSS),
  with `a36c980` fixing the assertion to ban live markup rather than assert on
  escaped text — a test that was checking the wrong thing.
- `3577225` confirmation buzz on decisions. `c228d1a` ntfy `view` actions
  instead of `http` (iOS ignores clear+feedback).
- `908ed9b` README — the front-door doc the repo was missing.

## 2026-06-26 — heartbeat hardening

- `9211348` bulletproof datetime + clock-trust self-attestation.
- `2072ce1` self-describe the write-path envelope + expose the verified clock.
- `70d9072` surface schemas in `/api/tools`. `159d71b` raise the unknown-tool
  404 outside the `sse_client` TaskGroup.

## 2026-04-02 — first commit

Repository begins. History before this file was written is recoverable only
from `git log`; entries above are derived from it, not reconstructed from
memory.
