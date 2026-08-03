# The Watchman

The re-imagined comms-dispatcher. Anthony assigned the post to cosmic-cli/Grok
(2026-08-02): a standing watch over the stack's inbound surfaces that notices,
classifies, and proposes — and does nothing else.

## The two-tier shape

```
launchd (the ear — mechanical, free)
  └─ watchman_sweep.py (the mechanical tier: scan, diff, sanitize, digest)
       └─ ONLY when deltas exist:
          cosmic-cli ask  (the mind — grok-4.5, event-driven)
            └─ spool.jsonl + latest.md  (machine-local working memory)
```

The LLM wakes on sound, never on the clock. A quiet sweep touches state,
writes one heartbeat line to `watchman.log`, and exits without spending a
token. Five surfaces, every sweep, each reported ok/error — a surface that
could not be read is REPORTED in the envelope, never silently omitted:

| surface | what it catches |
|---|---|
| `{grok_bridge,openai_bridge,antigravity_connector}/pending_writes/` | new/changed proposal files (mtime+size vs state) |
| `daemons/halts/` | daemon halt events |
| `handoffs/` | unconsumed count (`consumed_at` null) changing |
| bridge `/api/heartbeat` `source_commit` vs `~/sovereign-stack` HEAD | the stale-process class |
| legacy comms board `channel=general` | `daemon.uncertainty` still posts there — its whispers finally land |

## The eyes policy (Option C — Grok's own design)

What the mind may see was decided by the seat that holds the post: Option C is
**Grok's own proposal**, adopted by HQ with fail-closed tightenings.

- **Metadata always travels — but SANITIZED.** Every string metadata field (at
  any depth, including nested `detail`) runs through the SAME redactor as
  previews and is capped at 200 chars with an explicit truncation marker. A
  field the redactor could not clean becomes `<field-unsanitized:omitted>` —
  never the raw value. Metadata is copied out of untrusted files and board
  messages and is handed to a third-party model in argv, in the prompt, and in
  the spool; treating it as inherently safe was the leak-hunt's headline
  finding.
  - **Dict KEYS are sanitized too**, and capped at the same 200 chars. A key
    that cannot be cleaned takes its whole pair with it: key and value both
    drop and the block carries `"<pair-unsanitized:omitted>": N`, a COUNT so
    two dropped pairs cannot collide on one token key and lose one silently.
    No surface produces attacker-controlled keys today (every key in
    `_extract_meta`, `scan_comms` and the `detail` blocks is a literal), so
    this is defence in depth, not a live leak closed. **Consequence to know:**
    with the redactor wholly down, every key fails and the block collapses to
    the counter alone. That is fail-closed and it is loud (the standing-blind
    detector escalates in the same sweep), but do not read a collapsed block
    as an empty surface.
- **The SURFACES block is sanitized like any other metadata**, before it
  enters the digest handed to Grok and before `latest.md` renders it. Its
  strings are not house-authored: a surface `error` is an exception message
  carrying whatever the failing call put in it, and a `note` carries commit
  hashes read off the wire. The attend lines for surface errors are derived
  from the surface NAME (a house literal) plus the sanitized text, so they
  survive even when the block collapses under a dead redactor — deriving them
  from the sanitized block's shape would have failed open exactly when the
  instrument was already hurt.
- **Preview** = first 600 chars of the body, run through the t2helix redaction
  patterns (`~/t2helix/lib/secrets.js` via `sanitize_preview.js` — the same
  single source of truth as the helix write path; the table is loaded, never
  copied, so the eyes can never drift from the helix).
- **Fail-closed, in every direction:**
  1. **Denylist — DECLARATION leg** → metadata-only, no preview ever:
     protected/consent-shaped items (tool `comms_acknowledge`, `protected` or
     `consent` anywhere in an item's metadata — a hard-coded floor no config
     can switch off), plus `eyes_policy.json` (seeded: the antigravity queue;
     biomedical and security-audit domains).
  2. **Denylist — CONTENT leg** → `metadata-only:content-flagged`. After
     redaction, the wide window is matched against `content_terms` from
     `eyes_policy.json`. The declaration leg only catches sensitivity the
     writer declared; a biomed body filed under `domain=general` previewed in
     full, and the comms surface (`tool=None`, `declared_domain=None`) had no
     reachable denylist key at all. **Over-withholding is accepted by design**
     — Grok's mandatory flag-for-richer-review covers what a withheld preview
     costs.
  3. Sanitizer subprocess error, 2s timeout, or non-zero exit → metadata-only,
     `preview_state='metadata-only:sanitizer-failed'`, recorded honestly.
  4. Unknown/unparseable file → `metadata-only:unparseable`; whitespace-only
     body → `metadata-only:empty-body` (and NOT counted as previewed — nothing
     was inspected).
  5. Eyes policy **strictly validated**, four gates: every listed key must be a
     list of strings; wrong nesting (a dict where a list belongs) is rejected;
     **unknown keys are rejected**, which is what catches a singular-key typo
     (`denylist_domain`) that used to be ignored while its real key defaulted
     to empty; and the policy must declare at least one recognized key AND deny
     something — a file that parses to all-empty denylists and empty
     `content_terms` is a truncated or half-written config, not an intent, so it
     falls to the floor. Keys beginning with `_` are comments and are allowed
     (the shipped file carries a `_comment`; a validator that rejected it would
     have closed the eyes on every production sweep). A file that exists but
     does not validate closes the eyes completely (`floor-fallback`,
     metadata-only for everything) and raises an attend line about the file. A
     missing file falls back to compiled-in seeds identical to the shipped ones
     (`builtin-fallback`) and still says so.
- **Homoglyph handling — two mechanisms, and only one of them is general.**
  1. **The map (fast path).** All denylist and content matching runs on NFKC-
     normalized, casefolded text with a confusables map applied to both needle
     and haystack. One Cyrillic codepoint (`prоtected`) used to walk past a
     floor described as un-turn-off-able. The folded form is used for MATCHING
     ONLY and is never persisted.
  2. **MIXED SCRIPT FAILS CLOSED (the general one).** Any word-token — in the
     sanitized metadata or in the redacted content window — whose LETTERS come
     from more than one Unicode script is treated as a content-flag hit and the
     item becomes `metadata-only:content-flagged`. No map, no enumeration: an
     ASCII word with a foreign codepoint spliced into it is the actual attack
     shape for slipping a denylist term past an ASCII substring test, and it
     now fails closed by construction, for every script. This check runs on RAW
     text — `fold()` would already have erased the evidence — and ignores
     non-letters so the build's own typed tokens and the truncation marker
     never trip it. Precise scope: it is the CONTENT leg, so it fires only on
     an item that would otherwise have produced a preview; a denylisted or
     unparseable item keeps its own state.
  **The residual, stated exactly:** a SINGLE-script lookalike that survives
  NFKC — an all-Cyrillic word, say — is not mixed, so mechanism 2 does not see
  it. It is reachable only through the map in mechanism 1, and the map only
  knows the confusables someone remembered to add. See RESIDUAL RISK.
- **base64 blobs.** Runs of 40+ base64-alphabet characters in a preview are
  replaced with `<BASE64-BLOB:len=N>` before truncation. **Two alphabets,
  exactly: standard (`+` `/`) and URL-safe (`-` `_`), including runs that mix
  them.** The URL-safe case used to walk straight through — the old run regex
  was `[A-Za-z0-9+/]{40,}`, so a single `-` or `_` split the run into segments
  all shorter than 40 and nothing matched at all. This is a **watchman-side
  mitigation of an UPSTREAM t2helix limit**: no pattern in `lib/secrets.js`
  decodes base64, so a base64-wrapped credential scrubs clean. The watchman's
  exposure differs in kind from the helix's — the helix persists locally, the
  watchman ships the preview off-machine to xAI — which is why the mitigation
  lives here. **The upstream gap is unclosed and is flagged for the Grok helm**:
  a base64-wrapped secret still passes t2helix's own write-path scrub into the
  helix chronicle.
  **What the widened class now ALSO eats:** `-` and `_` are in the character
  class, so any contiguous kebab- or snake-cased identifier of 40+ characters
  is masked. This house's vocabulary is full of them —
  `pol_20260712_law-10-the-nuisance-baseline-a-gate-must` masks to
  `<BASE64-BLOB:len=53>`. Those were legible before this round. Accepted as
  over-withholding; `directive.md` tells Grok the token may be an identifier
  rather than an encoded payload.
- **Token-shaped pre-pass, UNANCHORED, before the redactor ever runs** —
  applied to previews AND to metadata. Two rules, both producing
  `<TOKEN-SHAPED:len=N>`:
  1. a known credential prefix (`sk-`, `sk_live_`, `ghp_`, `github_pat_`,
     `glpat-`, `xai-`, `xoxb-`, `AKIA`, `AIza`, `ya29.`, `npm_`, `hf_`, … —
     the full list is `sanitizer.TOKEN_PREFIXES`) followed by 16+ characters of
     `[A-Za-z0-9_-]`, **anywhere**, including glued, dotted and slashed
     contexts;
  2. a bare run of 32+ `[A-Za-z0-9]` carrying **at least one digit AND at least
     one letter**. That is what "high-entropy" means here — a stated mechanical
     rule, not Shannon entropy. A long repetitive run (`qqqq…`) is deliberately
     NOT masked, so a reader can still see where a long field was cut.

  **Why it exists — an UPSTREAM gap the watchman cannot fix.** t2helix's
  `lib/secrets.js` anchors on `\b` (`\bsk-[A-Za-z0-9_-]{16,}`,
  `\bghp_[A-Za-z0-9]{20,}\b`, `\bAKIA[0-9A-Z]{16}\b`), so a WORD character
  (letter, digit, or `_`) on the anchored side defeats the match. Measured
  against the live table, not assumed: `OPENAI_sk-…`, `MYKEYsk-…`, `123sk-…`,
  `ghp_…_backup` and `AKIA…TAIL` all pass `scrub()` **unchanged**.
  Punctuation-glued forms (`/sk-…`, `token=sk-…`, `file.sk-….bak`) are caught
  upstream correctly and are not the gap. **THIS PRE-PASS PROTECTS THE
  WATCHMAN'S EGRESS ONLY — the upstream gap remains open and is flagged for the
  Grok helm: t2helix's own write path still writes those credentials into the
  helix chronicle.**

  **Label order, so a reader knows which stage caught what:** the pre-pass runs
  first and claims what it recognizes (a pure-alnum base64 run therefore
  renders as `<TOKEN-SHAPED:len=N>`, not `<BASE64-BLOB:…>`); the base64 mask
  runs after redaction and catches runs carrying `+ / - _` that the bare-alnum
  rule splits on. Two labels, one guarantee: neither form travels in the clear.
  **What rule 1 also eats:** the prefixes are UNANCHORED by design, so `sk-`
  fires inside ordinary words — `task-`, `risk-`, `disk-`, `desk-` followed by
  16+ `[A-Za-z0-9_-]` all mask. `task-management-board-20260803` becomes
  `ta<TOKEN-SHAPED:len=28>`. Grok will see this constantly; the directive tells
  it the token may be a long identifier rather than a credential.
  **Consequence for receipts:** a full-length sha256 or git SHA is masked in
  BOTH previews and metadata now (rule 2 eats it), so neither surface will give
  you a digest. Read it from the source artifact. The heartbeat surface is
  unaffected in practice because it reports SHORT commits.

- **The content gate reads the RAW window as well as the masked one.** Both
  masks above run UPSTREAM of `content_flagged`, so a sensitive term living
  inside a run they claim would be gone before the gate could see it —
  `domain-biomedical-assay-protocol-reference-2026` is one 47-char run.
  Nothing would LEAK (the run is masked), but the item would silently lose its
  `content-flagged` state, and that state is what sets
  `flagged_for_richer_review`. Fail-closed on disclosure, fail-open on
  signalling. The gate therefore runs against the pre-mask window too, which is
  strictly tightening: it can only add flags.
- Every item carries its `preview_state`, its `digest_id`, its `surface`, and
  `body_bytes`; the envelope counts `items_previewed` vs `items_metadata_only`
  per reason and `items_by_surface`, so a partial view can never read as a full
  one.

## The instrument reports itself

Fail-closed is not enough on its own: a watchman whose redactor cannot run
withholds every body and looks exactly like a quiet night.

- **Standing-blind detector.** N consecutive sweeps (default 3,
  `WATCHMAN_BLIND_STREAK_N`) in which *every* preview attempt failed
  sanitization raise an `urgent` spool line naming the watchman's own
  blindness. A fully-blind sweep does **not** wake Grok — there is nothing
  sanitized to classify, so spending a call on it would be theatre.
- **Node resolution.** launchd does not inherit a login shell's PATH and node
  lives under `/opt/homebrew`. Chain: `WATCHMAN_NODE_BIN` →
  `/opt/homebrew/bin/node` → `/usr/local/bin/node` → `node`. The DRAFT plist
  also sets `PATH` and `WATCHMAN_NODE_BIN` explicitly.
- **Sanitizer failures are re-examined.** An item whose preview failed does not
  advance its high-water mark, so it comes back once the redactor is repaired.
  Previously a transient breakage blinded the watchman to those items forever.
  (Filesystem surfaces only — the comms high-water is server-side
  `mark_read_as`, so a comms message read during a blind sweep is already
  consumed. See RESIDUAL RISK #4; not fixed here.)
- **Reply coverage.** The directive commands that every digest item appear
  exactly once; the mechanical tier *verifies* it. The envelope carries
  `reply_coverage: {expected, answered, omitted, extra, duplicated,
  reply_items, judgments}` — enough for a reader to check the arithmetic
  (`expected == answered + omitted`, `reply_items == judgments + extra`)
  without trusting the label. An omitted item raises its own `attend` line
  (`grok-omitted`, flagged for richer review), an invented one is recorded as
  `grok-extra` with a standing skepticism note, and either demotes the reply to
  `parsed-partial`. **A duplicated item demotes it to `parsed-with-anomalies`**
  — the label used to stay at `parsed` while `duplicated_refs` was non-empty
  and an attend line fired, which is label and arithmetic disagreeing.
- **Coverage keys on `digest_id` ONLY, and so does the render.** `digest_id` is
  a mechanical label the watchman mints (`item-0001`, …) that no untrusted
  input can influence, so the accounting holds even when every metadata field
  failed sanitization. The tolerant `ref` fallback is GONE from both the
  coverage check and `render_latest`: `ref` is built from a filename or a board
  message id, so matching on it let a reply claim an expected slot by echoing a
  string the item's own source controls — and the render was the surface a
  human actually reads. A reply item without a valid `digest_id` is
  `grok-extra` and can never claim a slot; an omitted item renders as
  **UNJUDGED**, never with someone else's judgment borrowed onto it.
- **The reply's SHAPE is enforced before any of it is believed.** A parsed
  object is accepted only when its `sweep_id` EQUALS the digest's, `items` is a
  list, and every item is an object bearing a non-empty `digest_id`. Anything
  else is `grok-reply-unparseable` and is quarantined intact. A reply that does
  not name the sweep it answers cannot be reconciled against it, and one scored
  against the wrong digest is worse than none.
- **`grok_invoked` means a process ran.** `grok_process_state` is one of
  `spawned` / `spawn-failed` / `not-attempted`. A missing binary used to be
  stamped as an invocation, so a reader auditing spend from the spool alone
  would have miscounted.
- **Counts come from ONE source: the final items list.** `items_by_surface` was
  read back out of each scanner's self-reported count — a second source that
  can disagree with the first, so a surface failing mid-iteration could report
  a count for items that never reached the digest and `items_by_surface` would
  stop summing to `items_seen` with nothing saying why. Each item now carries
  its `surface`, and both numbers are counted off that.
- **AT-LEAST-ONCE: the high-water mark is saved only AFTER the spool write
  succeeds.** `save_state` used to run before the mind phase, so anything that
  raised in it consumed the deltas and the next sweep went quiet — the work was
  gone and nothing said so. A sweep that raises after collection now records
  `sweep_error`, raises its own `attend` line, spools an honest partial
  envelope, and leaves the high-water exactly where it was so the deltas
  re-fire. **Scope, stated exactly: this covers the FILESYSTEM surfaces and the
  counter surfaces, which re-derive from disk. It does NOT cover comms** —
  `mark_read_as` is applied server-side during collection, so those messages
  are already consumed. Named in RESIDUAL RISK, not papered over.
- **Single-instance lock.** launchd fires this script on both a `WatchPaths`
  trigger and a slow `StartInterval`, so two sweeps can overlap on a busy
  queue — and two live sweeps race the same high-water file and can each
  half-advance it, which is a silent-data-loss shape rather than a performance
  one. An `flock` on `<root>/watchman/sweep.lock` guards it: an overlapping
  invocation writes one line (`sweep already live, skipping`), touches nothing
  else, and exits 0 so a correct skip does not read to launchd as a failure.

## `--dry-run` mutates NOTHING

No high-water state write, no `mark_read_as`, no append to the production spool
or log. Dry output goes to `dry-run-spool.jsonl`, `latest.dry-run.md`,
`watchman.dry-run.log`, and `<sweep>.dry-run-prompt.txt`. **A dry run can never
blind a subsequent live sweep** — previously it consumed filesystem deltas, so
the "first live sweep is a baptism" expectation was silently defeated by the
demo this README itself invites.

## RESIDUAL RISK — what this build does NOT close

Written to be read by whoever inherits the post, and kept honest on purpose: a
defence list that only names its wins is the fail-open shape wearing a
security costume. These four are open, known, and accepted for now.

**1. The UPSTREAM t2helix boundary-anchoring gap — OPEN, flagged for the Grok
helm.** `lib/secrets.js` anchors on `\b`, so a credential glued to a WORD
character (letter, digit, `_`) on the anchored side is missed. Measured, not
assumed: `OPENAI_sk-…`, `MYKEYsk-…`, `123sk-…`, `ghp_…_backup`, `AKIA…TAIL`
all pass `scrub()` unchanged. The watchman's token pre-pass closes the
watchman's own egress and NOTHING ELSE — **t2helix's write path still writes
those credentials into the helix chronicle, and every other caller of `scrub()`
inherits the same gap.** Fixing it means widening the upstream patterns
(dropping the leading `\b`, or replacing it with a lookbehind that excludes only
the token's own alphabet), which is the helm's call and its blast radius, not
the watchman's. Same for base64: `scrub()` decodes nothing.

**2. Single-script all-foreign lookalike words — reachable only through the
map.** The mixed-script rule fails closed by construction for the actual attack
shape (an ASCII word with a foreign codepoint spliced in). It does NOT see a
word written ENTIRELY in one non-Latin script that renders like an ASCII term —
an all-Cyrillic `рrоtесtеd` with every letter substituted. That is single-script,
so only `sanitizer.CONFUSABLES` can catch it, and a map only knows the
confusables someone remembered to add. Widening this means a real
confusables table (UTS #39 / `confusable_homoglyphs`), which adds a dependency
this dependency-free script has so far avoided. **Unclosed.**

**3. Base64 variants beyond the two alphabets.** `<BASE64-BLOB:…>` covers
standard (`+` `/`) and URL-safe (`-` `_`) runs of 40+, including mixtures.
**Base32, base85/ascii85, hex above the 32-char bare-token rule's shape,
percent-encoding, and custom alphabets are not covered.** A credential wrapped
in any of those, that also carries no known prefix and no digit-plus-letter
32+ alnum run, previews in the clear. **Unclosed.**

**4. Comms is not covered by at-least-once.** `mark_read_as=watchman` is applied
server-side during collection, so a comms message read during a sweep that then
fails — or during a sweep whose sanitizer was broken — is already consumed and
will not re-surface. The filesystem surfaces hold their high-water back and
re-fire; comms cannot. Fixing it means a client-side comms high-water or a
server-side unread-restore, neither of which exists.

### The accepted posture, said plainly

These queues are **house-internal**: `grok_bridge`, `openai_bridge`,
`antigravity_connector`, `daemons/halts`, `handoffs` and the legacy comms board
are all written by seats and daemons Anthony runs. The threat model here is
accident and mislabelling — a credential pasted into the wrong field, a biomed
body filed under `domain=general` — far more than a deliberate adversary
crafting a homoglyph bypass. Against that model the posture holds: **the eyes
policy is fail-closed in every direction**, over-withholding is deliberate, and
**Grok's mandatory flag-for-richer-review is the second net** under anything the
mechanical tier withheld or mislabelled.

**Revisit every one of the four the moment any watched queue admits an
untrusted external writer.** At that point the threat model changes from
accident to adversary, the residuals above stop being acceptable, and this
section becomes a work list rather than a disclosure.

## The phone rule

**The watchman never texts Anthony.** His phone is an HQ-and-him channel only.
The escalation ceiling is a severity of `urgent` in the spool — the HQ seat
reads the spool (`latest.md` renders for the next booting seat) and relays
what deserves his attention. The spool is helix-side working memory, not the
Stack record; durable findings are HQ's to land, with receipts.

## Deploy steps — HELD FOR ANTHONY'S GATE

Nothing below happens without his explicit go (SOP #3):

1. Merge `draft/watchman` into `~/sovereign-bridge` main.
2. Rename `com.templetwo.comms-dispatcher.plist.DRAFT` → `.plist`, copy to
   `~/Library/LaunchAgents/`, `launchctl bootout` the old dispatcher job,
   `launchctl bootstrap` the new one (same label — addresses outlast
   occupants).
3. First sweep seeds `~/.sovereign/watchman/state.json` high-water; expect one
   large baseline envelope, then quiet.

Demo without any of that (and without a Grok call):

```
~/sovereign-stack/venv/bin/python3 watchman/watchman_sweep.py --dry-run
```

Dry-run performs the full mechanical sweep read-only, never invokes cosmic, and
saves the prompt that WOULD have gone to Grok. It is safe to run against the
real root before the plist is ever loaded: it consumes nothing, so the baseline
sweep still sees the full backlog.

## Retirement note for comms_dispatcher.py

`comms_dispatcher.py` (the predecessor at the repo root) stays untouched until
Anthony holds the retirement ceremony. When he does:

- **What stops:** the 30-second polling loop; keyword-matching messages into
  an action queue (`research`/`write_code`/`run_benchmark`); replying into the
  comms channel; the always-on process.
- **What the watchman inherits:** the comms-board watch itself — channel
  `general` stays swept (read + `mark_read_as=watchman`), so
  `daemon.uncertainty`'s whispers finally land somewhere a seat will read
  them, in the spool with everything else.
- **What nobody inherits:** the dispatcher's enactment lane. The watchman
  proposes; it does not queue actions, and it does not act.
