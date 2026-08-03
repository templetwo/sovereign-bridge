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
  5. Eyes policy **strictly validated**: every listed key must be a list of
     strings. A file that exists but does not validate closes the eyes
     completely (`floor-fallback`, metadata-only for everything) and raises an
     attend line about the file. A missing file falls back to compiled-in seeds
     identical to the shipped ones (`builtin-fallback`) and still says so.
- **Homoglyph folding.** All denylist and content matching runs on NFKC-
  normalized, casefolded text with a confusables map applied to both needle and
  haystack. One Cyrillic codepoint (`prоtected`) used to walk past a floor
  described as un-turn-off-able. The folded form is used for MATCHING ONLY and
  is never persisted.
- **base64 blobs.** Runs of 40+ base64-alphabet characters in a preview are
  replaced with `<BASE64-BLOB:len=N>` before truncation. This is a
  **watchman-side mitigation of an UPSTREAM t2helix limit**: no pattern in
  `lib/secrets.js` decodes base64, so a base64-wrapped credential scrubs clean.
  The watchman's exposure differs in kind from the helix's — the helix persists
  locally, the watchman ships the preview off-machine to xAI — which is why the
  mitigation lives here. **The upstream gap is unclosed and is flagged for the
  Grok helm**: a base64-wrapped secret still passes t2helix's own write-path
  scrub into the helix chronicle. Consequence to expect: a sha256 receipt in a
  body renders as `<BASE64-BLOB:len=64>`. That is over-withholding by design,
  but receipts are load-bearing in this house, so read the item's metadata (not
  the preview) when you need the digest.
- Every item carries its `preview_state`, its `digest_id`, and `body_bytes`;
  the envelope counts `items_previewed` vs `items_metadata_only` per reason and
  `items_by_surface`, so a partial view can never read as a full one.

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
  consumed. Noted as a residual, not fixed here.)
- **Reply coverage.** The directive commands that every digest item appear
  exactly once; now the mechanical tier *verifies* it. The envelope carries
  `reply_coverage: {expected, answered, omitted, extra}`; an omitted item
  raises its own `attend` line (`grok-omitted`, flagged for richer review), an
  invented one is recorded as `grok-extra` with a standing skepticism note, and
  either demotes the reply to `parsed-partial`. Coverage keys on `digest_id`, a
  mechanical label no untrusted input can influence, so the accounting holds
  even when every metadata field failed sanitization.
- **`grok_invoked` means a process ran.** `grok_process_state` is one of
  `spawned` / `spawn-failed` / `not-attempted`. A missing binary used to be
  stamped as an invocation, so a reader auditing spend from the spool alone
  would have miscounted.

## `--dry-run` mutates NOTHING

No high-water state write, no `mark_read_as`, no append to the production spool
or log. Dry output goes to `dry-run-spool.jsonl`, `latest.dry-run.md`,
`watchman.dry-run.log`, and `<sweep>.dry-run-prompt.txt`. **A dry run can never
blind a subsequent live sweep** — previously it consumed filesystem deltas, so
the "first live sweep is a baptism" expectation was silently defeated by the
demo this README itself invites.

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
