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

- **Metadata always travels** — queue, filename, tool, commit_target, declared
  risk_level, timestamp, size, age.
- **Preview** = first 600 chars of the body, run through the t2helix redaction
  patterns (`~/t2helix/lib/secrets.js` via `sanitize_preview.js` — the same
  single source of truth as the helix write path; the table is loaded, never
  copied, so the eyes can never drift from the helix).
- **Fail-closed, all three directions:**
  1. Denylist → metadata-only, no preview ever: protected/consent-shaped items
     (tool `comms_acknowledge`, any filename or declared domain containing
     `protected`/`consent` — a hard-coded floor no config can switch off),
     plus `eyes_policy.json` (seeded: the antigravity queue; biomedical and
     security-audit domains).
  2. Sanitizer subprocess error, 2s timeout, or non-zero exit → metadata-only,
     `preview_state='metadata-only:sanitizer-failed'`, recorded honestly.
  3. Unknown/unparseable file → metadata-only, `preview_state='metadata-only:unparseable'`.
- Every item carries its `preview_state`; the envelope counts
  `items_previewed` vs `items_metadata_only` per reason, so a partial view can
  never read as a full one.

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

Dry-run performs the full mechanical sweep read-only (comms read omits
`mark_read_as`, so nothing is mutated), never invokes cosmic, and saves the
prompt that WOULD have gone to Grok next to the spool.

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
