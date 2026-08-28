# Changelog — Sovereign Bridge

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
