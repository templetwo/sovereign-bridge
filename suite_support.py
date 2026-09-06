"""Shared, non-fixture support for both pytest suites.

Not a conftest and not a test module, deliberately: `watchman/tests/` has its
own `conftest.py`, so `from conftest import X` inside a test module resolves to
whichever conftest pytest imported most recently and dies at collection. A
plain module has one name and one meaning from anywhere on sys.path.

It holds the PINNED SEAT SURFACE and the measurement that checks it.

⚠ WHY A PINNED SURFACE EXISTS IN THE TEST LAYER AFTER THE PRODUCTION COPIES
WERE DELETED. `seat_identity` no longer remembers what the stack publishes — it
asks, once per cache window (HQ decision D2, 2026-09-06). That is right for the
bridge and useless for a test: the answer would then depend on which stack tree
happens to be importable on the machine running pytest, and on this machine
that is the LIVE checkout, a tree with no `RETIRED_TOOLS` at all. A gate test
would be green here and red there, or green today and red after somebody merges
the stack — the exact failure `tests/test_heartbeat_signals.py`'s own docstring
warns about. So every MECHANICS test decides against the fixed surface below.

THE COPY IS NOT TRUSTED — IT IS CHECKED.
`tests/test_seat_identity.py::test_the_pinned_surface_is_the_stack_release`
derives the real published/retired sets from the stack release source and
asserts these are they, skipping loudly when that source is not on disk. A
drift here is therefore a RED TEST, never a quiet change of policy — which is
the whole difference between this copy and the two production constants it
replaced.

Source: sovereign-stack release/2026-09-06. `list_tools` (server.py:2427) is
every registered tool minus `RETIRED_TOOLS`: 100 registered, 48 retired,
52 published.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import seat_identity

PINNED_PUBLISHED = frozenset(
    {
        "archive_exchange", "arrive", "arrive_lineage", "check_mistakes",
        "close_session", "comms_channels", "comms_get_acks", "comms_recall",
        "compass_check", "connectivity_status", "context_retrieve",
        "current_policies", "get_compaction_context", "get_compaction_stats",
        "get_growth_summary", "get_inheritable_context", "get_my_patterns",
        "get_open_threads", "get_pending_experiments",
        "get_unresolved_uncertainties", "handoff", "handoff_acted_on_records",
        "heartbeat", "inspect_claim", "my_toolkit", "nape_ack", "nape_summary",
        "post_fix_verify", "prior_for_turn", "recall_insights",
        "recall_reflections", "record_catch", "record_insight",
        "record_learning", "record_open_thread", "reflexive_surface",
        "resolve_thread_by_id", "season_review", "self_model", "set_policy",
        "signal_ack", "signals_summary", "spiral_inherit", "spiral_reflect",
        "spiral_status", "start_here", "supersede_insight", "the_ground",
        "thread_get_touches", "thread_touch", "triage_threads",
        "where_did_i_leave_off",
    }
)

PINNED_RETIRED = frozenset(
    {
        "agent_reflect", "arrive_delta", "ask_scribe", "comms_acknowledge",
        "comms_unread_bodies", "complete_experiment", "decline_protected_record",
        "derive", "end_session_review", "govern", "guardian_alerts",
        "guardian_audit", "guardian_baseline", "guardian_mcp_audit",
        "guardian_quarantine", "guardian_report", "guardian_scan",
        "guardian_status", "handoff_acted_on", "handoff_archaeology",
        "link_threads", "list_exchanges", "list_protected_thresholds",
        "mark_uncertainty", "metabolize", "nape_honks",
        "nape_honks_with_history", "nape_observe", "open_protected_record",
        "prior_alignment_summary", "propose_experiment", "recall_exchange",
        "record_breakthrough", "record_collaborative_insight",
        "record_prior_alignment", "reflection_ack", "resolve_thread",
        "resolve_uncertainty", "retire_hypothesis", "route", "scan_thresholds",
        "session_handoff", "stack_write_check", "store_compaction_summary",
        "synthesize_now", "watch_cancel", "watch_resample", "watch_status",
    }
)

PINNED_SURFACE = seat_identity.Surface(
    PINNED_PUBLISHED, PINNED_RETIRED, "test pin: sovereign-stack release/2026-09-06"
)

# Preference order: the release worktree this bridge release ships beside, then
# the live checkout. Named as a tuple so a skip message can say where it looked.
STACK_TREES = (
    Path.home() / ".cache" / "wt-release-stack" / "src",
    Path.home() / "sovereign-stack" / "src",
)


def release_stack_surface():
    """(published, retired, tree) measured from the stack source on disk.

    ⚠ IN A SUBPROCESS, AND THAT IS LOAD-BEARING. `bridge` inserts
    ~/sovereign-stack/src at import, so this test process ALREADY has
    `sovereign_stack` bound to the LIVE tree. Importing the release tree's
    server here would either silently reuse the live package — measuring the
    wrong tree while looking like it measured the right one — or half-import a
    second copy of a package that is already in sys.modules. A subprocess with
    its own PYTHONPATH cannot make that mistake, and it reports back the file
    it actually loaded so the caller can check rather than assume.

    Skips (loudly, naming the paths it tried) rather than failing when no stack
    source is on disk: a bridge checkout without its companion repo is a
    legitimate state, and turning that into a red suite teaches people to
    ignore a red suite.
    """
    tree = next(
        (p for p in STACK_TREES if (p / "sovereign_stack" / "server.py").exists()), None
    )
    if tree is None:
        pytest.skip(
            "no sovereign-stack source on disk (looked in "
            + ", ".join(str(p) for p in STACK_TREES)
            + "); the published surface cannot be measured, so this is SKIPPED "
            "rather than assumed"
        )
    code = (
        "import json, sovereign_stack, sovereign_stack.server as s\n"
        "retired = sorted(s.RETIRED_TOOLS)\n"
        "names = [t.name for t in s._registered_tools()]\n"
        "print(json.dumps({'loaded': sovereign_stack.__file__, 'retired': retired,\n"
        "  'published': sorted(n for n in names if n not in set(retired))}))"
    )
    env = dict(os.environ, PYTHONPATH=str(tree), PYTHONDONTWRITEBYTECODE="1")
    out = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, env=env, timeout=180
    )
    if out.returncode != 0:
        pytest.skip(f"the stack source at {tree} did not import: {out.stderr[-400:]}")
    data = json.loads(out.stdout.strip().splitlines()[-1])
    assert str(tree) in data["loaded"], (
        "the subprocess measured a DIFFERENT stack tree than the one asked for: "
        f"{data['loaded']}"
    )
    return frozenset(data["published"]), frozenset(data["retired"]), tree


def stack_release_tree() -> Path | None:
    """The stack RELEASE worktree's `src`, or None. Never the live checkout.

    D3 and D8 need the release candidate specifically — "does the bridge hold
    against the stack it ships beside" is not a question the live tree can
    answer — so this is deliberately narrower than STACK_TREES.
    """
    tree = STACK_TREES[0]
    return tree if (tree / "sovereign_stack" / "signal_ledger.py").exists() else None
