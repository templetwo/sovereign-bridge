"""The outside-seat grant map must not offer a tool the stack has retired.

⚠ THE FAILURE THIS FILE EXISTS TO MAKE IMPOSSIBLE. On 2026-09-06 the stack ran
its retirement census and `ask_scribe` and `reflection_ack` stopped being
served. `session_tokens.TOOL_SCOPES` still granted both, so an outside seat
holding a read grant saw `ask_scribe` on `GET /api/tools` and got a refusal
from the stack every time it called it — and a seat holding a write grant saw
`reflection_ack` the same way. Nothing anywhere said the grant was dead. That
is the read-side of a fail-open: the menu reported capability the surface no
longer had, and the only signal was a confusing refusal one layer up.

The drift is silent BY CONSTRUCTION — the two tables live in two repos and
nothing joined them — so this file joins them two ways:

  * against the PINNED retired set (`suite_support.PINNED_RETIRED`), which is
    in-repo, deterministic, and itself checked against the stack release by
    `tests/test_seat_identity.py::test_the_pinned_surface_is_the_stack_release`;
  * against the stack source ON DISK, measured in a subprocess, which is what
    catches the NEXT census. It skips loudly when no stack tree is present,
    because a bridge checkout without its companion repo is a legitimate state.

Both are kept. The pinned one can never be skipped, so the guarantee never
evaporates on a machine with no stack checkout; the measured one can never go
stale, so a future retirement cannot pass unnoticed while the pin agrees with
itself.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import session_tokens as st  # noqa: E402
from suite_support import (  # noqa: E402
    PINNED_PUBLISHED,
    PINNED_RETIRED,
    PUBLISHED_SINCE_PIN,
    STACK_TREES,
    release_stack_surface,
)


# ── The two names the 2026-09-06 census killed ──────────────────────────────


def test_ask_scribe_is_no_longer_granted_to_any_scope():
    """Retired on the stack 2026-09-06 ("Spend-bearing; not folded into a free
    surface"). A read grant must not enumerate it."""
    assert "ask_scribe" not in st.TOOL_SCOPES
    assert not st.tool_allowed("ask_scribe", ["read", "write", "session"])


def test_reflection_ack_is_no_longer_granted_to_any_scope():
    """Retired on the stack 2026-09-06 — the reflector is gone in all three
    generations, so there is nothing left to acknowledge."""
    assert "reflection_ack" not in st.TOOL_SCOPES
    assert not st.tool_allowed("reflection_ack", ["read", "write", "session"])


# ── The name the census created a hole for ──────────────────────────────────


def test_signals_summary_is_readable_by_a_read_grant():
    """The heartbeat carries `unacked_signals`; without this a read grant could
    see that a count existed and had no tool to read what it counted."""
    assert st.TOOL_SCOPES.get("signals_summary") == "read"
    assert st.tool_allowed("signals_summary", ["read"])


# ── The name Anthony granted on 2026-10-10 ──────────────────────────────────


def test_descend_is_readable_by_a_read_grant():
    """Anthony, 2026-10-10: `descend` goes to the read scope (and BASE on the
    claude.ai connector, stack clients/claude_bridge/tiers.py). Red before the
    grant: TOOL_SCOPES had no entry, so default-deny made it master-only."""
    assert st.TOOL_SCOPES.get("descend") == "read"
    assert st.tool_allowed("descend", ["read"])
    # read only: a write-only or session-only grant does not reach it
    assert not st.tool_allowed("descend", ["write"])
    assert not st.tool_allowed("descend", ["session"])


def test_the_read_scope_is_exactly_these_names():
    """The read grant asserted BY NAME, not by count: a count survives swapping
    one tool for another. Any change to the read scope must edit this set, which
    puts the widening (or narrowing) on the record in the same diff."""
    read = {t for t, sc in st.TOOL_SCOPES.items() if sc == "read"}
    assert read == {
        "arrive_lineage",
        "start_here",
        "my_toolkit",
        "recall_insights",
        "recall_reflections",
        "get_open_threads",
        "current_policies",
        "inspect_claim",
        "season_review",
        "signals_summary",
        "descend",
        "compass_check",
        "check_mistakes",
        "spiral_status",
    }


def test_signal_ack_is_granted_to_no_outside_scope():
    """THE DELIBERATE ASYMMETRY, ASSERTED SO IT CANNOT BE "COMPLETED" BY
    ACCIDENT. Reading the signal queue is granted; closing a signal is not.
    Whether an outside (arrival-granted, non-seated) caller may write to the
    ledger is a seat-permission question and therefore Anthony's. The LOCAL
    seat path admits signal_ack under HQ decision D1; that is a different
    actor — kernel-verified — and says nothing about a bearer token.

    A future seat that adds it must delete this test, which is the point: the
    omission becomes a decision on the record instead of an oversight.
    """
    assert "signal_ack" not in st.TOOL_SCOPES
    assert not st.tool_allowed("signal_ack", ["read", "write", "session"])


# ── The guards ──────────────────────────────────────────────────────────────


def test_no_granted_tool_is_in_the_pinned_retired_set():
    """Deterministic half. Scoped to TOOL_SCOPES only, NOT to NEVER_TOOLS:
    three NEVER_TOOLS members (the protected-drawer family) are legitimately
    retired now, and folding them in would manufacture a red for a table whose
    whole job is to name tools nobody may reach."""
    offenders = sorted(set(st.TOOL_SCOPES) & PINNED_RETIRED)
    assert offenders == [], (
        "TOOL_SCOPES grants tools the stack has retired: "
        f"{offenders}. A scoped seat would see them enumerated and be refused "
        "on every call. Remove the grant, or un-retire the tool on the stack."
    )


def test_every_granted_tool_is_actually_published():
    """The other half of the same honesty: a grant for a name the stack never
    publishes is equally dead, and retirement is only one way to get there
    (a rename does it too)."""
    unpublished = sorted(set(st.TOOL_SCOPES) - (PINNED_PUBLISHED | PUBLISHED_SINCE_PIN))
    assert unpublished == [], (
        f"TOOL_SCOPES grants tools the stack does not publish: {unpublished}"
    )


def test_published_since_pin_is_a_real_exception_not_a_hole():
    """PUBLISHED_SINCE_PIN widens the guard above, so it is checked itself.

    Deterministic half: every member is NEW (not already pinned published, not
    pinned retired). A name that drifted into the exception set while also being
    retired would otherwise launder a dead grant past the guard.
    """
    assert PUBLISHED_SINCE_PIN, "empty exception set: delete it and this test"
    assert PUBLISHED_SINCE_PIN.isdisjoint(PINNED_PUBLISHED)
    assert PUBLISHED_SINCE_PIN.isdisjoint(PINNED_RETIRED)


def test_published_since_pin_is_published_by_the_live_stack_source():
    """Measured half: each declared exception is actually published by the
    stack MAIN source on disk (the live checkout, STACK_TREES[1]) and not
    retired there. Skips loudly when no stack source is present. Measured in a
    subprocess for the reason release_stack_surface() documents.
    """
    published, retired, tree = release_stack_surface(trees=STACK_TREES[1:])
    missing = sorted(PUBLISHED_SINCE_PIN - published)
    assert missing == [], f"measured against {tree}: not published: {missing}"
    assert PUBLISHED_SINCE_PIN.isdisjoint(retired), f"{tree} retired a declared exception"


def test_no_granted_tool_is_retired_by_the_stack_source_on_disk():
    """Measured half — the one that catches the NEXT census.

    `release_stack_surface()` imports the stack in a SUBPROCESS with its own
    PYTHONPATH (this process already has `sovereign_stack` bound to whichever
    tree `bridge` inserted at import, so an in-process import would measure the
    wrong tree while looking like it measured the right one) and skips loudly,
    naming the paths it tried, when no stack source is on disk.

    ⚠ THIS TEST READS A TREE OUTSIDE THIS REPO ON PURPOSE. It will go red if
    the stack retires another tool that TOOL_SCOPES still grants. That is not
    flakiness — it is the join the two tables never had, and a red here is the
    signal to update the grant map.
    """
    _published, retired, tree = release_stack_surface()
    offenders = sorted(set(st.TOOL_SCOPES) & retired)
    assert offenders == [], (
        f"measured against {tree}: TOOL_SCOPES grants retired tools {offenders}"
    )


def test_the_measured_retired_set_agrees_with_the_pin():
    """THE FALSIFIER for the test above. Without it, a `release_stack_surface`
    that returned an empty retired set would make the guard vacuously green —
    it would pass against a stack that retired everything.
    """
    _published, retired, tree = release_stack_surface()
    assert "ask_scribe" in retired, f"{tree} does not report ask_scribe retired"
    assert "reflection_ack" in retired, f"{tree} does not report reflection_ack retired"
    assert retired == PINNED_RETIRED, (
        f"the retired set measured at {tree} has drifted from the pin: "
        f"missing {sorted(retired - PINNED_RETIRED)}, "
        f"stale {sorted(PINNED_RETIRED - retired)}"
    )


def test_the_guard_can_fail():
    """Experimental law #2 applied to this file: a gate must be demonstrably
    able to fail. Runs the same comparison over a SYNTHETIC table holding one
    live name and one retired one, and proves it names the retired one — so a
    green run above is evidence about TOOL_SCOPES, not about an assertion that
    could never fire.

    Synthetic rather than `dict(st.TOOL_SCOPES, ask_scribe=...)` on purpose:
    seeded from the real table, this falsifier's own result would change with
    the table under test, and a falsifier that moves with its subject proves
    nothing.
    """
    synthetic = {"recall_insights": "read", "ask_scribe": "read"}
    assert sorted(set(synthetic) & PINNED_RETIRED) == ["ask_scribe"]


@pytest.mark.parametrize("scope", sorted(st.GRANTABLE_SCOPES))
def test_each_grantable_scope_still_reaches_something(scope):
    """A retirement that emptied a scope would be a silent capability loss;
    this makes it a red test instead."""
    reachable = sorted(t for t, s in st.TOOL_SCOPES.items() if s == scope)
    assert reachable, f"scope {scope!r} now grants nothing at all"
