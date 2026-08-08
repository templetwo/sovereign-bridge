"""Mind-rest spend breaker (closure-round residual R4, fixed by HQ pre-gate).

The loop it breaks: an exception AFTER invoke_cosmic returns leaves the xAI
spend made but the high-water unsaved, so the same deltas re-fire and re-spend
every sweep — the scribe-greeting spend loop in a new costume. After N
consecutive spawned-but-unsaved failures the mind rests: mechanical digests
keep landing in the spool, Grok is not invoked, an urgent instrument line says
so, and --reset-mind re-arms after repair.
"""

import fcntl
import os

import watchman_sweep
from conftest import (
    good_reply_for,
    invocations,
    make_fake_cosmic,
    write_proposal,
)


def seed_streak(root, n):
    state = watchman_sweep.load_state(root)
    state["mind_failure_streak"] = n
    watchman_sweep.save_state(root, state)


def streak(root):
    return int(watchman_sweep.load_state(root).get("mind_failure_streak", 0) or 0)


def test_a_resting_mind_never_spawns(sov_root, clean_fetchers, tmp_path):
    seed_streak(sov_root, watchman_sweep.mind_rest_threshold())
    write_proposal(sov_root, "grok_bridge", "rest1.json")
    ref = "grok_bridge/pending_writes/rest1.json"
    fake, log = make_fake_cosmic(tmp_path, good_reply_for([ref]))
    env = watchman_sweep.run_sweep(sov_root, cosmic_bin=fake, **clean_fetchers)
    assert env["grok_invoked"] is False
    assert env["grok_process_state"] == "not-attempted"
    assert env["grok_reply_state"] == "not-invoked-mind-resting"
    assert invocations(log) == 0, "a resting mind must never spend"
    assert env["items"], "the mechanical digest still delivers"
    spool = (sov_root / "watchman" / "spool.jsonl").read_text(encoding="utf-8")
    assert "instrument:mind" in spool, "resting must be announced urgently"


def test_resting_still_consumes_deltas_mechanically(sov_root, clean_fetchers, tmp_path):
    seed_streak(sov_root, watchman_sweep.mind_rest_threshold())
    write_proposal(sov_root, "grok_bridge", "rest2.json")
    ref = "grok_bridge/pending_writes/rest2.json"
    fake, log = make_fake_cosmic(tmp_path, good_reply_for([ref]))
    watchman_sweep.run_sweep(sov_root, cosmic_bin=fake, **clean_fetchers)
    env2 = watchman_sweep.run_sweep(sov_root, cosmic_bin=fake, **clean_fetchers)
    refs2 = [] if env2 is None else [i["ref"] for i in env2["items"]]
    assert ref not in refs2, "a rested item lands in the spool once, not forever"


def test_spawned_failure_increments_streak_and_holds_highwater(
    sov_root, clean_fetchers, tmp_path, monkeypatch
):
    write_proposal(sov_root, "grok_bridge", "boom.json")
    ref = "grok_bridge/pending_writes/boom.json"
    fake, log = make_fake_cosmic(tmp_path, good_reply_for([ref]))

    with monkeypatch.context() as m:

        def explode(items, parsed):
            raise RuntimeError("synthetic post-spend crash")

        m.setattr(watchman_sweep, "compute_reply_coverage", explode)
        env = watchman_sweep.run_sweep(sov_root, cosmic_bin=fake, **clean_fetchers)

    assert env["grok_process_state"] == "spawned"
    assert env["sweep_error"]
    assert streak(sov_root) == 1, "a spawned-but-unsaved failure must be counted"
    # High-water was NOT advanced: the unpatched sweep re-fires the same file
    # (at-least-once), and this time the spawn completes and resets the streak.
    env2 = watchman_sweep.run_sweep(sov_root, cosmic_bin=fake, **clean_fetchers)
    assert env2 is not None and ref in [i["ref"] for i in env2["items"]]
    assert env2["grok_process_state"] == "spawned"
    assert streak(sov_root) == 0, "a completed spawn proves the mind path again"


def test_spawn_failed_does_not_increment(sov_root, clean_fetchers):
    write_proposal(sov_root, "grok_bridge", "nospawn.json")
    env = watchman_sweep.run_sweep(
        sov_root, cosmic_bin="/nonexistent/never-runs", **clean_fetchers
    )
    assert env["grok_process_state"] == "spawn-failed"
    assert streak(sov_root) == 0, "no spend happened, so nothing to guard"


def test_reset_mind_flag_re_arms(sov_root, clean_fetchers):
    seed_streak(sov_root, 5)
    watchman_sweep.main(["--root", str(sov_root), "--reset-mind"])
    assert streak(sov_root) == 0


def test_quarantine_write_failure_after_spawn_is_not_mislabeled_spawn_failed(
    sov_root, clean_fetchers, tmp_path, monkeypatch
):
    """COMMIT 2: in the 'grok reply unparseable' branch, a quarantine_reply
    write that raises OSError used to be caught by the SIBLING handler built
    for spawn failures (invoke_cosmic itself never running) — because both
    lived under the same try. That mislabels a sweep that genuinely invoked
    Grok and spent real xAI credit as grok_invoked=False /
    grok_process_state='spawn-failed', and it defeats the mind-rest spend
    breaker: the outer failure handler only counts the streak when
    grok_process_state == 'spawned', so a spawn that gets relabeled
    'spawn-failed' silently stops being counted — the exact loop the spend
    breaker exists to close."""
    write_proposal(sov_root, "grok_bridge", "unparseable.json")
    # A reply with no JSON object in it at all: parse_grok_reply returns
    # (None, False) -> hits the 'grok reply unparseable' branch, which is
    # where quarantine_reply is called on a genuinely-spawned process.
    fake, log = make_fake_cosmic(tmp_path, "not an envelope, no braces here")

    def boom_quarantine(*a, **k):
        raise OSError("synthetic quarantine-write failure (disk full)")

    monkeypatch.setattr(watchman_sweep, "quarantine_reply", boom_quarantine)
    env = watchman_sweep.run_sweep(sov_root, cosmic_bin=fake, **clean_fetchers)

    assert invocations(log) == 1, "the real spend happened"
    assert env["grok_invoked"] is True, (
        "a sweep that spawned and spent must always be recorded as having "
        "invoked Grok, even when the quarantine write afterward fails"
    )
    assert env["grok_process_state"] == "spawned"
    assert env["sweep_error"], "the quarantine-write failure must surface"
    assert streak(sov_root) == 1, (
        "the spend breaker must count this spawned-but-unsaved failure or "
        "the loop it exists to stop is defeated"
    )


# --------------------------------------------------------- --reset-mind CLI


def test_reset_mind_dry_run_does_not_write_state(sov_root):
    """COMMIT 3, defect A: the module docstring's --dry-run contract is
    'MUTATES NOTHING... the high-water state is not written'. --reset-mind
    performed a real read-modify-write of state.json regardless of
    --dry-run, with no guard and no argparse mutual exclusion. An operator
    rehearsing a repair with `--reset-mind --dry-run` believed nothing
    changed while the spend breaker was silently re-armed on disk."""
    seed_streak(sov_root, 5)
    watchman_sweep.main(["--root", str(sov_root), "--reset-mind", "--dry-run"])
    assert streak(sov_root) == 5, "dry-run must mutate nothing, including --reset-mind"


def test_reset_mind_live_still_writes(sov_root):
    """The dry-run guard must not swallow the real (non-dry-run) reset."""
    seed_streak(sov_root, 5)
    watchman_sweep.main(["--root", str(sov_root), "--reset-mind"])
    assert streak(sov_root) == 0


def test_reset_mind_does_not_race_a_live_sweep_and_says_so(sov_root, capsys):
    """COMMIT 3, defect B: --reset-mind did its read-modify-write of
    state.json BEFORE the sweep_lock was acquired, racing a concurrently
    running sweep's own state write (sweep_lock's own docstring names this
    exact shape: 'two live sweeps race the same high-water state file and
    can each half-advance it'). --reset-mind is a documented manual repair
    workflow, so this collision is realistic, not theoretical.

    fcntl.flock is scoped to the OPEN FILE DESCRIPTION, not the process, so
    a second independent open() in this SAME test process genuinely
    contends with the first — this reproduces 'another sweep holds the
    lock' without needing a second process."""
    seed_streak(sov_root, 5)
    lock_path = watchman_sweep.sweep_lock_path(sov_root)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT, 0o644)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        rc = watchman_sweep.main(["--root", str(sov_root), "--reset-mind"])
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)

    assert streak(sov_root) == 5, (
        "a reset that could not get the lock must not race the live "
        "sweep's own state.json write"
    )
    assert rc != 0, (
        "a --reset-mind that silently no-ops because a sweep was live is "
        "its own fail-open — it must not report success"
    )
    out = capsys.readouterr().out.lower()
    assert "reset-mind" in out and "not" in out, (
        "the no-op must be unmistakable on stdout, not just a generic "
        "'sweep already live' line that never mentions the reset at all"
    )
