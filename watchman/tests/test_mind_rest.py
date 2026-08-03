"""Mind-rest spend breaker (closure-round residual R4, fixed by HQ pre-gate).

The loop it breaks: an exception AFTER invoke_cosmic returns leaves the xAI
spend made but the high-water unsaved, so the same deltas re-fire and re-spend
every sweep — the scribe-greeting spend loop in a new costume. After N
consecutive spawned-but-unsaved failures the mind rests: mechanical digests
keep landing in the spool, Grok is not invoked, an urgent instrument line says
so, and --reset-mind re-arms after repair.
"""

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
