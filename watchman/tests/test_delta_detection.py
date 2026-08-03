"""Delta detection: new file, changed file, no-change -> no cosmic invocation.
Plus the two bridge-fed surfaces (heartbeat commit mismatch, comms unread) and
the handoff unconsumed count."""

import json
import os

import watchman_sweep
from conftest import (
    good_reply_for,
    invocations,
    make_fake_cosmic,
    write_handoff,
    write_proposal,
)


def sweep(sov_root, clean_fetchers, cosmic_bin, **kw):
    return watchman_sweep.run_sweep(
        sov_root, cosmic_bin=cosmic_bin, **clean_fetchers, **kw
    )


def test_new_file_is_a_delta_and_wakes_grok(sov_root, clean_fetchers, tmp_path):
    write_proposal(sov_root, "grok_bridge", "prop_new.json")
    ref = "grok_bridge/pending_writes/prop_new.json"
    fake, log = make_fake_cosmic(tmp_path, good_reply_for([ref]))
    env = sweep(sov_root, clean_fetchers, fake)
    assert env is not None
    assert env["grok_invoked"] is True
    assert invocations(log) == 1
    items = {i["ref"]: i for i in env["items"]}
    assert items[ref]["change"] == "new"
    assert items[ref]["risk_level"] == "low"
    assert items[ref]["tool"] == "propose_insight"


def test_no_change_means_no_cosmic_and_no_spool(sov_root, clean_fetchers, tmp_path):
    write_proposal(sov_root, "grok_bridge", "prop_a.json")
    fake, log = make_fake_cosmic(
        tmp_path, good_reply_for(["grok_bridge/pending_writes/prop_a.json"])
    )
    first = sweep(sov_root, clean_fetchers, fake)
    assert first is not None and invocations(log) == 1
    spool = sov_root / "watchman" / "spool.jsonl"
    lines_after_first = len(spool.read_text().splitlines())

    second = sweep(sov_root, clean_fetchers, fake)
    assert second is None, "no-change sweep must return quiet"
    assert invocations(log) == 1, "cosmic must NOT be invoked on a quiet sweep"
    assert len(spool.read_text().splitlines()) == lines_after_first, (
        "quiet sweep must not append to the spool"
    )
    # ... but the mechanical heartbeat IS written: log line + state touched.
    wlog = (sov_root / "watchman" / "watchman.log").read_text()
    assert "quiet" in wlog and "grok not invoked" in wlog
    state = json.loads((sov_root / "watchman" / "state.json").read_text())
    assert state["sweeps"] == 2


def test_changed_file_is_a_delta(sov_root, clean_fetchers, tmp_path):
    p = write_proposal(sov_root, "openai_bridge", "prop_b.json")
    ref = "openai_bridge/pending_writes/prop_b.json"
    fake, log = make_fake_cosmic(tmp_path, good_reply_for([ref]))
    sweep(sov_root, clean_fetchers, fake)

    write_proposal(
        sov_root, "openai_bridge", "prop_b.json", content="synthetic revised body v2"
    )
    os.utime(p, (p.stat().st_atime, p.stat().st_mtime + 5))
    env = sweep(sov_root, clean_fetchers, fake)
    assert env is not None
    items = {i["ref"]: i for i in env["items"]}
    assert items[ref]["change"] == "changed"


def test_heartbeat_commit_mismatch_alerts_once_per_pair(sov_root, tmp_path):
    fetchers = {
        "heartbeat_fetch": lambda: {"source_commit": "def5678"},
        "git_head_fn": lambda: "abc1234",
        "comms_fetch": lambda: {"channel": "general", "messages": [], "count": 0},
    }
    fake, log = make_fake_cosmic(
        tmp_path, good_reply_for(["bridge/heartbeat-source-commit"])
    )
    env = watchman_sweep.run_sweep(sov_root, cosmic_bin=fake, **fetchers)
    assert env is not None
    refs = [i["ref"] for i in env["items"]]
    assert "bridge/heartbeat-source-commit" in refs
    item = next(i for i in env["items"] if i["ref"] == "bridge/heartbeat-source-commit")
    assert item["detail"] == {"served": "def5678", "local": "abc1234"}

    # Same mismatch pair again: no re-alert (state remembers the pair).
    env2 = watchman_sweep.run_sweep(sov_root, cosmic_bin=fake, **fetchers)
    assert env2 is None


def test_heartbeat_short_long_prefix_is_not_a_mismatch(sov_root, tmp_path):
    fetchers = {
        "heartbeat_fetch": lambda: {"source_commit": "abc1234"},
        "git_head_fn": lambda: "abc1234567890",
        "comms_fetch": lambda: {"channel": "general", "messages": [], "count": 0},
    }
    fake, _ = make_fake_cosmic(tmp_path, "unused")
    env = watchman_sweep.run_sweep(sov_root, cosmic_bin=fake, **fetchers)
    assert env is None


def test_handoff_unconsumed_count_change_is_a_delta(sov_root, clean_fetchers, tmp_path):
    write_handoff(sov_root, "h1.json", consumed_at=None)
    write_handoff(sov_root, "h2.json", consumed_at="2026-08-01T00:00:00Z")
    fake, log = make_fake_cosmic(
        tmp_path, good_reply_for(["handoffs/unconsumed-count"])
    )

    # Baseline sweep: count recorded (1), no delta invented on first sight.
    env = sweep(sov_root, clean_fetchers, fake)
    assert env is None
    state = json.loads((sov_root / "watchman" / "state.json").read_text())
    assert state["handoffs_unconsumed"] == 1

    write_handoff(sov_root, "h3.json", consumed_at=None)
    env = sweep(sov_root, clean_fetchers, fake)
    assert env is not None
    item = next(i for i in env["items"] if i["ref"] == "handoffs/unconsumed-count")
    assert item["detail"]["unconsumed"] == 2
    assert item["detail"]["previous"] == 1


def test_comms_unread_message_is_a_delta(sov_root, tmp_path):
    fetchers = {
        "heartbeat_fetch": lambda: {"source_commit": "abc1234"},
        "git_head_fn": lambda: "abc1234",
        "comms_fetch": lambda: {
            "channel": "general",
            "messages": [
                {
                    "id": "m-synth-1",
                    "sender": "daemon.uncertainty",
                    "timestamp": "1785700000.0",
                    "content": "synthetic whisper: confidence dipped on synthetic metric",
                    "read_by": [],
                }
            ],
            "count": 1,
        },
    }
    fake, _ = make_fake_cosmic(tmp_path, good_reply_for(["comms/general/m-synth-1"]))
    env = watchman_sweep.run_sweep(sov_root, cosmic_bin=fake, **fetchers)
    assert env is not None
    item = next(i for i in env["items"] if i["ref"] == "comms/general/m-synth-1")
    assert item["sender"] == "daemon.uncertainty"
    assert item["preview_state"] == "sanitized"
    assert "synthetic whisper" in item["preview"]


def test_comms_read_at_limit_is_flagged_possibly_partial(
    sov_root, tmp_path, monkeypatch
):
    # A read that returns exactly the requested limit may be capped — the
    # envelope must say so rather than present a capped read as complete.
    monkeypatch.setattr(watchman_sweep, "COMMS_READ_LIMIT", 3)
    n = watchman_sweep.COMMS_READ_LIMIT
    fetchers = {
        "heartbeat_fetch": lambda: {"source_commit": "abc1234"},
        "git_head_fn": lambda: "abc1234",
        "comms_fetch": lambda: {
            "channel": "general",
            "messages": [
                {
                    "id": f"m-synth-{i}",
                    "sender": "synthetic-sender",
                    "timestamp": "1785700000.0",
                    "content": f"synthetic filler message {i}",
                    "read_by": [],
                }
                for i in range(n)
            ],
            "count": n,
        },
    }
    fake, _ = make_fake_cosmic(tmp_path, good_reply_for([]))
    env = watchman_sweep.run_sweep(sov_root, cosmic_bin=fake, **fetchers)
    assert env["surfaces"]["comms"]["possibly_partial"] is True
    assert "possibly partial" in env["surfaces"]["comms"]["note"]
