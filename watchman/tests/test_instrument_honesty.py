"""Honesty closure — findings 3, 4, 9, 10, 11, 12.

Same prove-can-fail discipline as test_metadata_and_content_leak.py: every test
asserts on run_sweep output or on persisted bytes, so the file runs unmodified
against 8adec9b and fails there on the assertion rather than on an import.

The class being hunted is the house's own SOP #2 — a surface that reports
success on a failed operation, or completeness on a partial one.
"""

import json
from pathlib import Path

import pytest

import watchman_sweep
from conftest import (
    dead_script,
    good_reply_for,
    invocations,
    make_fake_cosmic,
    write_proposal,
)

T2HELIX_ROOT = Path.home() / "t2helix"
needs_t2helix = pytest.mark.skipif(
    not (T2HELIX_ROOT / "lib" / "secrets.js").exists(),
    reason="t2helix secrets.js not present on this machine",
)


def mech_refs(env):
    return {m["ref"] for m in env.get("mechanical_lines", [])}


def mech_sources(env):
    return {m.get("source") for m in env.get("mechanical_lines", [])}


# ==================================== finding 3: the policy loader fail-open


def test_malformed_policy_closes_the_eyes_and_says_so(
    sov_root, clean_fetchers, tmp_path
):
    """A plausible hand-edit typo — brackets dropped — used to iterate the
    STRING into single characters, so antigravity_connector was NO LONGER
    denied while policy_state still reported 'loaded'. Coercion, not
    validation, and silent in both directions."""
    bad = tmp_path / "eyes_policy.json"
    bad.write_text(json.dumps({"denylist_queues": "antigravity_connector"}))
    write_proposal(
        sov_root,
        "antigravity_connector",
        "ag.json",
        content="synthetic body that must never be previewed under a broken policy",
    )
    env = watchman_sweep.run_sweep(
        sov_root, dry_run=True, policy_path=bad, **clean_fetchers
    )
    assert env["policy_state"] == "floor-fallback"
    assert env["items"][0]["preview_state"] == "metadata-only:denylist"
    assert any(r.startswith("policy:") for r in mech_refs(env)), (
        "a policy the sweep could not trust must raise an attend line about "
        "the policy FILE, not just quietly degrade"
    )


def test_wrongly_typed_policy_entry_also_closes(sov_root, clean_fetchers, tmp_path):
    bad = tmp_path / "eyes_policy.json"
    bad.write_text(json.dumps({"denylist_domains": [{"not": "a string"}]}))
    write_proposal(sov_root, "grok_bridge", "p.json", content="synthetic routine body")
    env = watchman_sweep.run_sweep(
        sov_root, dry_run=True, policy_path=bad, **clean_fetchers
    )
    assert env["policy_state"] == "floor-fallback"
    assert env["items"][0]["preview_state"] == "metadata-only:denylist"


def test_absent_policy_file_is_reported_but_does_not_close(
    sov_root, clean_fetchers, tmp_path
):
    """A MISSING file falls back to compiled-in seeds byte-equal to the shipped
    ones, so nothing widens — but it is still an instrument condition and the
    envelope names it."""
    env = watchman_sweep.run_sweep(
        sov_root,
        dry_run=True,
        policy_path=tmp_path / "does_not_exist.json",
        **clean_fetchers,
    )
    assert env is None or env["policy_state"] == "builtin-fallback"


# =================================== finding 4: node off PATH + standing blind


@needs_t2helix
def test_node_resolves_even_with_launchd_style_PATH(
    sov_root, clean_fetchers, monkeypatch
):
    """launchd does not inherit a login shell's PATH and node lives under
    /opt/homebrew. A bare 'node' turned the eyes off the moment the plist
    loaded, fail-closed in direction but permanently and silently."""
    monkeypatch.setenv("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
    monkeypatch.delenv("WATCHMAN_NODE_BIN", raising=False)
    write_proposal(sov_root, "grok_bridge", "nopath.json", content="synthetic routine")
    env = watchman_sweep.run_sweep(sov_root, dry_run=True, **clean_fetchers)
    assert env["items"][0]["preview_state"] == "sanitized"


def test_node_bin_override_is_honoured(sov_root, clean_fetchers, monkeypatch):
    monkeypatch.setenv("WATCHMAN_NODE_BIN", "/nonexistent/node-guard")
    write_proposal(sov_root, "grok_bridge", "ovr.json", content="synthetic routine")
    env = watchman_sweep.run_sweep(sov_root, dry_run=True, **clean_fetchers)
    assert env["items"][0]["preview_state"] == "metadata-only:sanitizer-failed"


def test_standing_blindness_escalates_to_urgent(sov_root, clean_fetchers, tmp_path):
    """The instrument must report ITSELF. Before this, the only signal that the
    watchman had gone blind was a counter in one spool line."""
    write_proposal(sov_root, "grok_bridge", "blind.json", content="synthetic routine")
    kw = {"sanitize_kwargs": {"script_path": dead_script(tmp_path)}}
    envs = [
        watchman_sweep.run_sweep(sov_root, **clean_fetchers, **kw) for _ in range(3)
    ]
    assert all(e is not None for e in envs), (
        "a blinded item must keep re-surfacing, not vanish behind the high-water"
    )
    assert [e["blindness"]["streak"] for e in envs] == [1, 2, 3]
    assert "instrument:sanitizer" not in mech_refs(envs[0])
    assert "instrument:sanitizer" in mech_refs(envs[2])
    assert envs[2]["severity_ceiling"] == "urgent"
    assert "THE WATCHMAN IS BLIND" in (sov_root / "watchman" / "latest.md").read_text()


def test_a_blind_sweep_does_not_spend_a_grok_call(sov_root, clean_fetchers, tmp_path):
    """Nothing sanitized survived, so there is nothing semantic to classify —
    same shape as the surface-errors-only path."""
    write_proposal(sov_root, "grok_bridge", "blind2.json", content="synthetic routine")
    fake, log = make_fake_cosmic(tmp_path, good_reply_for([]))
    env = watchman_sweep.run_sweep(
        sov_root,
        cosmic_bin=fake,
        sanitize_kwargs={"script_path": dead_script(tmp_path)},
        **clean_fetchers,
    )
    assert env["grok_invoked"] is False
    assert env["grok_process_state"] == "not-attempted"
    assert env["grok_reply_state"] == "not-invoked-sweep-blind"
    assert invocations(log) == 0


@needs_t2helix
def test_a_sanitizer_failure_is_re_examined_once_repaired(
    sov_root, clean_fetchers, tmp_path
):
    """A transient breakage used to blind the watchman to those items
    PERMANENTLY: the high-water advanced regardless of preview outcome, so the
    repaired sweep saw an unchanged file and went quiet."""
    write_proposal(sov_root, "grok_bridge", "transient.json", content="synthetic body")
    first = watchman_sweep.run_sweep(
        sov_root,
        sanitize_kwargs={"script_path": dead_script(tmp_path)},
        **clean_fetchers,
    )
    assert first["items"][0]["preview_state"] == "metadata-only:sanitizer-failed"

    fake, _ = make_fake_cosmic(
        tmp_path, good_reply_for(["grok_bridge/pending_writes/transient.json"])
    )
    second = watchman_sweep.run_sweep(sov_root, cosmic_bin=fake, **clean_fetchers)
    assert second is not None, "the repaired sweep must re-examine the held item"
    item = next(
        i
        for i in second["items"]
        if i["ref"] == "grok_bridge/pending_writes/transient.json"
    )
    assert item["preview_state"] == "sanitized"


# ======================================== finding 9: reply coverage accounting


def test_an_omitted_digest_item_is_counted_and_raises_the_ceiling(
    sov_root, clean_fetchers, tmp_path
):
    """directive.md commands 'Every digest item MUST appear exactly once in
    items'; nothing verified it. A reply omitting the hot item was accepted as
    'parsed', and severity_ceiling — computed only over the items Grok returned
    — read as complete triage. Visible by eye, absent by field."""
    write_proposal(sov_root, "grok_bridge", "answered.json")
    write_proposal(sov_root, "grok_bridge", "ignored.json")
    answered = "grok_bridge/pending_writes/answered.json"
    fake, _ = make_fake_cosmic(tmp_path, good_reply_for([answered]))
    env = watchman_sweep.run_sweep(sov_root, cosmic_bin=fake, **clean_fetchers)

    cov = env["reply_coverage"]
    assert cov["expected"] == 2 and cov["answered"] == 1 and cov["omitted"] == 1
    assert env["grok_reply_state"] == "parsed-partial"
    assert "grok-omitted" in mech_sources(env)
    omitted_line = next(
        m for m in env["mechanical_lines"] if m.get("source") == "grok-omitted"
    )
    assert omitted_line["severity"] == "attend"
    assert omitted_line["flagged_for_richer_review"] is True
    assert env["severity_ceiling"] == "attend", (
        "an all-info reply that skipped an item must not present as INFO"
    )
    latest = (sov_root / "watchman" / "latest.md").read_text()
    assert "grok-omitted" in latest


def test_an_extra_item_is_recorded_with_a_skepticism_note(
    sov_root, clean_fetchers, tmp_path
):
    write_proposal(sov_root, "grok_bridge", "real.json")
    reply = good_reply_for(
        [
            "grok_bridge/pending_writes/real.json",
            "grok_bridge/pending_writes/ghost.json",
        ]
    )
    fake, _ = make_fake_cosmic(tmp_path, reply)
    env = watchman_sweep.run_sweep(sov_root, cosmic_bin=fake, **clean_fetchers)

    cov = env["reply_coverage"]
    assert cov["extra"] == 1 and cov["omitted"] == 0
    assert env["grok_reply_state"] == "parsed-partial"
    extra_line = next(
        m for m in env["mechanical_lines"] if m.get("source") == "grok-extra"
    )
    assert "skepticism" in extra_line["reason"].lower()


def test_full_coverage_stays_parsed(sov_root, clean_fetchers, tmp_path):
    write_proposal(sov_root, "grok_bridge", "covered.json")
    ref = "grok_bridge/pending_writes/covered.json"
    fake, _ = make_fake_cosmic(tmp_path, good_reply_for([ref]))
    env = watchman_sweep.run_sweep(sov_root, cosmic_bin=fake, **clean_fetchers)
    assert env["grok_reply_state"] == "parsed"
    assert env["reply_coverage"] == {
        "expected": 1,
        "answered": 1,
        "omitted": 0,
        "extra": 0,
        "duplicated": 0,
        "reply_items": 1,
        "judgments": 1,
        "omitted_refs": [],
        "extra_refs": [],
        "duplicated_refs": [],
    }


def test_a_banner_json_fragment_does_not_win_over_the_envelope(
    sov_root, clean_fetchers, tmp_path
):
    """Coverage made 'first parseable object wins' load-bearing: a JSON-shaped
    banner fragment would report 0 answered / N omitted and fire false attend
    lines about an omission that never happened."""
    write_proposal(sov_root, "grok_bridge", "banner.json")
    ref = "grok_bridge/pending_writes/banner.json"
    reply = '{"cosmic_cli": {"version": "0.9.4"}}\n' + good_reply_for([ref])
    fake, _ = make_fake_cosmic(tmp_path, reply)
    env = watchman_sweep.run_sweep(sov_root, cosmic_bin=fake, **clean_fetchers)
    assert env["grok_reply_state"] == "parsed"
    assert env["reply_coverage"]["answered"] == 1


# ======================================== finding 10: grok_invoked must be true


def test_a_spawn_failure_is_its_own_state_and_claims_no_spend(sov_root, clean_fetchers):
    """grok_invoked was stamped True even when NO process ever ran, so a reader
    auditing spend from spool.jsonl alone would miscount."""
    write_proposal(sov_root, "grok_bridge", "nospawn.json")
    env = watchman_sweep.run_sweep(
        sov_root, cosmic_bin="/nonexistent/cosmic-guard", **clean_fetchers
    )
    assert env["grok_invoked"] is False
    assert env["grok_process_state"] == "spawn-failed"
    assert env["grok_reply_state"] == "grok-spawn-failed"
    assert "grok:spawn" in mech_refs(env)
    assert env["severity_ceiling"] == "attend"


def test_a_real_process_that_answers_garbage_is_spawned_not_failed(
    sov_root, clean_fetchers, tmp_path
):
    write_proposal(sov_root, "grok_bridge", "garbagereply.json")
    fake, _ = make_fake_cosmic(tmp_path, "no json here, captain")
    env = watchman_sweep.run_sweep(sov_root, cosmic_bin=fake, **clean_fetchers)
    assert env["grok_invoked"] is True
    assert env["grok_process_state"] == "spawned"
    assert env["grok_reply_state"] == "grok-reply-unparseable"


def test_a_dry_run_reports_not_attempted(sov_root, clean_fetchers):
    write_proposal(sov_root, "grok_bridge", "dryproc.json")
    env = watchman_sweep.run_sweep(sov_root, dry_run=True, **clean_fetchers)
    assert env["grok_invoked"] is False
    assert env["grok_process_state"] == "not-attempted"


# ============================================== finding 11: dry-run purity


def test_a_dry_run_does_not_consume_the_deltas_a_live_sweep_needs(
    sov_root, clean_fetchers, tmp_path
):
    """THE ONE THAT MATTERS: the high-water update ran unconditionally, so a
    dry run CONSUMED filesystem deltas and the following live sweep never
    handed them to Grok. The README's 'first live sweep is a baptism' was
    silently defeated by the demo the README itself invites."""
    write_proposal(sov_root, "grok_bridge", "prop_dry.json")
    ref = "grok_bridge/pending_writes/prop_dry.json"

    dry = watchman_sweep.run_sweep(sov_root, dry_run=True, **clean_fetchers)
    assert [i["ref"] for i in dry["items"]] == [ref]

    fake, log = make_fake_cosmic(tmp_path, good_reply_for([ref]))
    live = watchman_sweep.run_sweep(sov_root, cosmic_bin=fake, **clean_fetchers)
    assert live is not None, "the dry run blinded the live sweep"
    assert [i["ref"] for i in live["items"]] == [ref]
    assert invocations(log) == 1


def test_a_dry_run_writes_no_state_and_no_production_spool(sov_root, clean_fetchers):
    write_proposal(sov_root, "grok_bridge", "pure.json")
    watchman_sweep.run_sweep(sov_root, dry_run=True, **clean_fetchers)
    wd = sov_root / "watchman"
    assert not (wd / "state.json").exists()
    assert not (wd / "spool.jsonl").exists()
    assert not (wd / "latest.md").exists()
    assert not (wd / "watchman.log").exists()
    # ...and the dry output still exists, in its own lane
    assert (wd / "dry-run-spool.jsonl").exists()
    assert (wd / "latest.dry-run.md").exists()


def test_a_dry_run_does_not_advance_an_existing_high_water(
    sov_root, clean_fetchers, tmp_path
):
    write_proposal(sov_root, "grok_bridge", "first.json")
    fake, _ = make_fake_cosmic(
        tmp_path, good_reply_for(["grok_bridge/pending_writes/first.json"])
    )
    watchman_sweep.run_sweep(sov_root, cosmic_bin=fake, **clean_fetchers)
    before = (sov_root / "watchman" / "state.json").read_text()

    write_proposal(sov_root, "grok_bridge", "second.json")
    watchman_sweep.run_sweep(sov_root, dry_run=True, **clean_fetchers)
    assert (sov_root / "watchman" / "state.json").read_text() == before


# ============================================== finding 12: count consistency


def test_comms_note_reconciles_with_the_items_it_produced(sov_root, clean_fetchers):
    """The note said 'unread=N' while N included messages the sweep then
    dropped, so the note and items_seen disagreed by the skipped count with
    nothing saying why."""
    fetchers = dict(clean_fetchers)
    fetchers["comms_fetch"] = lambda: {
        "channel": "general",
        "messages": [
            {
                "id": "m-1",
                "sender": "daemon.uncertainty",
                "timestamp": "1785700000.0",
                "content": "synthetic whisper one",
            },
            {
                "id": "m-2",
                "sender": watchman_sweep.INSTANCE_ID,
                "timestamp": "1785700000.0",
                "content": "synthetic self-sent echo",
            },
            "not-a-dict",
        ],
        "count": 3,
    }
    env = watchman_sweep.run_sweep(sov_root, dry_run=True, **fetchers)
    comms = env["surfaces"]["comms"]
    assert comms["unread"] == 3
    assert comms["self_sent_excluded"] == 1
    assert comms["malformed_excluded"] == 1
    assert comms["items"] == 1
    assert "self-sent excluded=1" in comms["note"]


def test_every_surface_states_its_own_item_count_and_they_sum(sov_root, clean_fetchers):
    write_proposal(sov_root, "grok_bridge", "a.json")
    write_proposal(sov_root, "openai_bridge", "b.json")
    (sov_root / "daemons" / "halts" / "h.txt").write_text("synthetic halt note")
    env = watchman_sweep.run_sweep(sov_root, dry_run=True, **clean_fetchers)
    by_surface = env["counts"]["items_by_surface"]
    assert set(by_surface) == set(watchman_sweep.SURFACE_NAMES)
    assert sum(by_surface.values()) == env["counts"]["items_seen"]
