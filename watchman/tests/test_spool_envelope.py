"""Spool envelope honesty: surfaces reported (never omitted), grok_invoked
recorded either way, malformed Grok replies quarantined (never silently
dropped), and the directive JSON round-trip with a MOCKED grok reply."""

import json
import shutil

import watchman_sweep
from conftest import (
    good_reply_for,
    invocations,
    make_fake_cosmic,
    write_proposal,
)


def read_spool(sov_root, *, dry_run=False):
    name = "dry-run-spool.jsonl" if dry_run else "spool.jsonl"
    p = sov_root / "watchman" / name
    return [json.loads(line) for line in p.read_text().splitlines()]


def test_surface_error_is_reported_not_omitted(sov_root, clean_fetchers, tmp_path):
    # Kill one surface: handoffs becomes a file, not a directory.
    shutil.rmtree(sov_root / "handoffs")
    (sov_root / "handoffs").write_text("not a directory")
    fake, log = make_fake_cosmic(tmp_path, good_reply_for([]))
    env = watchman_sweep.run_sweep(sov_root, cosmic_bin=fake, **clean_fetchers)

    assert env is not None, "a surface error must produce an envelope, not silence"
    assert set(env["surfaces"].keys()) == set(watchman_sweep.SURFACE_NAMES), (
        "all five surfaces present in the envelope, errored ones included"
    )
    assert env["surfaces"]["handoffs"]["ok"] is False
    assert env["surfaces"]["handoffs"]["error"]
    # grok NOT invoked for a mechanical instrument problem — and recorded so.
    assert env["grok_invoked"] is False
    assert invocations(log) == 0
    # the spool carries an 'attend' line about the surface itself
    entries = read_spool(sov_root)
    mech = entries[-1]["mechanical_lines"]
    assert any(
        m["severity"] == "attend" and m["ref"] == "surface:handoffs" for m in mech
    )
    assert entries[-1]["severity_ceiling"] == "attend"
    latest = (sov_root / "watchman" / "latest.md").read_text()
    assert "surface could not be read" in latest


def test_bridge_down_is_reported_per_surface(sov_root, tmp_path):
    def boom():
        raise ConnectionError("synthetic: bridge unreachable")

    fake, log = make_fake_cosmic(tmp_path, good_reply_for([]))
    env = watchman_sweep.run_sweep(
        sov_root,
        cosmic_bin=fake,
        heartbeat_fetch=boom,
        git_head_fn=lambda: "abc1234",
        comms_fetch=boom,
    )
    assert env is not None
    assert env["surfaces"]["heartbeat"]["ok"] is False
    assert env["surfaces"]["comms"]["ok"] is False
    assert "unreachable" in env["surfaces"]["comms"]["error"]
    # filesystem surfaces still ok and still reported
    assert env["surfaces"]["pending_writes"]["ok"] is True
    assert env["grok_invoked"] is False


def test_grok_reply_round_trip_lands_in_spool(sov_root, clean_fetchers, tmp_path):
    write_proposal(sov_root, "grok_bridge", "prop_rt.json")
    ref = "grok_bridge/pending_writes/prop_rt.json"
    fake, log = make_fake_cosmic(tmp_path, good_reply_for([ref]))
    env = watchman_sweep.run_sweep(sov_root, cosmic_bin=fake, **clean_fetchers)

    assert env["grok_invoked"] is True
    assert env["grok_reply_state"] == "parsed"
    assert env["grok_identity_line_present"] is True
    judged = env["grok_reply"]["items"][0]
    assert judged["ref"] == ref
    assert judged["severity"] == "info"
    assert judged["flagged_for_richer_review"] is False
    assert judged["confidence_basis"]

    entry = read_spool(sov_root)[-1]
    assert entry["grok_reply"]["items"][0]["ref"] == ref
    assert entry["severity_ceiling"] == "info"
    latest = (sov_root / "watchman" / "latest.md").read_text()
    assert "confidence basis" in latest
    assert "grok_invoked: True" in latest


def test_malformed_grok_reply_is_quarantined(sov_root, clean_fetchers, tmp_path):
    write_proposal(sov_root, "grok_bridge", "prop_bad.json")
    raw = "Everything looks nominal, captain. No JSON for you."
    fake, log = make_fake_cosmic(tmp_path, raw)
    env = watchman_sweep.run_sweep(sov_root, cosmic_bin=fake, **clean_fetchers)

    assert env["grok_invoked"] is True
    assert env["grok_reply_state"] == "grok-reply-unparseable"
    assert env["grok_reply"] is None
    qfile = env["quarantine_file"]
    assert qfile and raw in open(qfile).read(), "raw reply kept, never dropped"
    entry = read_spool(sov_root)[-1]
    assert entry["grok_reply_state"] == "grok-reply-unparseable"
    assert entry["quarantine_file"] == qfile


def test_parse_tolerates_banner_and_fences():
    wrapped = (
        "╭─ COSMIC banner noise ─╮\n"
        "WATCHMAN SWEEP — grok-4.5 via cosmic-cli\n"
        "```json\n"
        '{"identity": "WATCHMAN SWEEP — grok-4.5 via cosmic-cli", '
        '"observation": {"summary": "s", "anomalies": []}, '
        '"proposal": {"summary": "n", "actions_proposed": []}, "items": []}\n'
        "```\n"
    )
    parsed, identity = watchman_sweep.parse_grok_reply(wrapped)
    assert identity is True
    assert parsed["observation"]["summary"] == "s"


def test_urgent_reply_raises_the_ceiling(sov_root, clean_fetchers, tmp_path):
    write_proposal(sov_root, "grok_bridge", "prop_hot.json", risk="high")
    ref = "grok_bridge/pending_writes/prop_hot.json"
    reply = "WATCHMAN SWEEP — grok-4.5 via cosmic-cli\n" + json.dumps(
        {
            "identity": "WATCHMAN SWEEP — grok-4.5 via cosmic-cli",
            "observation": {
                "summary": "high-risk item",
                "anomalies": ["cadence spike"],
            },
            "proposal": {
                "summary": "HQ seat should review now",
                "actions_proposed": ["review the flagged proposal"],
            },
            "items": [
                {
                    "ref": ref,
                    "severity": "urgent",
                    "reason": "declared high risk, unfamiliar pattern",
                    "flagged_for_richer_review": True,
                    "confidence_basis": "metadata cadence only, body withheld",
                }
            ],
        }
    )
    fake, _ = make_fake_cosmic(tmp_path, reply)
    env = watchman_sweep.run_sweep(sov_root, cosmic_bin=fake, **clean_fetchers)
    assert env["severity_ceiling"] == "urgent"
    latest = (sov_root / "watchman" / "latest.md").read_text()
    assert "URGENT" in latest
    assert "flagged for richer review" in latest
    # the phone rule is stated where the next seat will read it
    assert "never" in latest and "texts Anthony" in latest


def test_dry_run_never_invokes_cosmic_and_saves_prompt(
    sov_root, clean_fetchers, tmp_path
):
    write_proposal(sov_root, "grok_bridge", "prop_dry.json")
    env = watchman_sweep.run_sweep(sov_root, dry_run=True, **clean_fetchers)
    assert env["grok_invoked"] is False
    assert env["grok_reply_state"] == "dry-run"
    prompt_file = env["dry_run_prompt_file"]
    text = open(prompt_file).read()
    assert "WATCHMAN SWEEP DIRECTIVE" in text
    assert "DELTA DIGEST" in text
    assert "prop_dry.json" in text
    entry = read_spool(sov_root, dry_run=True)[-1]
    assert entry["dry_run"] is True and entry["grok_invoked"] is False
