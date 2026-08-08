"""Surface (f): the nape goose's honks. First run baselines (never itemizes
backlog — the baptism lesson), thereafter new unacked honks are items with
level mapped to declared risk; an absent store is a stated note, not an
error."""

import json

import watchman_sweep
from conftest import good_reply_for, make_fake_cosmic


def _honk(hid, level="sharp", observation="synthetic honk observation", **kw):
    return {
        "honk_id": hid,
        "session_id": "spiral_synthetic",
        "pattern": kw.get("pattern", "repeated_mistake"),
        "level": level,
        "trigger_tool": kw.get("trigger_tool", "record_insight"),
        "ts": "2026-08-03T12:00:00+00:00",
        "observation": observation,
    }


def _write_honks(root, honks):
    d = root / "nape"
    d.mkdir(exist_ok=True)
    with open(d / "honks.jsonl", "a", encoding="utf-8") as f:
        for h in honks:
            f.write(json.dumps(h) + "\n")


def test_absent_store_is_a_note_not_an_error(sov_root):
    surface, items, hw = watchman_sweep.scan_honks(sov_root, {})
    assert surface["ok"] is True
    assert "absent" in surface["note"]
    assert items == [] and hw is None


def test_first_run_baselines_without_itemizing(sov_root):
    _write_honks(sov_root, [_honk(f"h{i}") for i in range(50)])
    surface, items, hw = watchman_sweep.scan_honks(sov_root, {})
    assert items == [], "a backlog must never flood the digest"
    assert hw == 50
    assert "baseline: 50 honks" in surface["note"]
    assert "50 unacked (50 sharp" in surface["note"]


def test_new_unacked_honk_is_an_item_with_level_mapped_risk(sov_root):
    _write_honks(sov_root, [_honk("old1")])
    state = {"honks_line_count": 1}
    _write_honks(
        sov_root, [_honk("new1", level="sharp"), _honk("new2", level="uneasy")]
    )
    surface, items, hw = watchman_sweep.scan_honks(sov_root, state)
    assert hw == 3 and len(items) == 2
    by_id = {m["filename"]: m for m, _ in items}
    assert by_id["new1"]["risk_level"] == "high"
    assert by_id["new2"]["risk_level"] == "medium"
    assert by_id["new1"]["queue"] == "nape/honks"


def test_acked_honks_are_not_itemized(sov_root):
    _write_honks(sov_root, [_honk("seen")])
    state = {"honks_line_count": 1}
    _write_honks(sov_root, [_honk("quiet1")])
    (sov_root / "nape" / "acks.jsonl").write_text(
        json.dumps({"honk_id": "quiet1", "note": "handled"}) + "\n"
    )
    surface, items, hw = watchman_sweep.scan_honks(sov_root, state)
    assert items == [] and hw == 2


def test_corrupt_line_is_counted_never_silent(sov_root):
    _write_honks(sov_root, [_honk("a")])
    with open(sov_root / "nape" / "honks.jsonl", "a") as f:
        f.write("{not json\n")
    state = {"honks_line_count": 1}
    surface, items, hw = watchman_sweep.scan_honks(sov_root, state)
    assert "corrupt skipped=1" in surface["note"]
    assert hw == 2


def test_baseline_non_dict_line_is_corrupt_not_a_crash(sov_root):
    """json.loads() on `null` / `42` / `"x"` / `true` / `[1, 2]` succeeds and
    returns a non-dict; calling .get() on it (unguarded) raises
    AttributeError. This is a SYNTACTICALLY VALID line, unlike
    test_corrupt_line_is_counted_never_silent's `{not json` — that is why
    that test alone does not catch this defect."""
    d = sov_root / "nape"
    d.mkdir(exist_ok=True)
    with open(d / "honks.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(_honk("real1")) + "\n")
        for raw in ["null", "42", '"x"', "true", "[1, 2]"]:
            f.write(raw + "\n")
    surface, items, hw = watchman_sweep.scan_honks(sov_root, {})
    assert items == [], "a backlog must never flood the digest"
    assert hw == 6
    assert "corrupt=5" in surface["note"]


def test_incremental_non_dict_line_is_corrupt_not_a_crash(sov_root):
    _write_honks(sov_root, [_honk("old1")])
    state = {"honks_line_count": 1}
    d = sov_root / "nape"
    with open(d / "honks.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(_honk("new1")) + "\n")
        for raw in ["null", "42", '"x"', "true", "[1, 2]"]:
            f.write(raw + "\n")
    surface, items, hw = watchman_sweep.scan_honks(sov_root, state)
    assert hw == 7
    assert len(items) == 1, "only the one real dict honk becomes an item"
    assert items[0][0]["filename"] == "new1"
    assert "corrupt skipped=5" in surface["note"]


def test_ack_without_honk_id_does_not_poison_unacked_count(sov_root):
    """Micro-defect, same family: _load_ack_ids used to add None to the
    ack-id set for a record missing honk_id. A honk that also lacks
    honk_id then read as ALREADY ACKED (None in acked_ids) and was
    silently skipped from the unacked baseline count."""
    d = sov_root / "nape"
    d.mkdir(exist_ok=True)
    with open(d / "honks.jsonl", "a", encoding="utf-8") as f:
        f.write(
            json.dumps(
                {
                    "session_id": "spiral_synthetic",
                    "pattern": "repeated_mistake",
                    "level": "sharp",
                    "trigger_tool": "record_insight",
                    "ts": "2026-08-03T12:00:00+00:00",
                    "observation": "a honk missing honk_id entirely",
                }
            )
            + "\n"
        )
    (d / "acks.jsonl").write_text(
        json.dumps({"note": "malformed ack, no honk_id"}) + "\n", encoding="utf-8"
    )
    surface, items, hw = watchman_sweep.scan_honks(sov_root, {})
    assert "1 unacked" in surface["note"], (
        "a malformed ack lacking honk_id must not silently mark a "
        "honk_id-less honk as already acked"
    )


def test_end_to_end_new_honk_reaches_the_spool(sov_root, clean_fetchers, tmp_path):
    _write_honks(sov_root, [_honk("base")])
    fake, log = make_fake_cosmic(tmp_path, good_reply_for([]))
    env = watchman_sweep.run_sweep(sov_root, cosmic_bin=fake, **clean_fetchers)
    assert env is None or env["counts"]["items_by_surface"].get("honks", 0) == 0

    _write_honks(
        sov_root, [_honk("fresh", observation="a brand new synthetic sharp honk")]
    )
    ref = "nape/honks/fresh"
    fake2, log2 = make_fake_cosmic(tmp_path, good_reply_for([ref]))
    env2 = watchman_sweep.run_sweep(sov_root, cosmic_bin=fake2, **clean_fetchers)
    assert env2 is not None
    assert env2["counts"]["items_by_surface"]["honks"] == 1
    item = next(i for i in env2["items"] if i["surface"] == "honks")
    assert item["risk_level"] == "high"
    assert item["preview_state"] == "sanitized"
    assert "synthetic sharp honk" in item["preview"]
