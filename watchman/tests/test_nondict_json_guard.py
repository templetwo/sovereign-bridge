"""Non-dict JSON guard (COMMIT 1).

json.loads() on a SYNTACTICALLY VALID line like `null`, `42`, `"x"`, `true`,
or `[1, 2]` succeeds and returns a non-dict. Calling `.get()` on the result
raises an uncaught AttributeError. Five sites do this unguarded:
scan_handoffs, scan_honks (baseline loop), scan_honks (incremental loop),
_load_ack_ids, and load_state. The honks-loop sites are covered in
test_honks_surface.py; this file covers the other three, plus two
end-to-end run_sweep reproductions of the actual failure mode: the
collectors run before any log_line or save_state, so an unguarded crash
here kills the sweep having written NOTHING, and because the high-water
mark never advances, the SAME poison line re-crashes every sweep forever
until a human deletes it.

These are syntactically VALID JSON, unlike the pre-existing
`test_corrupt_line_is_counted_never_silent` (which writes `{not json`, a
SYNTAX error only) — that is exactly why the syntax-only test does not
catch this defect.
"""

import json

import watchman_sweep
from conftest import good_reply_for, make_fake_cosmic, write_handoff

NON_DICT_JSON_LINES = ["null", "42", '"x"', "true", "[1, 2]"]


def _write_raw(path, lines):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        for ln in lines:
            f.write(ln + "\n")


# ---------------------------------------------------------------- scan_handoffs


def test_scan_handoffs_survives_non_dict_json(sov_root):
    write_handoff(sov_root, "good.json", consumed_at=None)
    for i, raw in enumerate(NON_DICT_JSON_LINES):
        (sov_root / "handoffs" / f"poison{i}.json").write_text(raw, encoding="utf-8")
    surface, items, unconsumed = watchman_sweep.scan_handoffs(sov_root, {})
    assert surface["ok"] is True
    assert unconsumed == 1, "only the one real dict handoff counts as unconsumed"
    assert "corrupt" in surface["note"], (
        "a non-dict handoff must be REPORTED, not silently dropped from the "
        "unconsumed count while the surface still says ok"
    )
    assert str(len(NON_DICT_JSON_LINES)) in surface["note"]


def test_scan_handoffs_counts_syntax_errors_too(sov_root):
    """Pre-existing behaviour silently `continue`s past a JSONDecodeError
    with no counter at all. The fix must fold this in, not just the new
    non-dict case."""
    write_handoff(sov_root, "good.json", consumed_at=None)
    (sov_root / "handoffs" / "bad.json").write_text("{not json", encoding="utf-8")
    surface, items, unconsumed = watchman_sweep.scan_handoffs(sov_root, {})
    assert unconsumed == 1
    assert "corrupt" in surface["note"] and "1" in surface["note"]


def test_run_sweep_survives_poison_handoff_and_advances_state(
    sov_root, clean_fetchers, tmp_path
):
    """End-to-end reproduction of the PERMANENT crash: a poison handoff line
    must not kill the sweep, and the high-water mark must still advance so
    the same line does not re-crash every 30 minutes forever."""
    write_handoff(sov_root, "good.json", consumed_at=None)
    (sov_root / "handoffs" / "poison.json").write_text("null", encoding="utf-8")
    fake, log = make_fake_cosmic(tmp_path, good_reply_for([]))
    watchman_sweep.run_sweep(sov_root, cosmic_bin=fake, **clean_fetchers)  # must not raise
    state = json.loads((sov_root / "watchman" / "state.json").read_text())
    assert state["handoffs_unconsumed"] == 1
    assert state["sweeps"] == 1


# ---------------------------------------------------------------- load_state


def test_load_state_survives_non_dict_top_level(sov_root):
    sp = sov_root / "watchman" / "state.json"
    sp.parent.mkdir(parents=True, exist_ok=True)
    sp.write_text("null", encoding="utf-8")
    state = watchman_sweep.load_state(sov_root)
    assert isinstance(state, dict), (
        "a state.json whose top-level value is `null` parses cleanly via "
        "json.loads and must fall back to the default dict, not None"
    )
    assert state.get("files") == {}


def test_run_sweep_survives_non_dict_state_json(sov_root, clean_fetchers, tmp_path):
    sp = sov_root / "watchman" / "state.json"
    sp.parent.mkdir(parents=True, exist_ok=True)
    sp.write_text("42", encoding="utf-8")
    fake, log = make_fake_cosmic(tmp_path, good_reply_for([]))
    watchman_sweep.run_sweep(sov_root, cosmic_bin=fake, **clean_fetchers)  # must not raise
    state = json.loads(sp.read_text())
    assert isinstance(state, dict)


# ---------------------------------------------------------------- _load_ack_ids


def test_load_ack_ids_survives_non_dict_lines(sov_root):
    apath = sov_root / "nape" / "acks.jsonl"
    _write_raw(apath, NON_DICT_JSON_LINES + [json.dumps({"honk_id": "real1"})])
    ids = watchman_sweep._load_ack_ids(apath)
    assert ids == {"real1"}


def test_load_ack_ids_skips_missing_honk_id_instead_of_none(sov_root):
    """Micro-defect, same family: adding None to the ack-id set for a record
    missing honk_id means any honk that ALSO lacks honk_id reads as already
    acked and is silently skipped."""
    apath = sov_root / "nape" / "acks.jsonl"
    _write_raw(apath, [json.dumps({"note": "malformed ack, no honk_id"})])
    ids = watchman_sweep._load_ack_ids(apath)
    assert None not in ids
    assert ids == set()
