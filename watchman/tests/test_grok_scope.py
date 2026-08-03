"""Backlog-drain scale guard: Grok classifies at most the cap per sweep, the
envelope says exactly what was classified vs mechanical-only, and coverage is
computed against the capped set (found at the 2026-08-03 baptism: a 200-item
digest blew the invocation timeout)."""

import watchman_sweep
from conftest import good_reply_for, make_fake_cosmic, write_proposal


def test_cap_limits_what_grok_sees_and_envelope_says_so(
    sov_root, clean_fetchers, tmp_path, monkeypatch
):
    monkeypatch.setenv("WATCHMAN_GROK_ITEM_CAP", "2")
    for i in range(4):
        write_proposal(sov_root, "grok_bridge", f"cap{i}.json")
    refs = [f"grok_bridge/pending_writes/cap{i}.json" for i in range(2)]
    fake, log = make_fake_cosmic(tmp_path, good_reply_for(refs))
    env = watchman_sweep.run_sweep(sov_root, cosmic_bin=fake, **clean_fetchers)
    assert env["grok_scope"] == {"cap": 2, "classified": 2, "mechanical_only": 2}
    cov = env["reply_coverage"]
    assert cov["expected"] == 2, "coverage reconciles against the CAPPED set"
    assert env["grok_reply_state"] == "parsed"
    assert len(env["items"]) == 4, "every item still lands in the spool"


def test_filesystem_items_outrank_comms_under_the_cap(
    sov_root, clean_fetchers, tmp_path, monkeypatch
):
    monkeypatch.setenv("WATCHMAN_GROK_ITEM_CAP", "1")
    write_proposal(sov_root, "grok_bridge", "signal.json")
    fetchers = dict(clean_fetchers)
    fetchers["comms_fetch"] = lambda: {
        "channel": "general",
        "messages": [
            {
                "id": "m1",
                "sender": "daemon.synthetic",
                "content": "synthetic backlog chatter",
                "read_by": [],
            }
        ],
        "count": 1,
    }
    ref = "grok_bridge/pending_writes/signal.json"
    fake, log = make_fake_cosmic(tmp_path, good_reply_for([ref]))
    env = watchman_sweep.run_sweep(sov_root, cosmic_bin=fake, **fetchers)
    assert env["grok_scope"]["classified"] == 1
    judged = [i["digest_id"] for i in (env.get("grok_reply") or {}).get("items", [])]
    item_by_id = {i["digest_id"]: i for i in env["items"]}
    assert judged and item_by_id[judged[0]]["surface"] != "comms", (
        "the one classified slot goes to the filesystem signal, not backlog"
    )
