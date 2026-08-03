"""The eyes policy, fail-closed in all three directions, plus synthetic-secret
redaction. Every credential-shaped and biomed-shaped string here is INVENTED
for this test — drawn from no queue, no chronicle, no real system."""

import json
from pathlib import Path

import pytest

import sanitizer
import watchman_sweep
from conftest import (
    all_persisted_text,
    good_reply_for,
    make_fake_cosmic,
    write_proposal,
)

T2HELIX_ROOT = Path.home() / "t2helix"
needs_t2helix = pytest.mark.skipif(
    not (T2HELIX_ROOT / "lib" / "secrets.js").exists(),
    reason="t2helix secrets.js not present on this machine",
)

# SYNTHETIC fixtures — invented shapes, not real values.
SYNTH_SK_KEY = "sk-SYNTHFAKE00000000000000000000"
SYNTH_AWS_KEY = "AKIAFAKEFAKEFAKEFAKE"
SYNTH_ASSIGN = 'api_key = "SYNTH-not-real-000111"'
SYNTH_BIOMED = (
    "SYNTHETIC-BIOMED-MARKER: plasmid vector pUC-FAKE-19, synthetic titer 1e9 "
    "(invented string, no real protocol)"
)


# all_persisted_text lives in conftest now — a RECURSIVE glob over everything
# under <root>/watchman/. The enumerated version this replaced would have gone
# blind to the dry-run output files the moment they were added.


# ---------------------------------------------------------- direction (a): denylist


def test_denylist_queue_yields_metadata_only(sov_root, clean_fetchers, tmp_path):
    write_proposal(
        sov_root,
        "antigravity_connector",
        "prop_ag.json",
        content=SYNTH_BIOMED,
    )
    fake, _ = make_fake_cosmic(
        tmp_path,
        good_reply_for(["antigravity_connector/pending_writes/prop_ag.json"]),
    )
    env = watchman_sweep.run_sweep(sov_root, cosmic_bin=fake, **clean_fetchers)
    item = env["items"][0]
    assert item["preview_state"] == "metadata-only:denylist"
    assert "preview" not in item
    assert SYNTH_BIOMED not in all_persisted_text(sov_root, env)
    # metadata still travels
    assert item["tool"] == "propose_insight"
    assert item["size"] > 0


def test_denylist_floor_tool_and_names(sov_root, clean_fetchers, tmp_path):
    write_proposal(
        sov_root,
        "grok_bridge",
        "ack.json",
        tool="comms_acknowledge",
        content="synthetic ack body",
    )
    write_proposal(
        sov_root,
        "grok_bridge",
        "protected_item.json",
        content="synthetic protected body",
    )
    write_proposal(
        sov_root,
        "openai_bridge",
        "prop_bio.json",
        domain="biomedical",
        content=SYNTH_BIOMED,
    )
    fake, _ = make_fake_cosmic(tmp_path, good_reply_for([]))
    env = watchman_sweep.run_sweep(sov_root, cosmic_bin=fake, **clean_fetchers)
    states = {i["filename"]: i["preview_state"] for i in env["items"]}
    assert states["ack.json"] == "metadata-only:denylist"
    assert states["protected_item.json"] == "metadata-only:denylist"
    assert states["prop_bio.json"] == "metadata-only:denylist"
    persisted = all_persisted_text(sov_root, env)
    assert SYNTH_BIOMED not in persisted
    assert "synthetic protected body" not in persisted
    assert env["counts"]["items_metadata_only"]["denylist"] == 3


def test_floor_survives_a_policy_that_denies_almost_nothing(tmp_path):
    """UPDATED for the L2 strictness ruling. This used to write an ALL-empty
    policy and assert 'loaded'; an all-empty policy now falls to the floor (see
    test_an_all_empty_policy_falls_to_the_floor). The property under test here
    is different and still worth guarding: a policy that validates and denies
    almost nothing must STILL not be able to switch the protected/consent floor
    off, so the file keeps exactly one entry and empties the rest."""
    empty_policy = tmp_path / "eyes_policy.json"
    empty_policy.write_text(
        json.dumps(
            {
                "denylist_queues": [],
                "denylist_tools": [],
                "denylist_domains": ["some-unrelated-synthetic-domain"],
                "content_terms": [],
            }
        )
    )
    policy, state = sanitizer.load_policy(empty_policy)
    assert state == "loaded"
    assert sanitizer.denylisted(
        {
            "queue": "grok_bridge",
            "tool": None,
            "filename": "consent_ledger.json",
            "declared_domain": "general",
        },
        policy,
    ), "the protected/consent floor must hold even when the config denies nothing"
    assert sanitizer.denylisted(
        {
            "queue": "grok_bridge",
            "tool": "comms_acknowledge",
            "filename": "x.json",
            "declared_domain": None,
        },
        policy,
    )


def test_missing_policy_file_falls_back_to_builtin(tmp_path):
    policy, state = sanitizer.load_policy(tmp_path / "does_not_exist.json")
    assert state == "builtin-fallback"
    assert policy == sanitizer.DEFAULT_POLICY


# ------------------------------------------- direction (b): sanitizer subprocess


def _js(tmp_path, name, source):
    p = tmp_path / name
    p.write_text(source)
    return p


def test_sanitizer_timeout_yields_metadata_only(sov_root, clean_fetchers, tmp_path):
    slow = _js(tmp_path, "slow.js", "setTimeout(() => process.exit(0), 5000);\n")
    write_proposal(sov_root, "grok_bridge", "prop_slow.json", content=SYNTH_SK_KEY)
    fake, _ = make_fake_cosmic(tmp_path, good_reply_for([]))
    env = watchman_sweep.run_sweep(
        sov_root,
        cosmic_bin=fake,
        sanitize_kwargs={"script_path": slow, "timeout": 0.3},
        **clean_fetchers,
    )
    item = env["items"][0]
    assert item["preview_state"] == "metadata-only:sanitizer-failed"
    assert "preview" not in item
    assert SYNTH_SK_KEY not in all_persisted_text(sov_root, env)
    assert env["counts"]["items_metadata_only"]["sanitizer-failed"] == 1


def test_sanitizer_nonzero_exit_yields_metadata_only(
    sov_root, clean_fetchers, tmp_path
):
    dead = _js(tmp_path, "dead.js", "process.exit(2);\n")
    write_proposal(sov_root, "grok_bridge", "prop_dead.json", content=SYNTH_AWS_KEY)
    fake, _ = make_fake_cosmic(tmp_path, good_reply_for([]))
    env = watchman_sweep.run_sweep(
        sov_root,
        cosmic_bin=fake,
        sanitize_kwargs={"script_path": dead},
        **clean_fetchers,
    )
    item = env["items"][0]
    assert item["preview_state"] == "metadata-only:sanitizer-failed"
    assert SYNTH_AWS_KEY not in all_persisted_text(sov_root, env)


def test_sanitizer_echoing_nothing_is_a_failure(tmp_path):
    # A script that exits 0 but emits nothing did not run the patterns.
    silent = _js(tmp_path, "silent.js", "process.exit(0);\n")
    out, state = sanitizer.run_redactor("some non-empty body", script_path=silent)
    assert out is None
    assert state == "sanitizer-failed"


# ------------------------------------------------ direction (c): unparseable file


def test_garbage_file_yields_metadata_only(sov_root, clean_fetchers, tmp_path):
    garbage = sov_root / "grok_bridge" / "pending_writes" / "garbage.json"
    garbage.write_text("{this is not json" + SYNTH_ASSIGN)
    fake, _ = make_fake_cosmic(tmp_path, good_reply_for([]))
    env = watchman_sweep.run_sweep(sov_root, cosmic_bin=fake, **clean_fetchers)
    item = env["items"][0]
    assert item["preview_state"] == "metadata-only:unparseable"
    assert "preview" not in item
    assert "SYNTH-not-real-000111" not in all_persisted_text(sov_root, env)
    assert env["counts"]["items_metadata_only"]["unparseable"] == 1


# ------------------------------------------------------- synthetic-secret redaction


@needs_t2helix
def test_synthetic_secrets_become_type_tokens(sov_root, clean_fetchers):
    """UPDATED for the L7 pre-pass, and the update matters.

    The watchman now masks token-shaped runs BEFORE handing anything to the
    redactor, so the two prefix-bearing keys are claimed by the pre-pass and
    render as <TOKEN-SHAPED:len=N> rather than [REDACTED:sk-key:...]. Both
    still leave, and neither plaintext travels.

    THE `secret-assign` LEG IS LOAD-BEARING AND MUST STAY: 'SYNTH-not-real-
    000111' carries no known prefix and is far short of the 32-char bare-run
    rule, so the pre-pass leaves it alone and only the t2helix redactor can
    catch it. It is now the ONLY assertion in this suite proving the redactor
    actually ran and was not silently bypassed — delete it and a broken node
    path becomes invisible here."""
    body = (
        f"synthetic config dump: {SYNTH_ASSIGN}\n"
        f"key one {SYNTH_SK_KEY} and key two {SYNTH_AWS_KEY} end\n"
    )
    write_proposal(sov_root, "grok_bridge", "prop_secrets.json", content=body)
    # Dry run: full mechanical sweep, prompt saved, no cosmic — proves the
    # plaintext never reaches the Grok handoff surface either.
    env = watchman_sweep.run_sweep(sov_root, dry_run=True, **clean_fetchers)
    item = env["items"][0]
    assert item["preview_state"] == "sanitized"
    preview = item["preview"]
    assert f"<TOKEN-SHAPED:len={len(SYNTH_SK_KEY)}>" in preview
    assert f"<TOKEN-SHAPED:len={len(SYNTH_AWS_KEY)}>" in preview
    assert "[REDACTED:secret-assign:" in preview, (
        "the t2helix redactor did not run — this is the only leg that proves it"
    )
    persisted = all_persisted_text(sov_root, env)
    for raw in (SYNTH_SK_KEY, SYNTH_AWS_KEY, "SYNTH-not-real-000111"):
        assert raw not in persisted, (
            f"plaintext {raw!r} escaped into a persisted surface"
        )


@needs_t2helix
def test_preview_truncates_after_redaction_not_before(clean_fetchers):
    # A secret placed just before the 600-char line: truncate-first would cut
    # it mid-token and the pattern would miss the fragment. We redact a wide
    # window first, then truncate, so the token (not the plaintext) survives.
    # Filler is space-broken on purpose: an unbroken run of 590 base64-alphabet
    # chars is now masked as a <BASE64-BLOB:len=N> token, which would move the
    # secret away from the cut and quietly stop testing the boundary.
    body = ("xy " * 197) + " " + SYNTH_SK_KEY + " tail"
    assert len(body) > sanitizer.PREVIEW_CHARS
    policy, _ = sanitizer.load_policy()
    preview, state = sanitizer.preview_for(
        body,
        {
            "queue": "grok_bridge",
            "tool": "propose_insight",
            "filename": "p.json",
            "declared_domain": "general",
        },
        policy,
    )
    assert state == "sanitized"
    assert SYNTH_SK_KEY not in preview
    # The shown body is capped; the marker rides on top and SAYS it was cut.
    assert preview.endswith(f"of {len(body)} chars]")
    shown = preview.split("…[truncated:")[0]
    assert len(shown) <= sanitizer.PREVIEW_CHARS
