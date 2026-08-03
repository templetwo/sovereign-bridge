"""CLOSURE ROUND — one prove-can-fail test per enumerated fix.

Same discipline as the two files before it: every test runs unmodified against
the pre-fix tree (cf428bf) and fails there on the ASSERTION, not on an import.
Where a test needs a symbol the old tree lacks it is asserted through
run_sweep/sanitize_metadata output instead.

EVERY fixture is SYNTHETIC — invented here, assembled at runtime where it is
credential-shaped, drawn from no queue, no chronicle, no real credential store.
"""

import json

import pytest

import sanitizer
import watchman_sweep
from conftest import (
    SWEEP_ID_PLACEHOLDER,
    all_persisted_text,
    good_reply_for,
    make_fake_cosmic,
    write_proposal,
)

# --- synthetic, assembled at runtime -----------------------------------------
SYNTH_SK = "sk-" + "CLOSURESYNTH" + ("0" * 16)
SYNTH_GHP = "ghp_" + ("A" * 30)
SYNTH_AKIA = "AKIA" + "FAKE0000FAKE0000"
SYNTH_BARE = "deadBEEF0123456789abcdef01234567"  # 32 alnum, digits + letters

# Cyrillic 'с' (U+0441) and 'о' (U+043E) spliced into an ASCII word. BOTH are in
# sanitizer.CONFUSABLES on purpose: fold() maps them back to 'c'/'o', so if the
# mixed-script check ever runs on FOLDED text these canaries silently stop
# testing anything. They are the ordering guard, not just a sample.
MIXED_WORD = "соnfig"
MIXED_BODY = f"routine update: {MIXED_WORD} value adjusted, nothing sensitive"
MIXED_DOMAIN = "generаl"  # Cyrillic 'а'


def dry(sov_root, clean_fetchers, **kw):
    return watchman_sweep.run_sweep(sov_root, dry_run=True, **clean_fetchers, **kw)


def prompt_text(sov_root):
    return "\n".join(
        p.read_text() for p in (sov_root / "watchman").glob("*.dry-run-prompt.txt")
    )


# ============================================================ L1: dict KEYS


def test_a_dict_key_is_sanitized_like_any_other_string():
    """Keys used to be skipped entirely — _collect_string_paths walked
    dict.values() only, so a key was copied VERBATIM into the digest handed to
    xAI. Defence in depth: no surface produces attacker-controlled keys today
    (every key in _extract_meta, scan_comms and the detail blocks is a literal),
    which is exactly why this must be asserted at the sanitizer rather than
    waited for at a surface."""
    safe, ok = sanitizer.sanitize_metadata(
        {"queue": "grok_bridge", f"leaked_{SYNTH_SK}": "synthetic value"}
    )
    assert ok is True
    flat = json.dumps(safe, ensure_ascii=False)
    assert SYNTH_SK not in flat, "a raw credential survived in a metadata KEY"
    assert "queue" in safe, "clean keys must be unaffected"


def test_a_dict_key_is_length_capped_like_any_other_field():
    """200 chars, and the cut is STATED — the same rule values already had. An
    unbounded key is an unbounded shipment exactly like an unbounded value."""
    long_key = "synthetic-key-" + ("q" * 5000)
    safe, ok = sanitizer.sanitize_metadata({long_key: "v"})
    assert ok is True
    # Literal token, not the module constant: a test that reads its expectation
    # out of the module under test proves only that a constant exists.
    key = next(k for k in safe if k != "<pair-unsanitized:omitted>")
    assert len(key.split("…[truncated:")[0]) <= 200
    assert "…[truncated: showing 200 of" in key


def test_a_key_that_cannot_be_cleaned_drops_its_whole_pair(tmp_path):
    """The value is not salvageable without its key: an unnamed value in a
    digest is worse than an omission, because a reader attributes it to the
    wrong field. Both halves drop, and the COUNT travels so two dropped pairs
    cannot collide on one token key and lose one silently."""
    dead = tmp_path / "dead.js"
    dead.write_text("process.exit(2);\n")
    safe, ok = sanitizer.sanitize_metadata(
        {"alpha": "one", "beta": "two", "gamma": "three"}, script_path=dead
    )
    assert ok is False
    assert safe == {"<pair-unsanitized:omitted>": 3}
    assert "alpha" not in safe and "one" not in json.dumps(safe)


# ======================================================= L2: policy strictness


def test_the_shipped_policy_file_still_loads(tmp_path):
    """PERMANENT REGRESSION GUARD. The shipped eyes_policy.json carries a
    `_comment`; a validator that rejected unknown keys without a comment
    carve-out would have closed the eyes on every production sweep, which is a
    worse outage than the typo it was written to catch."""
    from pathlib import Path

    shipped = Path(watchman_sweep.__file__).resolve().parent / "eyes_policy.json"
    policy, state = sanitizer.load_policy(shipped)
    assert state == "loaded", "the SHIPPED policy file must validate"
    assert "antigravity_connector" in policy["denylist_queues"]


def test_the_builtin_seeds_would_themselves_validate():
    """The compiled-in fallback must be able to pass its own schema, or
    'builtin-fallback' would be a state the loader could never reach honestly."""
    assert sanitizer._validate_policy(dict(sanitizer.DEFAULT_POLICY))


@pytest.mark.parametrize(
    "raw,why",
    [
        ({"denylist_domain": ["biomedical"]}, "singular-key typo"),
        ({"denylist_queues": ["a"], "denylist_domain": ["b"]}, "typo alongside good"),
        ({"denylist_queues": {"0": "antigravity_connector"}}, "dict where list"),
        ({"content_terms": {"terms": ["consent"]}}, "dict where list, nested"),
        ({"_comment": "only a comment"}, "no recognized key at all"),
        ({}, "empty object"),
        (
            {
                "denylist_queues": [],
                "denylist_tools": [],
                "denylist_domains": [],
                "content_terms": [],
            },
            "all-empty: an eyes policy with no eyes",
        ),
    ],
)
def test_an_untrustworthy_policy_closes_the_eyes(
    sov_root, clean_fetchers, tmp_path, raw, why
):
    """Each of these used to load as 'loaded' and deny LESS than the author
    intended — a singular-key typo was ignored and its real key defaulted empty;
    an all-empty file was honoured as if emptiness were the intent. A config the
    sweep cannot trust closes the eyes completely and SAYS so."""
    bad = tmp_path / "eyes_policy.json"
    bad.write_text(json.dumps(raw))
    write_proposal(sov_root, "grok_bridge", "p.json", content="synthetic routine body")
    env = dry(sov_root, clean_fetchers, policy_path=bad)
    assert env["policy_state"] == "floor-fallback", why
    assert env["items"][0]["preview_state"] == "metadata-only:denylist"
    assert any(m["ref"].startswith("policy:") for m in env["mechanical_lines"]), (
        "an untrustworthy policy must raise an attend line about the FILE"
    )


def test_a_policy_that_denies_something_still_loads(tmp_path):
    """The strictness must not swing the other way: a real, minimal, valid
    policy still loads."""
    good = tmp_path / "eyes_policy.json"
    good.write_text(json.dumps({"_note": "hi", "denylist_queues": ["some_queue"]}))
    policy, state = sanitizer.load_policy(good)
    assert state == "loaded"
    assert policy["denylist_queues"] == ["some_queue"]


# ==================================================== L3: the surfaces block


def test_a_surface_error_string_is_sanitized_before_it_travels(
    sov_root, clean_fetchers
):
    """The surfaces block goes into the digest handed to Grok, into the spool
    and into latest.md, and NONE of it used to see the redactor. Its strings are
    not house-authored: a surface error is an exception message, and an
    exception message carries whatever the failing call put in it."""
    fetchers = dict(clean_fetchers)

    def boom():
        # Deliberately NOT written as 'token=<secret>': that shape is caught by
        # t2helix's own name-based secret-assign pattern, which would mask the
        # field for a reason unrelated to the fix under test. Inline placement
        # is the honest probe of the watchman's own path.
        raise ConnectionError(f"synthetic bridge failure carrying {SYNTH_SK} inline")

    fetchers["heartbeat_fetch"] = boom
    write_proposal(sov_root, "grok_bridge", "s.json", content="synthetic routine")
    env = watchman_sweep.run_sweep(sov_root, dry_run=True, **fetchers)

    error = env["surfaces"]["heartbeat"]["error"]
    assert SYNTH_SK not in error, "a raw credential travelled in a surface error"
    assert f"<TOKEN-SHAPED:len={len(SYNTH_SK)}>" in error
    assert SYNTH_SK not in prompt_text(sov_root), "...and it reached the digest"
    assert SYNTH_SK not in all_persisted_text(sov_root, env)
    # latest.md is what a human reads; render_latest must see the sanitized copy
    assert SYNTH_SK not in (sov_root / "watchman" / "latest.dry-run.md").read_text()


def test_surface_errors_are_still_reported_when_the_redactor_is_dead(
    sov_root, clean_fetchers, tmp_path
):
    """Guards the fix's own blast radius. Sanitizing the surfaces block means a
    dead redactor collapses it — and the attend lines must NOT be derived from
    that collapsed shape, or the reporting path fails open exactly when the
    instrument is already hurt."""
    fetchers = dict(clean_fetchers)

    def boom():
        raise ConnectionError("synthetic: bridge unreachable")

    fetchers["heartbeat_fetch"] = boom
    dead = tmp_path / "dead.js"
    dead.write_text("process.exit(2);\n")
    env = watchman_sweep.run_sweep(
        sov_root, dry_run=True, sanitize_kwargs={"script_path": dead}, **fetchers
    )
    refs = {m["ref"] for m in env["mechanical_lines"]}
    assert "surface:heartbeat" in refs
    assert env.get("surfaces_sanitized") is False, (
        "the envelope must SAY the surfaces block could not be sanitized"
    )
    # and the render did not blow up on the collapsed block
    assert (
        "Surfaces watched" in (sov_root / "watchman" / "latest.dry-run.md").read_text()
    )


# ================================================ L4: mixed script fails closed


def test_a_mixed_script_token_in_a_body_fails_closed(sov_root, clean_fetchers):
    """MIXED SCRIPT IS THE ACTUAL ATTACK SHAPE and the map cannot be the
    defence: a map only knows the confusables someone remembered to add. This
    body folds to the innocuous word 'config', matches no content term, and
    previewed in full. Now the script mixture ITSELF is the flag."""
    write_proposal(sov_root, "grok_bridge", "mx.json", content=MIXED_BODY)
    env = dry(sov_root, clean_fetchers)
    assert env["items"][0]["preview_state"] == "metadata-only:content-flagged"
    assert "preview" not in env["items"][0]


def test_a_mixed_script_token_in_metadata_fails_closed(sov_root, clean_fetchers):
    """Same rule on the metadata side. 'generаl' folds to 'general' — no
    denylist term, no content term — so nothing else in the build catches it."""
    write_proposal(
        sov_root,
        "grok_bridge",
        "mxmeta.json",
        domain=MIXED_DOMAIN,
        content="synthetic routine body, nothing sensitive",
    )
    env = dry(sov_root, clean_fetchers)
    assert env["items"][0]["preview_state"] == "metadata-only:content-flagged"


CLEAN_META = {
    "queue": "grok_bridge",
    "tool": "propose_insight",
    "filename": "p.json",
    "declared_domain": "general",
}


def _state_for(body, meta=None):
    policy, _ = sanitizer.load_policy()
    return sanitizer.preview_for(body, dict(meta or CLEAN_META), policy)[1]


def test_the_mixed_script_check_runs_on_raw_not_folded_text():
    """THE ORDERING GUARD, asserted through the public decision point so it is
    red on the old tree for the right reason.

    fold() applies the confusables map, so 'соnfig' becomes 'config' and every
    trace of the script mixture is gone. A mixed-script leg that ever sees
    FOLDED input is a silent no-op. This asserts both halves: the raw mixed form
    is withheld, and the folded ASCII form is NOT (so the check cannot be
    'passing' merely by flagging everything)."""
    assert _state_for(f"note about {MIXED_WORD} here") == (
        "metadata-only:content-flagged"
    )
    assert _state_for(f"note about {sanitizer.fold(MIXED_WORD)} here") == "sanitized"


def test_a_pure_single_script_word_is_a_documented_residual_not_a_hit():
    """States the RESIDUAL as a test, so the README's claim is checkable.

    A pure single-script word is NOT mixed and this leg does not see it — an
    all-Cyrillic lookalike is reachable only through the confusables map. Plain
    ASCII and accented Latin must also stay clean, or the eyes close on
    everything and the whole preview mechanism becomes theatre."""
    assert _state_for("routine ррот note, synthetic") == "sanitized"
    assert _state_for("routine café résumé note, synthetic") == "sanitized"
    # ...and the map is what covers the single-script case it happens to know:
    assert "o" in sanitizer.fold("о")


@pytest.mark.parametrize(
    "body,why",
    [
        pytest.param(
            "note about domain-biomedical-assay-protocol-reference-2026 here",
            "a 47-char kebab run the widened base64 class swallows whole",
            id="eaten-by-base64-mask",
        ),
        pytest.param(
            "ref biomedicalassay2026protocolreference00 here",
            "a 38-char high-entropy run the L7 pre-pass swallows whole",
            id="eaten-by-token-pre-pass",
        ),
    ],
)
def test_a_masked_run_cannot_hide_a_content_term_from_the_gate(body, why):
    """THE ONE TEST IN THIS ROUND THAT CATCHES A DEFECT THE ROUND ITSELF
    INTRODUCED.

    Its provenance is the opposite of every other test here, and the difference
    is the point: it is GREEN on cf428bf (the old tree got this right), RED on
    the first closure commit 9019c92, and green again now. Measured, not
    assumed — on cf428bf both probes return metadata-only:content-flagged.

    L6 widened the base64 class to [A-Za-z0-9+/_-] and L7 added a pre-pass, and
    BOTH run upstream of the content gate. A sensitive term living inside a run
    those masks claim is therefore gone before content_flagged() reads it.
    Nothing LEAKS — the run is masked either way — but the item silently loses
    its metadata-only:content-flagged state, and that state is what sets
    flagged_for_richer_review. Fail-closed on disclosure, fail-OPEN on
    signalling: the README calls that flag 'the second net', and this turned it
    off for a whole class of items with nothing saying so.

    The gate reads the RAW window as well as the masked one. That is strictly
    tightening: it can only add flags, never remove one."""
    assert _state_for(body) == "metadata-only:content-flagged", why


def test_masking_tokens_and_markers_never_trip_the_mixed_script_check():
    """The check ignores non-letters, so the build's OWN typed tokens and the
    truncation marker cannot flag every item forever. A defence that fires on
    the artefacts of its own siblings withholds everything and teaches the
    reader to ignore the flag."""
    body = (
        "<TOKEN-SHAPED:len=32> <BASE64-BLOB:len=64> "
        "<field-unsanitized:omitted> <pair-unsanitized:omitted> "
        "[REDACTED:sk-key:2f11ca21] body…[truncated: showing 600 of 2700 chars]"
    )
    assert _state_for(body) == "sanitized"


# ================================================= L5: the ref fallback is gone


def test_a_reply_item_with_only_a_ref_can_never_claim_a_slot(
    sov_root, clean_fetchers, tmp_path
):
    """`ref` is ATTACKER-DERIVED — it is built from a filename or a board
    message id. Matching coverage on it let a reply claim an expected slot by
    echoing a string the item's own source controls. digest_id is the only key
    the watchman mints, so it is the only key coverage may trust."""
    write_proposal(sov_root, "grok_bridge", "refonly.json")
    ref = "grok_bridge/pending_writes/refonly.json"
    reply = json.dumps(
        {
            "identity": "WATCHMAN SWEEP — grok-4.5 via cosmic-cli",
            "sweep_id": SWEEP_ID_PLACEHOLDER,
            "observation": {"summary": "s", "anomalies": []},
            "proposal": {"summary": "n", "actions_proposed": []},
            "items": [
                {
                    "digest_id": "not-a-real-digest-id",
                    "ref": ref,
                    "severity": "info",
                    "reason": "claimed by ref alone",
                    "flagged_for_richer_review": False,
                    "confidence_basis": "n/a",
                }
            ],
        }
    )
    fake, _ = make_fake_cosmic(tmp_path, reply)
    env = watchman_sweep.run_sweep(sov_root, cosmic_bin=fake, **clean_fetchers)

    cov = env["reply_coverage"]
    assert cov["answered"] == 0, "a ref-only judgment claimed an expected slot"
    assert cov["omitted"] == 1 and cov["extra"] == 1
    assert env["grok_reply_state"] == "parsed-partial"
    latest = (sov_root / "watchman" / "latest.md").read_text()
    assert "UNJUDGED (grok-omitted)" in latest, (
        "the render borrowed a judgment onto an item Grok never named"
    )
    assert (
        "claimed by ref alone"
        not in latest.split("## Delta items")[1].split("## Grok")[0]
    )


# ================================================= L6: base64 urlsafe coverage


def test_a_run_mixing_both_base64_alphabets_is_masked():
    """One run carrying '+' and '_' is neither pure-standard nor pure-urlsafe;
    the extended class covers the mixture rather than splitting on it."""
    blob = "AAAA+BBBB_CCCC-DDDD/EEEEFFFFGGGGHHHHIIIIJJJJ"
    assert len(blob) >= sanitizer.BASE64_RUN_MIN
    masked = sanitizer.mask_base64_blobs(f"payload={blob} end")
    assert f"<BASE64-BLOB:len={len(blob)}>" in masked
    assert blob not in masked


# ============================================== L7: glue-char token pre-pass


@pytest.mark.parametrize(
    "glued,secret",
    [
        pytest.param(f"OPENAI_{SYNTH_SK}", SYNTH_SK, id="underscore-glued"),
        pytest.param(f"MYKEY{SYNTH_SK}", SYNTH_SK, id="letter-glued"),
        pytest.param(f"123{SYNTH_SK}", SYNTH_SK, id="digit-glued"),
        pytest.param(f"{SYNTH_GHP}_backup", SYNTH_GHP, id="github-trailing-glue"),
        pytest.param(f"{SYNTH_AKIA}TAIL", SYNTH_AKIA, id="aws-trailing-glue"),
    ],
)
def test_a_word_glued_credential_is_masked_before_the_redactor(
    sov_root, clean_fetchers, glued, secret
):
    """CLOSES THE WATCHMAN'S EGRESS ON AN UPSTREAM GAP IT CANNOT FIX.

    t2helix's patterns anchor on \\b, so a WORD character (letter, digit, '_')
    on the anchored side defeats the match. Verified against the live table:
    every fixture here passes t2helix's scrub() UNCHANGED. Punctuation-glued
    forms ('/sk-…', 'token=sk-…', 'file.sk-….bak') are caught upstream and are
    deliberately not in this list — the claim is about word glue, exactly.

    THE UPSTREAM GAP IS NOT CLOSED BY THIS TEST PASSING: the helix's own write
    path still writes those credentials to its chronicle. This is the watchman's
    egress only, and it is flagged for the Grok helm in the README."""
    write_proposal(
        sov_root,
        "grok_bridge",
        "glue.json",
        content=f"synthetic log line: {glued} trailing text",
    )
    env = dry(sov_root, clean_fetchers)
    item = env["items"][0]
    assert item["preview_state"] == "sanitized"
    assert "<TOKEN-SHAPED:len=" in item["preview"]
    assert secret not in item["preview"]
    assert secret not in all_persisted_text(sov_root, env)
    assert secret not in prompt_text(sov_root)


def test_the_pre_pass_covers_metadata_too(sov_root, clean_fetchers):
    write_proposal(
        sov_root,
        "grok_bridge",
        "gluemeta.json",
        domain=f"general_OPENAI_{SYNTH_SK}",
        content="synthetic routine",
    )
    env = dry(sov_root, clean_fetchers)
    assert SYNTH_SK not in json.dumps(env["items"][0], ensure_ascii=False)
    assert "<TOKEN-SHAPED:len=" in env["items"][0]["declared_domain"]


def test_a_bare_high_entropy_run_is_masked_and_a_repetitive_one_is_not(
    sov_root, clean_fetchers
):
    """'High-entropy' here is a STATED mechanical rule, not Shannon entropy:
    32+ [A-Za-z0-9] carrying at least one digit AND at least one letter.

    The second half is what keeps a long repetitive identifier legible instead
    of masked — including the 5000 q's the metadata-cap test depends on. A rule
    that ate those would have quietly broken a different guarantee (that a
    reader can see WHERE a field was cut) while looking like more security.

    ASSERTED ON METADATA, deliberately. In a PREVIEW a repetitive run of 40+
    base64-alphabet characters is claimed by mask_base64_blobs regardless of
    entropy (pre-existing behaviour, previews only), so a preview cannot show
    the difference. Metadata is where the entropy rule is the only rule."""
    repetitive = "q" * 100
    write_proposal(
        sov_root,
        "grok_bridge",
        "entropy.json",
        domain=f"synthetic-{SYNTH_BARE}",
        tool=f"propose_{repetitive}",
        content="synthetic routine body",
    )
    env = dry(sov_root, clean_fetchers)
    item = env["items"][0]
    assert f"<TOKEN-SHAPED:len={len(SYNTH_BARE)}>" in item["declared_domain"]
    assert SYNTH_BARE not in item["declared_domain"]
    assert repetitive in item["tool"], "a repetitive run must not be masked"


# =========================== L8: the denylisted-body property, corrected scope


DENY_CANARY = "SYNTHETIC-CLOSURE-BODY-CANARY-must-not-reach-the-subprocess"


def _spy(tmp_path):
    """A redactor stand-in that RECORDS its stdin. Marker-file proof: the
    question is not 'was the subprocess called' (it is — metadata sanitization
    calls it for every item) but 'what did it SEE'."""
    capture = tmp_path / "SPY_STDIN_CAPTURE"
    spy = tmp_path / "spy.js"
    spy.write_text(
        "let b=[];process.stdin.on('data',c=>b.push(c));"
        "process.stdin.on('end',()=>{"
        f"require('fs').appendFileSync({json.dumps(str(capture))},"
        "Buffer.concat(b).toString('utf8')+'\\n');"
        "process.stdout.write('[]');process.exit(0);});\n"
    )
    return spy, capture


@pytest.mark.parametrize(
    "queue,name,tool,domain",
    [
        pytest.param(
            "grok_bridge", "ack.json", "comms_acknowledge", "general", id="floor-tool"
        ),
        pytest.param(
            "grok_bridge",
            "protected_x.json",
            "propose_insight",
            "general",
            id="floor-filename",
        ),
        pytest.param(
            "openai_bridge",
            "x.json",
            "propose_insight",
            "consent-ledger",
            id="floor-domain",
        ),
        pytest.param(
            "antigravity_connector",
            "ag.json",
            "propose_insight",
            "general",
            id="policy-queue",
        ),
        pytest.param(
            "openai_bridge",
            "b.json",
            "propose_insight",
            "biomedical",
            id="policy-domain",
        ),
        pytest.param(
            "grok_bridge",
            "hg.json",
            "propose_insight",
            "prоtected-drawer",
            id="homoglyph-domain",
        ),
    ],
)
def test_a_denylisted_body_never_enters_the_subprocess(
    sov_root, clean_fetchers, tmp_path, queue, name, tool, domain
):
    """THE PROPERTY, RESTORED WITH THE CORRECTED SCOPE.

    The original proof was 'the redactor is never called for a denylisted item'.
    That is no longer the invariant: metadata sanitization calls the redactor
    for EVERY item, denylisted or not. The narrower property is the one that
    actually protects anything — the BODY of a denylisted item never enters the
    subprocess — and it is proved by reading what the spy was fed, not by
    string-absence in the output."""
    spy, capture = _spy(tmp_path)
    write_proposal(sov_root, queue, name, tool=tool, domain=domain, content=DENY_CANARY)
    env = dry(sov_root, clean_fetchers, sanitize_kwargs={"script_path": spy})

    assert env["items"][0]["preview_state"] == "metadata-only:denylist"
    assert capture.exists(), "metadata must still go through the redactor"
    assert DENY_CANARY not in capture.read_text(), (
        "a denylisted body was handed to the subprocess"
    )
    assert DENY_CANARY not in all_persisted_text(sov_root, env)


def test_a_body_never_enters_the_subprocess_under_an_untrustworthy_policy(
    sov_root, clean_fetchers, tmp_path
):
    """The property under the L2 ruling, and the case that is RED on the old
    tree: an all-empty policy used to load as 'loaded', so an item matching no
    floor substring was not denylisted and its body went straight to the
    redactor. floor-fallback denies everything, so nothing does."""
    spy, capture = _spy(tmp_path)
    policy = tmp_path / "eyes_policy.json"
    policy.write_text(json.dumps({"denylist_queues": [], "content_terms": []}))
    write_proposal(sov_root, "grok_bridge", "plain.json", content=DENY_CANARY)
    env = dry(
        sov_root,
        clean_fetchers,
        policy_path=policy,
        sanitize_kwargs={"script_path": spy},
    )
    assert env["policy_state"] == "floor-fallback"
    assert env["items"][0]["preview_state"] == "metadata-only:denylist"
    assert capture.exists()
    assert DENY_CANARY not in capture.read_text(), (
        "an untrustworthy policy let a body reach the subprocess"
    )


# ============================================ H1: strict reply shape


DROP = object()


def _reply(**over):
    envelope = {
        "identity": "WATCHMAN SWEEP — grok-4.5 via cosmic-cli",
        "sweep_id": SWEEP_ID_PLACEHOLDER,
        "observation": {"summary": "s", "anomalies": []},
        "proposal": {"summary": "n", "actions_proposed": []},
        "items": [
            {
                "digest_id": "item-0001",
                "ref": "grok_bridge/pending_writes/h1.json",
                "severity": "info",
                "reason": "routine",
                "flagged_for_richer_review": False,
                "confidence_basis": "sanitized preview read directly",
            }
        ],
    }
    for key, value in over.items():
        if value is DROP:
            envelope.pop(key, None)
        else:
            envelope[key] = value
    return json.dumps(envelope)


@pytest.mark.parametrize(
    "over,why",
    [
        pytest.param(
            {"sweep_id": "20200101T000000Z"}, "a stale sweep_id", id="stale-sweep-id"
        ),
        pytest.param({"sweep_id": DROP}, "no sweep_id at all", id="missing-sweep-id"),
        pytest.param(
            {"items": {"item-0001": {}}}, "items is a dict", id="items-not-a-list"
        ),
        pytest.param(
            {"items": ["item-0001"]}, "items are not dicts", id="items-not-dicts"
        ),
        pytest.param(
            {
                "items": [
                    {"ref": "grok_bridge/pending_writes/h1.json", "severity": "info"}
                ]
            },
            "an item without digest_id",
            id="item-without-digest-id",
        ),
    ],
)
def test_a_reply_of_the_wrong_shape_is_quarantined(
    sov_root, clean_fetchers, tmp_path, over, why
):
    """A reply the mechanical tier cannot RECONCILE is not a reply. Accepting a
    stale or shapeless envelope scores it against the wrong digest and reports
    coverage numbers that mean nothing — the fail-open shape, wearing a
    'parsed' label. The raw text is still kept in quarantine; nothing is
    dropped, it is just not believed."""
    write_proposal(sov_root, "grok_bridge", "h1.json")
    fake, _ = make_fake_cosmic(tmp_path, _reply(**over))
    env = watchman_sweep.run_sweep(sov_root, cosmic_bin=fake, **clean_fetchers)

    assert env["grok_reply_state"] == "grok-reply-unparseable", why
    assert env["grok_reply"] is None
    assert env["quarantine_file"], "the raw reply must be kept, never dropped"
    assert "identity" in open(env["quarantine_file"]).read()


def test_a_well_shaped_reply_still_parses(sov_root, clean_fetchers, tmp_path):
    """The strictness must not swing the other way."""
    write_proposal(sov_root, "grok_bridge", "h1.json")
    fake, _ = make_fake_cosmic(tmp_path, _reply())
    env = watchman_sweep.run_sweep(sov_root, cosmic_bin=fake, **clean_fetchers)
    assert env["grok_reply_state"] == "parsed"
    assert env["grok_reply"]["sweep_id"] == env["sweep_id"]


# ============================================ H3: state-save ordering


def test_a_failure_after_collection_leaves_the_high_water_byte_identical(
    sov_root, clean_fetchers, tmp_path, monkeypatch
):
    """AT-LEAST-ONCE. save_state ran BEFORE the mind phase, so anything that
    raised in it consumed the deltas: the next sweep saw unchanged files and
    went quiet. The work was gone and nothing said so — the same permanent-
    blinding shape the sanitizer holdback closes on its own axis."""
    write_proposal(sov_root, "grok_bridge", "first.json")
    fake, _ = make_fake_cosmic(
        tmp_path, good_reply_for(["grok_bridge/pending_writes/first.json"])
    )
    watchman_sweep.run_sweep(sov_root, cosmic_bin=fake, **clean_fetchers)
    state_file = sov_root / "watchman" / "state.json"
    before = state_file.read_bytes()

    write_proposal(sov_root, "grok_bridge", "second.json")

    def boom(prompt, *, cosmic_bin):
        raise RuntimeError("synthetic: injected post-collection failure")

    monkeypatch.setattr(watchman_sweep, "invoke_cosmic", boom)
    try:
        env = watchman_sweep.run_sweep(sov_root, cosmic_bin=fake, **clean_fetchers)
    except RuntimeError:
        env = None

    assert state_file.read_bytes() == before, (
        "the high-water advanced through a sweep that never finished"
    )
    assert env is not None, "the failure must still produce an honest envelope"
    assert env["sweep_error"]
    line = next(
        m for m in env["mechanical_lines"] if m["ref"] == "sweep:partial-failure"
    )
    assert line["severity"] == "attend"
    assert "at-least-once" in line["reason"]
    assert "Comms messages are NOT covered" in line["reason"], (
        "the at-least-once claim must state the surface it does not cover"
    )

    # ...and the delta genuinely re-fires.
    monkeypatch.undo()
    fake2, _ = make_fake_cosmic(
        tmp_path, good_reply_for(["grok_bridge/pending_writes/second.json"])
    )
    again = watchman_sweep.run_sweep(sov_root, cosmic_bin=fake2, **clean_fetchers)
    assert again is not None
    assert "grok_bridge/pending_writes/second.json" in [
        i["ref"] for i in again["items"]
    ]


def test_the_spool_is_written_before_the_state_is_saved(sov_root, clean_fetchers):
    """The ordering itself, asserted where it is cheapest to assert: if the
    spool write raises, nothing was consumed."""
    import spool_writer

    write_proposal(sov_root, "grok_bridge", "ordering.json")
    original = spool_writer.write_sweep

    def refuse(*a, **kw):
        raise OSError("synthetic: spool unwritable")

    spool_writer.write_sweep = refuse
    try:
        with pytest.raises(OSError):
            watchman_sweep.run_sweep(sov_root, dry_run=False, **clean_fetchers)
    finally:
        spool_writer.write_sweep = original
    assert not (sov_root / "watchman" / "state.json").exists()


# ============================================ H4: duplicate demotion


def test_a_duplicated_digest_id_demotes_the_reply(sov_root, clean_fetchers, tmp_path):
    """The label and the arithmetic used to disagree: duplicated_refs raised an
    attend line while grok_reply_state still read 'parsed'. A reader trusting
    the label would have recorded a clean triage over a reply that judged one
    item twice and, in the general case, mixed two verdicts for it."""
    write_proposal(sov_root, "grok_bridge", "dup.json")
    ref = "grok_bridge/pending_writes/dup.json"
    reply = json.dumps(
        {
            "identity": "WATCHMAN SWEEP — grok-4.5 via cosmic-cli",
            "sweep_id": SWEEP_ID_PLACEHOLDER,
            "observation": {"summary": "s", "anomalies": []},
            "proposal": {"summary": "n", "actions_proposed": []},
            "items": [
                {
                    "digest_id": "item-0001",
                    "ref": ref,
                    "severity": "info",
                    "reason": f"judgment {n}",
                    "flagged_for_richer_review": False,
                    "confidence_basis": "sanitized preview read directly",
                }
                for n in (1, 2)
            ],
        }
    )
    fake, _ = make_fake_cosmic(tmp_path, reply)
    env = watchman_sweep.run_sweep(sov_root, cosmic_bin=fake, **clean_fetchers)

    cov = env["reply_coverage"]
    assert env["grok_reply_state"] == "parsed-with-anomalies"
    assert cov["duplicated"] == 1
    assert cov["omitted"] == 0 and cov["extra"] == 0
    # The arithmetic a reader can check without trusting the label:
    assert cov["expected"] == cov["answered"] + cov["omitted"]
    assert cov["reply_items"] == cov["judgments"] + cov["extra"]
    assert cov["reply_items"] == 2 and cov["judgments"] == 2
    dup_line = next(
        m for m in env["mechanical_lines"] if m.get("source") == "grok-duplicate"
    )
    assert "parsed-with-anomalies" in dup_line["reason"]
    assert env["severity_ceiling"] == "attend"


# ============================================ H6: count consistency


def test_counts_come_from_the_items_list_not_from_each_scanner(
    sov_root, clean_fetchers, monkeypatch
):
    """items_by_surface was read back out of each scanner's SELF-REPORTED
    count — a second source that can disagree with the first. A surface that
    raises mid-iteration reports a count for items that never reached the
    digest, and items_by_surface stops summing to items_seen with nothing
    saying why. One source now: the final items list."""
    write_proposal(sov_root, "grok_bridge", "count.json")
    real_scan = watchman_sweep.scan_comms

    def lying_scan(*, comms_fetch):
        surface, items = real_scan(comms_fetch=comms_fetch)
        # Exactly what a mid-iteration failure leaves behind: a count from
        # before the exception, and fewer items than it claims.
        surface["items"] = 7
        return surface, items

    monkeypatch.setattr(watchman_sweep, "scan_comms", lying_scan)
    env = watchman_sweep.run_sweep(sov_root, dry_run=True, **clean_fetchers)
    by_surface = env["counts"]["items_by_surface"]
    assert set(by_surface) == set(watchman_sweep.SURFACE_NAMES)
    assert sum(by_surface.values()) == env["counts"]["items_seen"], (
        "items_by_surface must sum to items_seen from ONE source"
    )
    assert by_surface["comms"] == 0
    assert all(i["surface"] in watchman_sweep.SURFACE_NAMES for i in env["items"])


# ============================================ C1: single-instance lock


def test_an_overlapping_invocation_exits_zero_and_touches_nothing(
    sov_root, clean_fetchers, monkeypatch, tmp_path
):
    """launchd fires this script on BOTH a WatchPaths trigger and a slow
    StartInterval, so two sweeps can overlap on a busy queue. Two live sweeps
    race the same high-water file and can each half-advance it — a silent
    data-loss shape, not a performance one."""
    import fcntl
    import os

    write_proposal(sov_root, "grok_bridge", "locked.json")
    # No network from the guarded path: the bridge points at a dead port and
    # the stack repo at an empty dir, so nothing leaves this machine even if
    # the guard were to fail open.
    monkeypatch.setenv("BRIDGE_URL", "http://127.0.0.1:9")
    monkeypatch.setenv("SOVEREIGN_STACK_REPO", str(tmp_path / "not-a-repo"))

    lock_path = sov_root / "watchman" / "sweep.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    holder = os.open(str(lock_path), os.O_RDWR | os.O_CREAT, 0o644)
    fcntl.flock(holder, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        rc = watchman_sweep.main(["--root", str(sov_root)])
    finally:
        fcntl.flock(holder, fcntl.LOCK_UN)
        os.close(holder)

    assert rc == 0, "a correct skip must not read to launchd as a failure"
    wd = sov_root / "watchman"
    assert not (wd / "state.json").exists(), "the skipped sweep touched state"
    assert not (wd / "spool.jsonl").exists(), "the skipped sweep wrote the spool"
    assert not (wd / "latest.md").exists()
    assert "sweep already live, skipping" in (wd / "watchman.log").read_text()


def test_the_lock_is_released_so_the_next_invocation_runs(
    sov_root, clean_fetchers, monkeypatch, tmp_path
):
    """A lock that is never released is an outage, not a guard."""
    monkeypatch.setenv("BRIDGE_URL", "http://127.0.0.1:9")
    monkeypatch.setenv("SOVEREIGN_STACK_REPO", str(tmp_path / "not-a-repo"))
    write_proposal(sov_root, "grok_bridge", "seq.json")

    assert watchman_sweep.main(["--root", str(sov_root)]) == 0
    assert (sov_root / "watchman" / "state.json").exists()
    # Second invocation acquires cleanly and runs again — proven by the log
    # gaining a real sweep line rather than a skip line.
    assert watchman_sweep.main(["--root", str(sov_root)]) == 0
    log = (sov_root / "watchman" / "watchman.log").read_text()
    assert "sweep already live, skipping" not in log
    assert len(log.strip().splitlines()) == 2
