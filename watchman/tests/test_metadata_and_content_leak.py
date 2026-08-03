"""Leak-hunt closure — findings 1, 2, 5, 6, 7, 8.

Every one of these is a PROVE-CAN-FAIL test: written to run unmodified against
the pre-fix tree (8adec9b) and fail there on the assertion, not on an import.
They therefore assert on run_sweep OUTPUT and on persisted bytes, never on a
symbol the old tree does not have. The literal tokens ('<field-unsanitized:
omitted>', 'metadata-only:content-flagged', '<BASE64-BLOB:len=', 'metadata-only:
empty-body', '…[truncated: showing') are asserted as strings for that reason.

EVERY fixture is SYNTHETIC — invented for these tests, assembled at runtime
where it is credential-shaped, drawn from no queue, no chronicle, no real
credential store.
"""

import json

import pytest

import watchman_sweep
from conftest import all_persisted_text, dead_script, write_proposal

# Assembled at runtime: a literal credential-shaped string in a source file is
# the shape the t2helix Bash gate correctly PAUSEs on.
SYNTH_KEY = "sk-" + "SYNTHMETA" + ("0" * 20)
SYNTH_B64_INNER = "sk-" + "SYNTHB64" + ("0" * 21)
SYNTH_B64 = "c2stU1lOVEhCNjQwMDAwMDAwMDAwMDAwMDAwMDAwMDA"  # 43 base64 chars

SYNTH_BIOMED_UNDECLARED = (
    "Routine ops note. Reviewing the run we noticed the SYNTHETIC-REDTEAM-MARKER "
    "assay used plasmid vector pUC-NOTREAL-19 at an invented titer of 1e9. "
    "Nothing else to report."
)
SYNTH_CONSENT_UNDECLARED = (
    "SYNTHETIC-CONSENT-CANARY: the participant stated they did not consent to "
    "having this recorded and asked that it never be repeated to another system."
)
# Cyrillic 'о' (U+043E) substituted into the ASCII word "protected".
HOMOGLYPH_DOMAIN = "prоtected-drawer"


def dry_sweep(sov_root, clean_fetchers, **kw):
    """Dry runs are the honest probe here: they build the full digest and write
    the prompt Grok WOULD have received, without a cosmic call and (post-fix)
    without touching state."""
    return watchman_sweep.run_sweep(sov_root, dry_run=True, **clean_fetchers, **kw)


def prompt_text(sov_root):
    return "\n".join(
        p.read_text() for p in (sov_root / "watchman").glob("*.dry-run-prompt.txt")
    )


# ============================================ finding 1: unsanitized metadata


def test_secret_in_declared_domain_never_reaches_a_persisted_byte(
    sov_root, clean_fetchers
):
    """THE HEADLINE LEAK. Metadata was copied VERBATIM out of an untrusted file
    and travelled to xAI in argv, in the prompt, and into the spool. Credentials
    landing in the wrong field is exactly why t2helix scrubs at four write
    chokepoints rather than one."""
    write_proposal(
        sov_root,
        "grok_bridge",
        "metafield.json",
        domain=f"general {SYNTH_KEY}",
        content="synthetic body with nothing sensitive in it",
    )
    env = dry_sweep(sov_root, clean_fetchers)
    item = env["items"][0]

    assert SYNTH_KEY not in item["declared_domain"], (
        "the raw key survived in the metadata handed to the mind"
    )
    assert "[REDACTED:" in item["declared_domain"]
    assert SYNTH_KEY not in all_persisted_text(sov_root, env)
    assert SYNTH_KEY not in prompt_text(sov_root)


def test_secret_in_comms_sender_never_reaches_a_persisted_byte(
    sov_root, clean_fetchers
):
    """The comms surface builds its own metadata dict; `sender` is whatever the
    board says it is."""
    fetchers = dict(clean_fetchers)
    fetchers["comms_fetch"] = lambda: {
        "channel": "general",
        "messages": [
            {
                "id": "m-synth-9",
                "sender": f"impostor {SYNTH_KEY}",
                "timestamp": "1785700000.0",
                "content": "synthetic board message, routine",
            }
        ],
        "count": 1,
    }
    env = watchman_sweep.run_sweep(sov_root, dry_run=True, **fetchers)
    item = next(i for i in env["items"] if i["queue"].startswith("comms"))
    assert SYNTH_KEY not in item["sender"]
    assert SYNTH_KEY not in all_persisted_text(sov_root, env)


def test_secret_in_filename_is_redacted_in_the_travelling_metadata(
    sov_root, clean_fetchers
):
    """filename and ref both travel to the mind. (state.json legitimately keeps
    the real name as its high-water key — that file never leaves the machine
    and is not part of the digest, so the assertion is scoped to the item.)"""
    write_proposal(
        sov_root,
        "grok_bridge",
        f"{SYNTH_KEY}.json",
        content="synthetic body, routine",
    )
    env = dry_sweep(sov_root, clean_fetchers)
    item = env["items"][0]
    assert SYNTH_KEY not in item["filename"]
    assert SYNTH_KEY not in item["ref"]
    assert SYNTH_KEY not in prompt_text(sov_root)


def test_metadata_fields_are_length_capped_with_an_explicit_marker(
    sov_root, clean_fetchers
):
    """An unbounded metadata field is an unbounded shipment. 200 chars, and the
    cut is stated — silent truncation is the silent-partial class."""
    long_domain = "synthetic-domain-" + ("q" * 5000)
    write_proposal(
        sov_root,
        "grok_bridge",
        "longmeta.json",
        domain=long_domain,
        content="synthetic body, routine",
    )
    env = dry_sweep(sov_root, clean_fetchers)
    item = env["items"][0]
    # 200 as a LITERAL, not sanitizer.METADATA_FIELD_CHARS: a test that reads
    # the cap from the module under test proves only that a constant exists.
    shown = item["declared_domain"].split("…[truncated:")[0]
    assert len(shown) <= 200
    assert "…[truncated: showing 200 of" in item["declared_domain"]
    assert len(item["declared_domain"]) < len(long_domain)
    # The marker names the ORIGINAL length, so the reader can size what was cut.
    assert f"of {len(long_domain)} chars]" in item["declared_domain"]


def test_metadata_redactor_failure_omits_the_field_it_cannot_clean(
    sov_root, clean_fetchers, tmp_path
):
    """FAIL CLOSED, never verbatim. If the redactor cannot clean a metadata
    field, the field is replaced by a typed token that says so."""
    canary = "SYNTHETIC-METAFIELD-CANARY"
    write_proposal(
        sov_root,
        "grok_bridge",
        "cannot_clean.json",
        tool=f"propose_insight_{canary}",
        content="synthetic body, routine",
    )
    env = dry_sweep(
        sov_root,
        clean_fetchers,
        sanitize_kwargs={"script_path": dead_script(tmp_path)},
    )
    item = env["items"][0]
    assert item["tool"] == "<field-unsanitized:omitted>"
    assert item["metadata_sanitized"] is False
    assert canary not in all_persisted_text(sov_root, env)


# ======================================= finding 2: the denylist CONTENT leg


def test_biomed_content_declared_general_is_withheld(sov_root, clean_fetchers):
    """The denylist gated DECLARATIONS, not content: a body is previewed in
    full whenever its sensitivity is not self-declared in metadata."""
    write_proposal(
        sov_root,
        "grok_bridge",
        "innocuous.json",
        domain="general",
        content=SYNTH_BIOMED_UNDECLARED,
    )
    env = dry_sweep(sov_root, clean_fetchers)
    item = env["items"][0]
    assert item["preview_state"] == "metadata-only:content-flagged"
    assert "preview" not in item
    assert "pUC-NOTREAL-19" not in all_persisted_text(sov_root, env)
    assert env["counts"]["items_metadata_only"]["content-flagged"] == 1


def test_consent_assertion_shaped_as_an_ordinary_insight_is_withheld(
    sov_root, clean_fetchers
):
    write_proposal(
        sov_root,
        "grok_bridge",
        "ordinary_note.json",
        domain="general",
        content=SYNTH_CONSENT_UNDECLARED,
    )
    env = dry_sweep(sov_root, clean_fetchers)
    item = env["items"][0]
    assert item["preview_state"] in (
        "metadata-only:content-flagged",
        "metadata-only:denylist",
    )
    assert "SYNTHETIC-CONSENT-CANARY" not in all_persisted_text(sov_root, env)


def test_comms_surface_now_has_content_coverage(sov_root, clean_fetchers):
    """SHARPEST FORM of the finding: scan_comms sets tool=None and
    declared_domain=None, so the only reachable floor was the message id. The
    comms surface — the one carrying the live 50+ unread backlog — had
    effectively ZERO denylist coverage."""
    fetchers = dict(clean_fetchers)
    fetchers["comms_fetch"] = lambda: {
        "channel": "general",
        "messages": [
            {
                "id": 4001,
                "sender": "daemon.uncertainty",
                "timestamp": "1785700000.0",
                "content": SYNTH_CONSENT_UNDECLARED,
            },
            {
                "id": 4002,
                "sender": "daemon.metabolize",
                "timestamp": "1785700000.0",
                "content": SYNTH_BIOMED_UNDECLARED,
            },
        ],
        "count": 2,
    }
    env = watchman_sweep.run_sweep(sov_root, dry_run=True, **fetchers)
    assert all(i["preview_state"].startswith("metadata-only:") for i in env["items"])
    text = all_persisted_text(sov_root, env)
    assert "SYNTHETIC-CONSENT-CANARY" not in text
    assert "pUC-NOTREAL-19" not in text


def test_halt_file_body_is_not_previewed_wholesale(sov_root, clean_fetchers):
    """A non-.json halt file has no tool and no declared domain, so its whole
    body used to preview."""
    (sov_root / "daemons" / "halts" / "daemon.halt").write_text(
        SYNTH_CONSENT_UNDECLARED + "\n" + SYNTH_BIOMED_UNDECLARED
    )
    env = dry_sweep(sov_root, clean_fetchers)
    item = env["items"][0]
    assert item["preview_state"].startswith("metadata-only:")
    assert "SYNTHETIC-CONSENT-CANARY" not in all_persisted_text(sov_root, env)


def test_nested_arguments_list_no_longer_bypasses_the_gate(sov_root, clean_fetchers):
    """`arguments` as a LIST leaves declared_domain None even though the JSON
    declares 'biomedical', and the body falls back to the RAW JSON text."""
    (sov_root / "grok_bridge" / "pending_writes" / "listargs.json").write_text(
        json.dumps(
            {
                "tool": "propose_insight",
                "arguments": [
                    {"domain": "biomedical", "content": SYNTH_BIOMED_UNDECLARED}
                ],
            }
        )
    )
    env = dry_sweep(sov_root, clean_fetchers)
    item = env["items"][0]
    assert item["declared_domain"] is None, "premise: the declaration leg is blind here"
    assert item["preview_state"] == "metadata-only:content-flagged"
    assert "pUC-NOTREAL-19" not in all_persisted_text(sov_root, env)


# =============================================== finding 5: homoglyph bypass


def test_homoglyph_cannot_walk_past_the_protected_floor(sov_root, clean_fetchers):
    """One codepoint used to defeat a floor described as un-turn-off-able:
    denylisted() did a plain ASCII `in` against a .lower()-ed string."""
    write_proposal(
        sov_root,
        "grok_bridge",
        "hg.json",
        domain=HOMOGLYPH_DOMAIN,
        content=SYNTH_CONSENT_UNDECLARED,
    )
    env = dry_sweep(sov_root, clean_fetchers)
    item = env["items"][0]
    assert item["preview_state"] == "metadata-only:denylist"
    assert "SYNTHETIC-CONSENT-CANARY" not in all_persisted_text(sov_root, env)


def test_homoglyph_in_a_body_term_is_also_folded(sov_root, clean_fetchers):
    """Folding is applied to the content leg too, not just to metadata."""
    body = "Routine note about a plаsmid vector, synthetic."  # Cyrillic 'а'
    write_proposal(sov_root, "grok_bridge", "hgbody.json", content=body)
    env = dry_sweep(sov_root, clean_fetchers)
    assert env["items"][0]["preview_state"] == "metadata-only:content-flagged"


# ================================================= finding 6: base64 blobs


def test_base64_runs_are_masked_before_truncation(sov_root, clean_fetchers):
    """Watchman-side mitigation of an UPSTREAM t2helix limit: no pattern in
    lib/secrets.js decodes base64, and the watchman's exposure differs in kind
    from the helix's — the helix persists locally, the watchman ships the
    preview to a third-party model."""
    write_proposal(
        sov_root,
        "grok_bridge",
        "b64.json",
        content=f"synthetic payload blob={SYNTH_B64} end",
    )
    env = dry_sweep(sov_root, clean_fetchers)
    item = env["items"][0]
    assert item["preview_state"] == "sanitized"
    assert f"<BASE64-BLOB:len={len(SYNTH_B64)}>" in item["preview"]
    assert SYNTH_B64 not in all_persisted_text(sov_root, env)


# ============================================== finding 7: whitespace preview


def test_whitespace_only_body_is_not_counted_as_previewed(sov_root, clean_fetchers):
    """A count of 'previewed' items must not include items where nothing was
    inspected."""
    write_proposal(sov_root, "grok_bridge", "ws.json", content="   \n\t  ")
    env = dry_sweep(sov_root, clean_fetchers)
    item = env["items"][0]
    assert item["preview_state"] == "metadata-only:empty-body"
    assert "preview" not in item
    assert env["counts"]["items_previewed"] == 0
    assert env["counts"]["items_metadata_only"]["empty-body"] == 1


# ========================================= finding 8: silent preview truncation


def test_long_preview_states_that_it_was_cut(sov_root, clean_fetchers):
    """Nothing told Grok whether it was reading a complete body or the first
    600 chars of a 50MB one — the same silent-partial shape the build already
    closes on the comms limit."""
    body = "synthetic filler sentence. " * 100  # 2700 chars, no base64 runs
    write_proposal(sov_root, "grok_bridge", "long.json", content=body)
    env = dry_sweep(sov_root, clean_fetchers)
    item = env["items"][0]
    assert item["preview_state"] == "sanitized"
    assert f"…[truncated: showing 600 of {len(body)} chars]" in item["preview"]
    assert item["body_bytes"] == len(body.encode("utf-8"))


def test_short_preview_carries_no_truncation_marker(sov_root, clean_fetchers):
    write_proposal(
        sov_root, "grok_bridge", "short.json", content="synthetic short body"
    )
    env = dry_sweep(sov_root, clean_fetchers)
    item = env["items"][0]
    assert "…[truncated" not in item["preview"]
    assert item["body_bytes"] == len("synthetic short body")


def test_a_denylisted_body_is_still_never_handed_to_the_subprocess(
    sov_root, clean_fetchers, tmp_path
):
    """GUARDS AN INVARIANT THIS FIX ROUND CHANGED THE SHAPE OF.

    The review's strongest proof was a marker file showing the redactor is
    never called for a denylisted item. Sanitizing metadata means the redactor
    IS called now — for the metadata. The invariant that actually matters is
    narrower and still holds: the denylisted BODY never reaches the subprocess.
    This test instruments the spy to capture its STDIN and asserts on content,
    not on whether it was called at all.
    """
    capture = tmp_path / "SPY_STDIN_CAPTURE"
    spy = tmp_path / "spy.js"
    spy.write_text(
        "let b=[];process.stdin.on('data',c=>b.push(c));"
        "process.stdin.on('end',()=>{"
        f"require('fs').appendFileSync({json.dumps(str(capture))},"
        "Buffer.concat(b).toString('utf8')+'\\n');"
        "process.stdout.write('[]');process.exit(0);});\n"
    )
    body = "SYNTHETIC-DENYLIST-BODY-CANARY must never reach the redactor"
    write_proposal(
        sov_root, "grok_bridge", "ack.json", tool="comms_acknowledge", content=body
    )
    write_proposal(sov_root, "antigravity_connector", "ag.json", content=body)
    write_proposal(sov_root, "grok_bridge", "protected_x.json", content=body)
    write_proposal(sov_root, "openai_bridge", "consent_y.json", content=body)

    env = dry_sweep(sov_root, clean_fetchers, sanitize_kwargs={"script_path": spy})

    assert all(i["preview_state"] == "metadata-only:denylist" for i in env["items"])
    assert capture.exists(), "metadata must go through the redactor"
    seen_by_subprocess = capture.read_text()
    assert "SYNTHETIC-DENYLIST-BODY-CANARY" not in seen_by_subprocess, (
        "a denylisted body was handed to the subprocess"
    )
    assert "SYNTHETIC-DENYLIST-BODY-CANARY" not in all_persisted_text(sov_root, env)


@pytest.mark.parametrize("state_key", ["empty-body", "content-flagged"])
def test_new_metadata_only_reasons_are_present_in_the_count_shape(
    sov_root, clean_fetchers, state_key
):
    """Envelope shape must be stable across sweeps: a reason key that only
    appears when it fires is a reader's silent-partial."""
    write_proposal(sov_root, "grok_bridge", "shape.json", content="synthetic routine")
    env = dry_sweep(sov_root, clean_fetchers)
    assert state_key in env["counts"]["items_metadata_only"]
