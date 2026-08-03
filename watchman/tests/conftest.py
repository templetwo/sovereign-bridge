"""Watchman test fixtures — everything under tmp roots, every cosmic call
mocked, every red-team string SYNTHETIC (invented for these tests, drawn from
no queue and no chronicle)."""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import watchman_sweep  # noqa: E402

QUEUES = watchman_sweep.QUEUES


@pytest.fixture(autouse=True)
def _no_real_cosmic(monkeypatch):
    """Zero-spend rail: if any test path reaches an un-mocked cosmic
    invocation, it hits a nonexistent binary and fails loudly instead of
    calling the xAI API."""
    monkeypatch.setenv("WATCHMAN_COSMIC_BIN", "/nonexistent/cosmic-guard")
    monkeypatch.delenv("SOVEREIGN_WATCHMAN_ROOT", raising=False)


@pytest.fixture
def sov_root(tmp_path):
    root = tmp_path / "sovereign"
    for q in QUEUES:
        (root / q / "pending_writes").mkdir(parents=True)
    (root / "daemons" / "halts").mkdir(parents=True)
    (root / "handoffs").mkdir(parents=True)
    return root


def write_proposal(
    root,
    queue,
    name,
    *,
    tool="propose_insight",
    domain="general",
    content="synthetic routine note, nothing sensitive",
    risk="low",
):
    p = root / queue / "pending_writes" / name
    p.write_text(
        json.dumps(
            {
                "proposal_id": name,
                "timestamp": "2026-08-03T00:00:00Z",
                "source_instance": "synthetic-test-seat",
                "tool": tool,
                "arguments": {
                    "domain": domain,
                    "content": content,
                    "layer": "hypothesis",
                },
                "commit_target": "record_insight",
                "risk_level": risk,
            }
        ),
        encoding="utf-8",
    )
    return p


def write_handoff(root, name, *, consumed_at=None):
    p = root / "handoffs" / name
    p.write_text(
        json.dumps(
            {
                "timestamp": "2026-08-03T00:00:00Z",
                "source_instance": "synthetic-test-seat",
                "thread": "test-thread",
                "note": "synthetic handoff",
                "consumed_at": consumed_at,
                "consumed_by": "someone" if consumed_at else None,
            }
        ),
        encoding="utf-8",
    )
    return p


def all_persisted_text(sov_root, envelope=None):
    """EVERY byte under <root>/watchman/, at any depth, plus the envelope the
    caller would report.

    A RECURSIVE GLOB, deliberately, not an enumerated file list. An enumerated
    list stops seeing output the moment a new file appears — dry-run routing
    added three — and a leak assertion that stops looking passes for the wrong
    reason. Enumerated exclusions are blind by construction.
    """
    chunks = []
    if envelope is not None:
        chunks.append(json.dumps(envelope, default=str, ensure_ascii=False))
    wd = Path(sov_root) / "watchman"
    if wd.is_dir():
        for p in sorted(wd.rglob("*")):
            if p.is_file():
                chunks.append(p.read_text(encoding="utf-8", errors="replace"))
    return "\n".join(chunks)


def dead_script(tmp_path, name="dead_redactor.js"):
    """A redactor that always fails — the fail-closed lever for tests."""
    p = tmp_path / name
    p.write_text("process.exit(2);\n")
    return p


@pytest.fixture
def clean_fetchers():
    """Bridge surfaces answering cleanly with matching commits and no comms."""
    return {
        "heartbeat_fetch": lambda: {"source_commit": "abc1234"},
        "git_head_fn": lambda: "abc1234",
        "comms_fetch": lambda: {"channel": "general", "messages": [], "count": 0},
    }


GOOD_REPLY_TEMPLATE = """WATCHMAN SWEEP — grok-4.5 via cosmic-cli
{envelope}
"""

# The fake cosmic substitutes the real sweep_id for this placeholder, exactly as
# a real Grok reply must echo the digest's sweep_id. The parser now REJECTS a
# reply whose sweep_id does not match, so a canned literal would quarantine.
SWEEP_ID_PLACEHOLDER = "__SWEEP_ID__"


def good_reply_for(refs, *, sweep_id=SWEEP_ID_PLACEHOLDER):
    envelope = {
        "identity": "WATCHMAN SWEEP — grok-4.5 via cosmic-cli",
        "sweep_id": sweep_id,
        "observation": {
            "summary": "Digest shows routine proposal traffic; metadata consistent with normal cadence.",
            "anomalies": [],
        },
        "proposal": {"summary": "nothing", "actions_proposed": []},
        "items": [
            {
                # digest_id is the ONLY key reply coverage reconciles on; ref is
                # carried for the human render and is ignored by the check.
                "digest_id": f"item-{i:04d}",
                "ref": r,
                "severity": "info",
                "reason": "routine low-risk proposal, consistent with baseline",
                "flagged_for_richer_review": False,
                "confidence_basis": "sanitized preview read directly",
            }
            for i, r in enumerate(refs, start=1)
        ],
    }
    return GOOD_REPLY_TEMPLATE.format(envelope=json.dumps(envelope, indent=2))


def make_fake_cosmic(tmp_path, reply_text, exit_code=0):
    """A recording stand-in for cosmic-cli: logs each invocation, reads the
    sweep_id out of the prompt it was handed, and emits the canned reply with
    SWEEP_ID_PLACEHOLDER substituted. Returns (bin_path, invocation_log_path).

    The stand-in parses the prompt rather than being told the sweep_id because
    the sweep_id is minted from the clock inside run_sweep — a test cannot know
    it in advance, and a real Grok is in exactly the same position.
    """
    log = tmp_path / "cosmic_invocations.log"
    reply = tmp_path / "cosmic_reply.txt"
    reply.write_text(reply_text, encoding="utf-8")
    script = tmp_path / "fake-cosmic"
    script.write_text(
        f"""#!{sys.executable}
import json, pathlib, sys

pathlib.Path({str(log)!r}).open("a").write("invoked\\n")
prompt = sys.argv[2] if len(sys.argv) > 2 else ""
sweep_id = ""
marker = "## DELTA DIGEST (input)"
if marker in prompt:
    blob = prompt.split(marker, 1)[1].split("```")[1]
    if blob.startswith("json"):
        blob = blob.split("\\n", 1)[1]
    try:
        sweep_id = json.loads(blob).get("sweep_id", "")
    except Exception:
        sweep_id = ""
text = pathlib.Path({str(reply)!r}).read_text(encoding="utf-8")
sys.stdout.write(text.replace({SWEEP_ID_PLACEHOLDER!r}, sweep_id))
sys.exit({exit_code})
"""
    )
    script.chmod(0o755)
    return str(script), log


def invocations(log_path):
    if not log_path.exists():
        return 0
    return len(log_path.read_text().splitlines())
