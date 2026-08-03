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


def good_reply_for(refs):
    envelope = {
        "identity": "WATCHMAN SWEEP — grok-4.5 via cosmic-cli",
        "observation": {
            "summary": "Digest shows routine proposal traffic; metadata consistent with normal cadence.",
            "anomalies": [],
        },
        "proposal": {"summary": "nothing", "actions_proposed": []},
        "items": [
            {
                "ref": r,
                "severity": "info",
                "reason": "routine low-risk proposal, consistent with baseline",
                "flagged_for_richer_review": False,
                "confidence_basis": "sanitized preview read directly",
            }
            for r in refs
        ],
    }
    return GOOD_REPLY_TEMPLATE.format(envelope=json.dumps(envelope, indent=2))


def make_fake_cosmic(tmp_path, reply_text, exit_code=0):
    """A recording stand-in for cosmic-cli: logs each invocation, emits the
    canned reply. Returns (bin_path, invocation_log_path)."""
    log = tmp_path / "cosmic_invocations.log"
    reply = tmp_path / "cosmic_reply.txt"
    reply.write_text(reply_text, encoding="utf-8")
    script = tmp_path / "fake-cosmic"
    script.write_text(
        f'#!/bin/sh\necho invoked >> "{log}"\ncat "{reply}"\nexit {exit_code}\n'
    )
    script.chmod(0o755)
    return str(script), log


def invocations(log_path):
    if not log_path.exists():
        return 0
    return len(log_path.read_text().splitlines())
