"""post_fix_verify is classified by its ARGUMENTS — HQ decision D5, review F5.

THE FINDING: the seat gate checks only the tool NAME. `post_fix_verify` is
allowed to seats, and its `command` probes run commands when the host sets
`POST_FIX_ALLOW_COMMAND=1`. The reviewer set that one variable in a fixture
server's environment, called the tool as a registered seat, and rewrote the
fixture's `hq/seats/registry.json` to `{}` — HTTP 200. Arbitrary command
execution can equally enact policy, move a ring, or delete a file.

⚠ THE HOST FLAG IS OFF TODAY AND THAT IS NOT A DEFENCE. HQ checked
`~/Library/LaunchAgents/com.templetwo.sovereign-bridge.plist`: it does not set
the variable, so the escape is conditional. But a boundary that holds because a
DIFFERENT component's environment happens to be configured a certain way is a
boundary held by luck, and the luck is somebody else's to change. Every refusal
below fires regardless of the flag, so turning it on for the master path can
never silently widen the seat path.

Everything here is synthetic and every path is under a tmp SOVEREIGN_ROOT. No
command is ever actually run: the upstream is a fake that records what it was
asked for, and the assertion is that it was asked for NOTHING.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import bridge  # noqa: E402
import seat_identity as si  # noqa: E402
import seat_socket as ss  # noqa: E402
import session_tokens as st  # noqa: E402

MASTER = "test-master-token-0123456789abcdef-0123456789abcdef"
SEAT = "grok-build-studio"
TOOL = "post_fix_verify"


class StampPeer:
    def __init__(self, app, verified):
        self.app, self.verified = app, verified

    async def __call__(self, scope, receive, send):
        if scope.get("type") == "http" and self.verified is not None:
            ext = dict(scope.get("extensions") or {})
            ext[ss.SEAT_PEER_EXT] = self.verified
            scope = {**scope, "extensions": ext}
        await self.app(scope, receive, send)


@pytest.fixture
def seated(monkeypatch, tmp_path):
    monkeypatch.setenv("SOVEREIGN_ROOT", str(tmp_path))
    monkeypatch.setenv("SOVEREIGN_CHRONICLE", str(tmp_path / "chronicle"))
    monkeypatch.setattr(st, "DB_PATH", tmp_path / "session_tokens.db")
    monkeypatch.setattr(bridge, "BEARER_TOKEN", MASTER)
    reg = tmp_path / "hq" / "seats" / "registry.json"
    reg.parent.mkdir(parents=True)
    reg.write_text(json.dumps({"seats": {SEAT: {"kind": "seated", "enabled": True}}}))
    (tmp_path / "post_fix" / "watches").mkdir(parents=True)
    return tmp_path


@pytest.fixture
def calls(monkeypatch):
    seen = []

    async def fake(tool, args, seat=None):
        seen.append((tool, args))
        return {"ok": True, "result": {"echo": tool}}

    monkeypatch.setattr(bridge, "call_mcp_tool", fake)
    return seen


def call(**args):
    c = TestClient(
        StampPeer(
            bridge.app,
            {"ok": True, "pid": os.getpid(), "uid": os.getuid(), "seat": SEAT},
        ),
        client=("127.0.0.1", 51234),
    )
    return c.post(
        "/api/call",
        json={"tool": TOOL, "arguments": args},
        headers={"X-Sovereign-Seat": SEAT},
    )


def bearer_call(**args):
    return TestClient(bridge.app).post(
        "/api/call",
        json={"tool": TOOL, "arguments": args},
        headers={"Authorization": f"Bearer {MASTER}"},
    )


# ── The four refusals ───────────────────────────────────────────────────────


def test_a_command_probe_is_refused_whatever_the_host_flag_says(seated, calls, monkeypatch):
    """The reviewer's exact escape. Refused on the seat path, and the refusal
    does not consult POST_FIX_ALLOW_COMMAND — set it either way and the answer
    is the same, because a boundary that reads another component's environment
    is a boundary that component can revoke."""
    for flag in ("1", "0", None):
        if flag is None:
            monkeypatch.delenv("POST_FIX_ALLOW_COMMAND", raising=False)
        else:
            monkeypatch.setenv("POST_FIX_ALLOW_COMMAND", flag)
        r = call(
            fix_description="x",
            probes=[{"name": "p", "type": "command", "cmd": "echo hello"}],
        )
        assert r.status_code == 403, f"a command probe was accepted with flag={flag!r}"
        assert "run commands" in r.json()["detail"]
    assert not calls, "a command probe reached the stack"


def test_an_http_probe_may_only_read(seated, calls):
    """A POST probe is a write wearing a health check's name. GET and HEAD are
    the shapes that only observe."""
    for method in ("POST", "PUT", "DELETE", "PATCH", "post"):
        r = call(
            fix_description="x",
            probes=[{"name": "p", "type": "http", "url": "http://127.0.0.1:8100/api/heartbeat",
                     "method": method}],
        )
        assert r.status_code == 403, f"{method} was accepted"
        assert "write wearing a health check" in r.json()["detail"]
    assert not calls


def test_a_get_probe_is_a_seats_ordinary_act(seated, calls):
    """FAIL-CLOSED IS NOT FAIL-USELESS. Watching a fix for drift is what the
    tool is FOR, and a seat that cannot open a watch has lost the capability
    this widening was supposed to give it."""
    for probe in (
        {"name": "p", "type": "http", "url": "http://127.0.0.1:8100/api/heartbeat"},
        {"name": "p", "type": "http", "url": "http://127.0.0.1:8100/api/heartbeat",
         "method": "get"},
        {"name": "p", "type": "http", "url": "http://127.0.0.1:8100/api/heartbeat",
         "method": "HEAD"},
    ):
        r = call(fix_description="x", probes=[probe])
        assert r.status_code == 200, r.text
    assert len(calls) == 3


def test_a_file_hash_probe_cannot_leave_the_sovereign_root(seated, calls):
    """Hashing an arbitrary path is a read primitive over the whole filesystem,
    and the protected drawer lives on this disk. `..` is resolved, not
    string-matched, so a traversal is caught by where it LANDS."""
    for path in (
        "/etc/passwd",
        "~/.config/sovereign-bridge.env",
        str(seated / ".." / ".." / "etc" / "hosts"),
        str(Path(seated).parent / "elsewhere.txt"),
    ):
        r = call(
            fix_description="x",
            probes=[{"name": "p", "type": "file_hash", "path": path}],
        )
        assert r.status_code == 403, f"{path!r} was accepted"
        assert "read primitive over the whole filesystem" in r.json()["detail"]
    assert not calls


def test_a_file_hash_probe_inside_the_root_is_allowed(seated, calls):
    target = seated / "chronicle" / "insights.jsonl"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("{}\n")
    r = call(
        fix_description="x",
        probes=[{"name": "p", "type": "file_hash", "path": str(target)}],
    )
    assert r.status_code == 200, r.text
    assert len(calls) == 1


def test_an_unknown_probe_type_is_refused(seated, calls):
    """A type this bridge cannot classify cannot be classified as SAFE. The
    stack may add one tomorrow, and default-allow on an unrecognised argument
    is how a name nobody reviewed becomes a capability nobody granted."""
    for probe in (
        {"name": "p", "type": "exec"},
        {"name": "p", "type": None},
        {"name": "p"},
        "not even an object",
    ):
        r = call(fix_description="x", probes=[probe])
        assert r.status_code == 403, f"{probe!r} was accepted"
    assert not calls


# ── The lifecycle modes ─────────────────────────────────────────────────────


def test_the_lifecycle_modes_that_do_not_RUN_a_watch_are_allowed(seated, calls):
    """status and cancel replace the retired watch_* trio. "Opening a watch you
    cannot then inspect or cancel is not a lifecycle" — they READ and STOP a
    watch, they do not run it, and D5 restricts them only by where they point.
    `resample` is the one that executes, and it is refused: see below."""
    for args in (
        {"mode": "status"},
        {"mode": "status", "watch_id": "wf-123"},
        {"mode": "cancel", "watch_id": "wf-123", "reason": "done"},
    ):
        r = call(**args)
        assert r.status_code == 200, r.text
    assert len(calls) == 3


def test_a_seat_resample_is_refused_because_the_probes_are_not_in_the_request(
    seated, calls
):
    """⚠ REVIEW N2, REPRODUCED END TO END BY ASTRA: an ordinary synthetic
    COMMAND watch, resampled by a verified seat, recreated its marker and
    returned 200/ok:true.

    Every other rule in `probe_call_refusal` classifies the probes IN THE
    REQUEST. `mode='resample'` carries none — the stack loads `watch['probes']`
    off disk and runs them — so a stored `type='command'` probe, the one thing
    a seat may never run, executes while the request looks innocent.

    REFUSED, NOT INSPECTED. Reading the watch file here would put a second,
    drifting copy of the stack's probe semantics in the bridge and a TOCTOU
    window between our read and the stack's. The bridge declines to classify
    what it never received.
    """
    r = call(mode="resample", watch_id="pfw_20260906_abcd")
    assert r.status_code == 403
    detail = r.json()["detail"]
    assert "re-runs the probes STORED in the watch" in detail
    assert "'status'" in detail and "'cancel'" in detail
    assert not calls, "a resample reached the stack"


def test_the_resample_refusal_does_not_depend_on_the_watch_id_being_odd(
    seated, calls
):
    """A perfectly well-formed, stack-generated watch id is refused just the
    same. The objection is not the address, it is that the OPERATION cannot be
    classified from what the caller sent — so a valid id must not read as a
    valid request."""
    for watch_id in ("pfw_20260906_120000_a1b2", "wf-123", "abc"):
        r = call(mode="resample", watch_id=watch_id)
        assert r.status_code == 403, watch_id
        assert "probes STORED" in r.json()["detail"]
    assert not calls


def test_a_watch_id_that_is_not_a_watch_id_is_refused(seated, calls):
    """A watch is addressed as <root>/post_fix/watches/<watch_id>.json, so a
    watch_id is a PATH SEGMENT the stack interpolates into a filename.

    ⚠ THE SECOND CASE IS WHY THIS RULE IS STRICTER THAN THE INSTRUCTION.
    HQ's D5 says to refuse a watch "outside SOVEREIGN_ROOT". Implemented
    literally, `../../hq/seats/registry` passes — it resolves to
    `<root>/hq/seats/registry.json`, INSIDE the root, and it is Anthony's SEAT
    REGISTRY, and `mode='cancel'` writes. A containment check whose boundary
    encloses the thing being protected is not a containment check. Measured
    here rather than argued: this case is in the list, and it must be a 403.
    """
    for watch_id in (
        "../../../etc/hosts",
        "../../hq/seats/registry",
        "../../chronicle/protected",
        "/etc/hosts",
        "..",
        "a/b",
        "x\x00y",
        123,
    ):
        r = call(mode="cancel", watch_id=watch_id, reason="x")
        assert r.status_code == 403, f"{watch_id!r} was accepted"
        assert "not a watch id" in r.json()["detail"]
    assert not calls


# ── The boundary of the boundary ────────────────────────────────────────────


def test_the_bearer_path_keeps_every_probe(seated, calls):
    """Master is master. D5 narrows what a SEAT may ask for; it is not a new
    restriction on Anthony's own token, and quietly making it one would be this
    bridge deciding what the operator may do on his own machine."""
    r = bearer_call(
        fix_description="x",
        probes=[{"name": "p", "type": "command", "cmd": "echo hello"}],
    )
    assert r.status_code == 200, r.text
    assert calls[0][1]["probes"][0]["type"] == "command"


def test_other_tools_are_not_touched_by_the_probe_rules(seated, calls):
    """The classifier is scoped to post_fix_verify. A `probes` key on some
    unrelated tool is not this guard's business, and a guard that widened
    itself by argument NAME would deny things nobody meant to deny."""
    assert si.probe_call_refusal("record_insight", {"probes": [{"type": "command"}]}) is None
    assert si.probe_call_refusal("recall_insights", {"mode": "cancel", "watch_id": "../x"}) is None
