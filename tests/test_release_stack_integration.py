"""The bridge against the STACK RELEASE CANDIDATE it ships beside.

HQ decisions D3 and D8, from Codex review 2026-09-06 findings F3/F4. Everything
else in `tests/test_heartbeat_signals.py` INJECTS the ledger's behaviour at
`bridge._signal_heartbeat_field`, deliberately, so those tests assert the
contract in both worlds and cannot flip when a deploy lands. This file is the
other half: it runs the bridge against the real `sovereign_stack.signal_ledger`
from the release worktree, so the contract is checked against the code that
will actually serve it.

⚠ WHY EVERY CHECK HERE RUNS IN A SUBPROCESS.

`bridge.py` does `sys.path.insert(0, "~/sovereign-stack/src")` at import, so a
pytest process that has imported bridge ALREADY has `sovereign_stack` bound to
the LIVE checkout — a tree that (today) has no `signal_ledger` at all. Loading
the release module in-process would either fail, or half-load a second copy of
a package already in `sys.modules`, and either way the thing measured would not
be the thing named. A subprocess that imports `sovereign_stack` FIRST, off an
explicit `PYTHONPATH`, cannot make that mistake — and each one reports back the
`__file__` it actually loaded so the assertion is on the tree, not on a hope.

That is what "an explicit sys.path override in the TEST only" means here: no
production code changes to accommodate a test, and no chance of the override
leaking into the rest of the suite.

⚠ THE RELEASE WORKTREE MOVES UNDER THIS FILE. It is another agent's working
tree, dirty and advancing while this runs. Every test therefore RECORDS the rev
and the porcelain status it measured against, in the assertion message, so a
result read tomorrow says which tree produced it. A finding against a tree
nobody can name is not a finding — Astra's review stayed usable precisely
because it pinned `4632e93` and said so.

Skips — loudly, naming the path — when the release worktree is not on disk.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from suite_support import stack_release_tree  # noqa: E402

REPO = Path(__file__).resolve().parent.parent


def _release_tree() -> Path:
    tree = stack_release_tree()
    if tree is None:
        pytest.skip(
            "the stack RELEASE worktree is not on disk "
            "(~/.cache/wt-release-stack/src/sovereign_stack/signal_ledger.py). "
            "This file is the only place the bridge is measured against the "
            "release candidate's real ledger, so it is SKIPPED rather than "
            "silently satisfied by the live checkout — which does not carry "
            "signal_ledger at all and would make every assertion here vacuous."
        )
    return tree


def _tree_provenance(tree: Path) -> str:
    """rev + porcelain of the worktree, for the assertion message."""
    repo = tree.parent
    try:
        rev = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=30,
        ).stdout.strip()
        dirty = subprocess.run(
            ["git", "-C", str(repo), "status", "--porcelain"],
            capture_output=True, text=True, timeout=30,
        ).stdout.strip().splitlines()
    except Exception as exc:  # noqa: BLE001
        return f"(provenance unavailable: {type(exc).__name__}: {exc})"
    return f"stack worktree {repo} @ {rev or 'unknown'}, {len(dirty)} uncommitted path(s)"


def _run(script: str, *, with_release_stack: bool, tmp_path: Path) -> dict:
    """Run `script` in a fresh interpreter and return the JSON it printed last.

    `with_release_stack=False` runs with NO stack source reachable at all, so
    `bridge`'s guarded import must fail and the tool route must be the one that
    answers. That is the "absent" half of D3, and it is a different process
    rather than a monkeypatch precisely because the import is resolved once at
    module scope.
    """
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["SOVEREIGN_ROOT"] = str(tmp_path / "sovereign")
    env["SOVEREIGN_CHRONICLE"] = str(tmp_path / "sovereign" / "chronicle")
    # The credential seam (F6): a synthetic file, so a subprocess of this suite
    # is no less isolated than the suite itself.
    envfile = tmp_path / "synthetic-bridge.env"
    envfile.write_text("BRIDGE_TOKEN=synthetic-subprocess-token\n")
    env["SOVEREIGN_BRIDGE_ENV_FILE"] = str(envfile)
    if with_release_stack:
        env["PYTHONPATH"] = f"{_release_tree()}{os.pathsep}{REPO}"
    else:
        env["PYTHONPATH"] = str(REPO)
        # Point the guarded import at nothing: bridge inserts this path itself,
        # so redirecting HOME is what makes ~/sovereign-stack/src unreachable.
        env["HOME"] = str(tmp_path / "empty-home")
        (tmp_path / "empty-home").mkdir(parents=True, exist_ok=True)
        # ⚠ AND HOME ALONE IS NOT ENOUGH, WHICH THIS FILE LEARNED THE HARD WAY.
        # The venv carries an EDITABLE INSTALL of sovereign_stack pointing at
        # the live checkout, so the package resolves whatever HOME says. This
        # test passed for as long as the live tree simply had no
        # `signal_ledger` — an absence, not a control. On 2026-09-06 14:39 HQ
        # merged the stack release to `main`, the live tree gained the module,
        # and the "import absent" case silently became the "import present"
        # case. The test went red, which is the only reason anyone noticed.
        #
        # So the absence is now a PROPERTY OF THE TEST. `sys.modules[name] =
        # None` makes the import raise ImportError for real — the same failure
        # bridge's guarded import would see on a machine without the module —
        # and it cannot be undone by anything a deploy does.
        script = _BLOCK_LEDGER + script
    out = subprocess.run(
        [sys.executable, "-c", textwrap.dedent(script)],
        capture_output=True, text=True, env=env, cwd=str(REPO), timeout=300,
    )
    assert out.returncode == 0, f"subprocess failed:\nSTDOUT:\n{out.stdout}\nSTDERR:\n{out.stderr}"
    return json.loads(out.stdout.strip().splitlines()[-1])


# Makes `import sovereign_stack.signal_ledger` fail for real, whatever is
# installed. Must run BEFORE `import bridge`, because bridge resolves its
# guarded import once at module scope.
_BLOCK_LEDGER = """
import sys
sys.modules["sovereign_stack.signal_ledger"] = None
"""


# The preamble every subprocess shares: import the stack FIRST (so the release
# tree wins over the path bridge inserts), then the bridge, then report which
# files were actually loaded.
_PREAMBLE = """
import json, os, sys
loaded = {}
try:
    import sovereign_stack
    loaded["sovereign_stack"] = sovereign_stack.__file__
except Exception as exc:
    loaded["sovereign_stack"] = f"UNIMPORTABLE: {type(exc).__name__}: {exc}"
import bridge
from fastapi.testclient import TestClient
loaded["bridge"] = bridge.__file__
loaded["signals_source"] = bridge.SIGNALS_SOURCE
client = TestClient(bridge.app)
"""


def test_the_local_route_answers_when_the_release_stack_is_importable(tmp_path):
    """D3, the IMPORT-PRESENT half. With the release stack on the path the
    bridge must resolve the local reader, not the tool fallback — a network
    round-trip in place of a filesystem read is a real regression even when
    both happen to return the same number."""
    tree = _release_tree()
    result = _run(
        _PREAMBLE
        + """
from sovereign_stack import signal_ledger as sl
root = os.environ["SOVEREIGN_ROOT"]
os.makedirs(os.path.join(root, "signals"), exist_ok=True)
# A clean, honestly-empty ledger: scanned, nothing open.
counts = {src: 0 for src in sl.SOURCES}
status = {src: "ok" for src in sl.SOURCES}
sl._write_scan_marker(counts, status, root)
field = client.get("/api/heartbeat").json()["unacked_signals"]
loaded["field"] = field
print(json.dumps(loaded))
""",
        with_release_stack=True,
        tmp_path=tmp_path,
    )
    prov = _tree_provenance(tree)
    assert str(tree) in result["sovereign_stack"], (
        f"the subprocess loaded a different stack than the release worktree ({prov}): "
        f"{result['sovereign_stack']}"
    )
    assert result["signals_source"] == "sovereign_stack.signal_ledger", (
        f"the bridge did not resolve the LOCAL ledger route against {prov}: "
        f"{result['signals_source']}"
    )
    field = result["field"]
    assert field["source"] == "sovereign_stack.signal_ledger"
    # A MEASURED zero is still a zero. "never render 0" implemented literally
    # would make the field useless in the state everyone wants.
    assert field["total"] == 0, prov
    assert field["error"] is None, prov


def test_the_import_absent_route_is_an_error_not_a_zero(tmp_path):
    """D3, the IMPORT-ABSENT half, in a process where the import REALLY failed.

    Monkeypatching `SIGNALS_SOURCE` proves the routing; it does not prove that
    a bridge which genuinely cannot import the ledger degrades correctly,
    because the import is resolved once at module scope and a patched constant
    never exercises that. Here the import genuinely raises: the subprocess
    blocks `sovereign_stack.signal_ledger` in `sys.modules` before bridge is
    imported, upstream is unreachable, and the field must still refuse to say
    zero.

    ⚠ THE ABSENCE IS ARRANGED, NOT INHERITED — see `_BLOCK_LEDGER`. Until
    2026-09-06 this test relied on the live checkout not having the module,
    which meant it was measuring the machine rather than the bridge. HQ merged
    the stack release, the module appeared, and the test flipped to exercising
    the opposite branch. A control that a deploy can revoke is not a control.
    """
    result = _run(
        _PREAMBLE
        + """
field = client.get("/api/heartbeat").json()["unacked_signals"]
loaded["field"] = field
print(json.dumps(loaded))
""",
        with_release_stack=False,
        tmp_path=tmp_path,
    )
    assert result["signals_source"] == "unavailable", result["sovereign_stack"]
    field = result["field"]
    assert field["source"] == "stack tool heartbeat"
    assert field["total"] is None, "an unimportable ledger reported a COUNT"
    assert field["stale_24h"] is None
    assert field["by_source"] is None
    assert "signal_ledger_unavailable" in field["error"]


def test_a_schema_corrupt_row_under_a_valid_marker_is_null_and_errored(tmp_path):
    """D8 / review F4 — THE ONE THAT MAY LEGITIMATELY BE RED, AND IS REPORTED
    EITHER WAY.

    The reviewer wrote a valid scan marker over a ledger containing the
    well-formed JSON row `{"signal_id":"bad"}` — valid JSON, invalid schema, no
    `source` — and measured `error="corrupt_rows:1 ...", ingestion="ok",
    total=0, stale_24h=0, stale_7d=0` through the bridge's local route. Visibly
    an error AND a zero count, which violates the never-zero-on-error contract
    this whole field exists for: a reader who checks `total` sees "nothing is
    waiting" about a ledger with an unreadable row in it.

    The bridge propagates that faithfully; it does not originate it, and this
    test cannot be made green from the bridge side. It is here so the pairing
    is measured rather than assumed, and so the day the stack closes it, the
    bridge suite says so.

    The marker is written by the stack's OWN `_write_scan_marker` rather than
    hand-built, so its integrity fields (ledger_bytes / ledger_rows /
    ledger_sha256) match the corrupt file exactly. A hand-built marker would
    fail integrity for a DIFFERENT reason and the test would pass for the wrong
    one — certifying instrument A while licensing instrument B.
    """
    tree = _release_tree()
    result = _run(
        _PREAMBLE
        + """
from sovereign_stack import signal_ledger as sl
root = os.environ["SOVEREIGN_ROOT"]
os.makedirs(os.path.join(root, "signals"), exist_ok=True)
lp = sl.ledger_path(root)
lp.parent.mkdir(parents=True, exist_ok=True)
# Valid JSON, invalid ROW: no source, no state, no timestamps.
lp.write_text('{"signal_id":"bad"}\\n', encoding="utf-8")
counts = {src: 0 for src in sl.SOURCES}
status = {src: "ok" for src in sl.SOURCES}
sl._write_scan_marker(counts, status, root)
loaded["direct"] = sl.heartbeat_field(root)
field = client.get("/api/heartbeat").json()["unacked_signals"]
loaded["field"] = field
print(json.dumps(loaded))
""",
        with_release_stack=True,
        tmp_path=tmp_path,
    )
    prov = _tree_provenance(tree)
    assert result["signals_source"] == "sovereign_stack.signal_ledger", prov
    field = result["field"]
    assert field["error"], f"a schema-corrupt row produced no error at all ({prov})"
    assert "corrupt" in str(field["error"]).lower(), (
        f"the error does not name the corruption ({prov}): {field['error']!r}"
    )
    assert field["total"] is None, (
        "F4 IS STILL OPEN in the stack this bridge was measured against: a valid "
        "marker over a schema-corrupt row reported a COUNT alongside its error, "
        f"and a count is what a reader acts on. Measured {field['total']!r} "
        f"against {prov}. This is the stack's to close (signal_ledger.heartbeat_field); "
        "the bridge propagates it faithfully and cannot fix it from here."
    )
    assert field["stale_24h"] is None, prov
    assert field["stale_7d"] is None, prov
