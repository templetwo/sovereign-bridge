"""Runtime-freshness receipt on /api/heartbeat — GPT-5.6 hardening item #1.

Postmortem 2026-07-11: sovereign_stack.__version__ reads importlib.metadata,
which reads .dist-info written at the last `pip install -e .`. That snapshot
does NOT move when the tree is later `git checkout`'d — the heartbeat kept
reporting v1.13.0 while main was really at v1.12.0, and the false reading
rode into the chronicle as a ground_truth entry.

These tests prove the replacement is structurally different, not just
differently wrong: _resolve_version reads the checked-out pyproject.toml
directly and CANNOT be satisfied by a stale metadata_fallback when the two
disagree (test_resolve_version_prefers_source_over_stale_metadata is the
load-bearing one — it fails against the old `VERSION = _METADATA_VERSION`
logic by construction). _git_head_state proves source_commit is read fresh
from .git, never a constant, and that working_tree_dirty ignores ambient
untracked scratch files (the failure mode a naive `git status --porcelain`
would hit in HQ's real working tree — see conftest-free fixture below).
"""

import asyncio
import subprocess
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import bridge  # noqa: E402


def _run(coro):
    return asyncio.run(coro)


def _init_git_repo(path: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.name", "test"], cwd=path, check=True)


def _commit_all(path: Path, message: str) -> str:
    subprocess.run(["git", "add", "-A"], cwd=path, check=True)
    subprocess.run(["git", "commit", "-q", "-m", message], cwd=path, check=True)
    out = subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"], cwd=path, check=True, capture_output=True, text=True
    )
    return out.stdout.strip()


# --- version: pyproject.toml (source) vs. dist-info (metadata) --------------


def test_resolve_version_prefers_source_over_stale_metadata(tmp_path):
    """The whole point of this item. A stale dist-info metadata_fallback
    ("1.13.0", exactly what production reported tonight) must NOT win when
    the checked-out tree disagrees. This is the test that FAILS against the
    old `VERSION = sovereign_stack.__version__` (metadata-only) logic."""
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\nversion = "9.9.9"\n')
    stale_metadata = "1.13.0"
    resolved = bridge._resolve_version(tmp_path, stale_metadata)
    assert resolved == "9.9.9"
    assert resolved != stale_metadata


def test_resolve_version_falls_back_when_tree_unreadable(tmp_path):
    """No pyproject.toml on disk (e.g. non-editable install) => honest
    fallback to metadata, not a crash and not a fabricated version."""
    resolved = bridge._resolve_version(tmp_path, "1.12.0")
    assert resolved == "1.12.0"


def test_resolve_version_falls_back_when_repo_root_none():
    assert bridge._resolve_version(None, "1.12.0") == "1.12.0"


def test_pyproject_version_ignores_non_string_or_missing_field(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[project]\nname = \"x\"\n")
    assert bridge._pyproject_version(tmp_path) is None


def test_pyproject_version_survives_malformed_toml(tmp_path):
    (tmp_path / "pyproject.toml").write_text("not valid [ toml")
    assert bridge._pyproject_version(tmp_path) is None


# --- _find_repo_root ----------------------------------------------------------


def test_find_repo_root_walks_up_to_git(tmp_path):
    (tmp_path / ".git").mkdir()
    deep = tmp_path / "src" / "pkg"
    deep.mkdir(parents=True)
    assert bridge._find_repo_root(deep / "mod.py") == tmp_path


def test_find_repo_root_none_when_no_git_anywhere(tmp_path):
    deep = tmp_path / "a" / "b"
    deep.mkdir(parents=True)
    assert bridge._find_repo_root(deep) is None


# --- _git_head_state: real git, not a constant -------------------------------


def test_git_head_state_reads_actual_head_sha(tmp_path):
    _init_git_repo(tmp_path)
    (tmp_path / "f.txt").write_text("v1")
    expected_sha = _commit_all(tmp_path, "init")

    sha, dirty = _run(bridge._git_head_state(tmp_path))
    assert sha == expected_sha
    assert dirty is False


def test_git_head_state_tracks_new_commit_after_checkout_moves(tmp_path):
    """The exact shape of the bug this item fixes: the reported commit must
    move when the tree moves, proving it isn't a frozen value."""
    _init_git_repo(tmp_path)
    (tmp_path / "f.txt").write_text("v1")
    sha_1 = _commit_all(tmp_path, "first")
    sha_1_reported, _ = _run(bridge._git_head_state(tmp_path))
    assert sha_1_reported == sha_1

    (tmp_path / "f.txt").write_text("v2")
    sha_2 = _commit_all(tmp_path, "second")
    sha_2_reported, _ = _run(bridge._git_head_state(tmp_path))
    assert sha_2_reported == sha_2
    assert sha_2_reported != sha_1_reported


def test_git_head_state_dirty_true_on_tracked_change(tmp_path):
    _init_git_repo(tmp_path)
    (tmp_path / "f.txt").write_text("v1")
    _commit_all(tmp_path, "init")
    (tmp_path / "f.txt").write_text("modified, uncommitted")

    _, dirty = _run(bridge._git_head_state(tmp_path))
    assert dirty is True


def test_git_head_state_clean_despite_untracked_scratch_files(tmp_path):
    """Regression guard for the ambient-noise trap: HQ's real working tree
    always has untracked scratch (temp_clone/, *_insights.json, ...). A naive
    `git status --porcelain` would report dirty=True permanently, which is
    noise, not signal. Untracked files must NOT flip working_tree_dirty."""
    _init_git_repo(tmp_path)
    (tmp_path / "f.txt").write_text("v1")
    _commit_all(tmp_path, "init")
    (tmp_path / "scratch_notes.json").write_text("{}")
    (tmp_path / "temp_clone").mkdir()
    (tmp_path / "temp_clone" / "x.py").write_text("# untracked")

    sha, dirty = _run(bridge._git_head_state(tmp_path))
    assert dirty is False
    assert sha is not None


def test_git_head_state_none_for_non_repo(tmp_path):
    sha, dirty = _run(bridge._git_head_state(tmp_path))
    assert sha is None
    assert dirty is None


def test_git_head_state_none_for_none_repo_root():
    sha, dirty = _run(bridge._git_head_state(None))
    assert sha is None
    assert dirty is None


def test_git_head_state_degrades_when_git_binary_missing(monkeypatch, tmp_path):
    _init_git_repo(tmp_path)
    (tmp_path / "f.txt").write_text("v1")
    _commit_all(tmp_path, "init")
    monkeypatch.setattr(bridge, "GIT_BIN", str(tmp_path / "no-such-git-binary"))

    sha, dirty = _run(bridge._git_head_state(tmp_path))
    assert sha is None
    assert dirty is None


def test_git_head_state_kills_process_on_timeout_no_orphan(monkeypatch, tmp_path):
    """Mirrors _probe_one's sntp handling: a wedged subprocess must be killed,
    not just abandoned. asyncio.wait_for cancels the AWAIT, it does not touch
    the process — proving no-raise alone (the old version of this test) is
    not enough to prove no-orphan. Assert the pid is actually gone."""
    _init_git_repo(tmp_path)
    (tmp_path / "f.txt").write_text("v1")
    _commit_all(tmp_path, "init")
    monkeypatch.setattr(bridge, "GIT_PROBE_TIMEOUT", 0.05)

    spawned_pids = []
    real_exec = asyncio.create_subprocess_exec

    async def slow_exec(*args, **kwargs):
        proc = await real_exec(
            "sleep", "5", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        spawned_pids.append(proc.pid)
        return proc

    monkeypatch.setattr(asyncio, "create_subprocess_exec", slow_exec)
    sha, dirty = _run(bridge._git_head_state(tmp_path))
    assert sha is None
    assert dirty is None

    assert spawned_pids, "test setup didn't actually spawn a subprocess"
    import os
    import time

    deadline = time.time() + 2.0
    alive = True
    while time.time() < deadline:
        try:
            os.kill(spawned_pids[0], 0)
            time.sleep(0.05)
        except ProcessLookupError:
            alive = False
            break
    assert not alive, f"pid {spawned_pids[0]} (sleep 5) was left running — orphaned process"


def test_run_git_kills_process_on_cancellation_no_orphan(monkeypatch, tmp_path):
    """Companion to test_git_head_state_kills_process_on_timeout_no_orphan:
    a TASK CANCELLATION landing mid-communicate() must also kill the child,
    not just a timeout. asyncio.CancelledError is a BaseException, not an
    Exception, so it does NOT route through `except (..., Exception)` — and
    this is now a live scenario, not a hypothetical one:
    _runtime_receipt_refresh_loop is cancelled on every lifespan shutdown,
    possibly while a `git` call is in flight."""
    spawned_pids = []
    real_exec = asyncio.create_subprocess_exec

    async def slow_exec(*args, **kwargs):
        proc = await real_exec(
            "sleep", "5", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        spawned_pids.append(proc.pid)
        return proc

    monkeypatch.setattr(asyncio, "create_subprocess_exec", slow_exec)

    async def _drive():
        task = asyncio.create_task(bridge._run_git(tmp_path, "status"))
        await asyncio.sleep(0.1)  # let it get past create_subprocess_exec, into communicate()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    _run(_drive())

    assert spawned_pids, "test setup didn't actually spawn a subprocess"
    import os
    import time as _time

    deadline = _time.time() + 2.0
    alive = True
    while _time.time() < deadline:
        try:
            os.kill(spawned_pids[0], 0)
            _time.sleep(0.05)
        except ProcessLookupError:
            alive = False
            break
    assert not alive, f"pid {spawned_pids[0]} (sleep 5) was left running after cancellation — orphaned process"


# --- _compute_runtime_receipt: full cache populate, matches CLOCK_PROBE shape -


def test_compute_runtime_receipt_populates_all_fields(monkeypatch, tmp_path):
    _init_git_repo(tmp_path)
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\nversion = "3.3.3"\n')
    (tmp_path / "f.txt").write_text("v1")
    expected_sha = _commit_all(tmp_path, "init")

    monkeypatch.setattr(bridge, "_STACK_REPO_ROOT", tmp_path)
    # _compute_runtime_receipt mutates the module-level VERSION global on a
    # successful pass (defect 1 fix) — without this guard, this test would
    # leak "3.3.3" into bridge.VERSION for every test that runs afterward in
    # the same process.
    monkeypatch.setattr(bridge, "VERSION", "0.0.0-pretest")
    monkeypatch.setattr(
        bridge,
        "RUNTIME_RECEIPT",
        {
            "source_commit": None, "source_commit_at_bridge_boot": None,
            "working_tree_dirty": None, "source_repo": None,
            "bridge_commit": None, "bridge_commit_at_boot": None,
        "bridge_working_tree_dirty": None,
            "service_start_time": None, "bridge_start_time": None,
            "version": None, "receipt_computed_at": None,
        },
    )
    _run(bridge._compute_runtime_receipt())

    assert bridge.RUNTIME_RECEIPT["source_commit"] == expected_sha
    assert bridge.RUNTIME_RECEIPT["source_commit_at_bridge_boot"] == expected_sha
    assert bridge.RUNTIME_RECEIPT["working_tree_dirty"] is False
    assert bridge.RUNTIME_RECEIPT["source_repo"] == str(tmp_path)
    assert bridge.RUNTIME_RECEIPT["service_start_time"] is not None
    assert bridge.RUNTIME_RECEIPT["version"] == "3.3.3"
    assert bridge.VERSION == "3.3.3"


def test_compute_runtime_receipt_never_raises_when_stack_root_unknown(monkeypatch):
    monkeypatch.setattr(bridge, "_STACK_REPO_ROOT", None)
    monkeypatch.setattr(bridge, "VERSION", "0.0.0-pretest")  # defensive; no pollution expected here
    monkeypatch.setattr(
        bridge,
        "RUNTIME_RECEIPT",
        _fresh_receipt(),
    )
    _run(bridge._compute_runtime_receipt())  # must not raise
    assert bridge.RUNTIME_RECEIPT["source_commit"] is None
    assert bridge.RUNTIME_RECEIPT["source_commit_at_bridge_boot"] is None
    assert bridge.RUNTIME_RECEIPT["source_repo"] is None
    assert bridge.RUNTIME_RECEIPT["service_start_time"] is not None
    assert bridge.RUNTIME_RECEIPT["version"] is None
    assert bridge.VERSION == "0.0.0-pretest"


# --- heartbeat wiring: cache -> response, never a per-request git shell-out --


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    monkeypatch.setattr(bridge, "COMMS_DIR", tmp_path)
    from datetime import datetime, timezone

    monkeypatch.setattr(
        bridge,
        "CLOCK_PROBE",
        {
            "drift_seconds": 0.04,
            "drift_uncertainty": 0.006,
            "drift_measured_at": datetime.now(timezone.utc).isoformat(),
            "drift_source": "time.apple.com",
        },
    )

    async def fake_count():
        return 82

    monkeypatch.setattr(bridge, "get_tool_count", fake_count)
    # Every `with TestClient(...)` test in this file starts the REAL
    # lifespan, which starts _clock_probe_loop — that fires a genuine `sntp`
    # subprocess over the network on every test run otherwise (hundreds of
    # ms to CLOCK_PROBE_TIMEOUT=6s of real latency, and a live PytestUnraisable
    # ExceptionWarning source: verified empirically 2026-07-13 — 8/30 stress
    # runs warned with real sntp, 0/30 with it neutralized here). A bogus
    # SNTP_BIN makes create_subprocess_exec fail fast via FileNotFoundError
    # (no real subprocess, no network egress, no timing window to orphan).
    monkeypatch.setattr(bridge, "SNTP_BIN", "/no-such-sntp-binary-for-tests")


def test_heartbeat_reports_cached_runtime_receipt(monkeypatch):
    """heartbeat() must READ the cache, never compute it inline. Prove the
    dict is threaded through by planting a value no live git call would
    produce and asserting it round-trips verbatim to the HTTP response."""
    from fastapi.testclient import TestClient

    monkeypatch.setattr(
        bridge,
        "RUNTIME_RECEIPT",
        {
            "source_commit": "deadbee",
            "working_tree_dirty": True,
            "source_repo": "/nonexistent/planted",
            "bridge_commit": "feedfac",
            "bridge_working_tree_dirty": False,
            "service_start_time": "2026-07-12T00:00:00+00:00",
        },
    )
    client = TestClient(bridge.app)
    b = client.get("/api/heartbeat").json()
    assert b["source_commit"] == "deadbee"
    assert b["working_tree_dirty"] is True
    assert b["bridge_commit"] == "feedfac"
    assert b["bridge_working_tree_dirty"] is False
    assert b["service_start_time"] == "2026-07-12T00:00:00+00:00"


def test_heartbeat_degrades_cleanly_when_receipt_unpopulated(monkeypatch):
    """If lifespan hasn't run (e.g. TestClient without the `with` context),
    the receipt fields must be present-but-None, never a KeyError/500."""
    from fastapi.testclient import TestClient

    monkeypatch.setattr(
        bridge,
        "RUNTIME_RECEIPT",
        {
            "source_commit": None, "working_tree_dirty": None, "source_repo": None,
            "bridge_commit": None, "bridge_working_tree_dirty": None, "service_start_time": None,
        },
    )
    client = TestClient(bridge.app)
    r = client.get("/api/heartbeat")
    assert r.status_code == 200
    b = r.json()
    assert b["source_commit"] is None
    assert b["working_tree_dirty"] is None


def test_heartbeat_legacy_version_key_still_present(monkeypatch):
    """Back-compat: other seats and Anthony's docs read `version` directly.
    It must still exist — it is just honest now (pyproject-sourced)."""
    from fastapi.testclient import TestClient

    client = TestClient(bridge.app)
    b = client.get("/api/heartbeat").json()
    assert "version" in b
    assert b["version"] == bridge.VERSION


# --- TTL background refresh: reproduces the actual 2026-07-12 production bug -


def _fresh_receipt() -> dict:
    return {
        "source_commit": None, "source_commit_at_bridge_boot": None,
        "working_tree_dirty": None, "source_repo": None,
        "bridge_commit": None, "bridge_working_tree_dirty": None,
        "service_start_time": None, "bridge_start_time": None,
        "version": None, "receipt_computed_at": None,
    }


def _write_pyproject(repo_root: Path, version: str) -> None:
    """version and source_commit are AND-gated (coordinator review, 2026-07-13
    defect 1): receipt_computed_at only advances when BOTH the stack git read
    AND the pyproject.toml version read succeed in the same pass. Any test
    that wants source_commit to actually update via the real
    _compute_runtime_receipt path needs a readable pyproject.toml in the repo
    it points _STACK_REPO_ROOT at, or the AND-gate withholds everything."""
    (repo_root / "pyproject.toml").write_text(f'[project]\nname = "x"\nversion = "{version}"\n')


def test_heartbeat_reflects_moved_head_after_ttl_refresh(monkeypatch, tmp_path):
    """The exact shape of the 2026-07-12 production incident: sovereign_stack
    merged 8ba052d while the bridge process stayed up ~20h with no restart,
    and source_commit kept reporting the old sha the entire time because
    RUNTIME_RECEIPT was computed once at boot and never touched again.

    This drives the REAL lifespan (background refresh task included) via a
    `with TestClient(...)` block — not a direct function call — so it
    exercises the actual production wiring: receipt computed at boot, HEAD
    moves, TTL cycles elapse in real wall-clock time, heartbeat must report
    the new sha with no restart in between.

    On the unfixed bridge.py (RUNTIME_RECEIPT populated once in lifespan, no
    refresh loop, no RUNTIME_RECEIPT_TTL) this fails cleanly on the
    `source_commit == sha_2` assertion below: the cache is written once at
    startup and heartbeat keeps serving sha_1 forever — reproducing the
    incident, not just erroring out on a missing symbol (the TTL monkeypatch
    uses raising=False for exactly that reason: it must not itself blow up
    on unfixed code before the real assertion gets to run).

    source_commit and version are AND-gated (2026-07-13 coordinator review,
    defect 1) so this repo needs a readable pyproject.toml too, or the gate
    withholds source_commit even though the git read alone would succeed.
    RUNTIME_RECEIPT_STALE_MULTIPLIER is pushed way up so receipt_stale=False
    has a wide margin against poll/scheduling jitter — this test's job is
    proving source_commit tracks a moved HEAD, not proving the stale gate;
    the dedicated stale test below owns driving that gate to True with its
    own tight, deliberately-chosen margins."""
    from fastapi.testclient import TestClient

    _init_git_repo(tmp_path)
    _write_pyproject(tmp_path, "1.0.0")
    (tmp_path / "f.txt").write_text("v1")
    sha_1 = _commit_all(tmp_path, "first")

    monkeypatch.setattr(bridge, "_STACK_REPO_ROOT", tmp_path)
    monkeypatch.setattr(bridge, "RUNTIME_RECEIPT", _fresh_receipt())
    # VERSION is a module global _compute_runtime_receipt mutates on success
    # (defect 1 fix) — without this guard a real refresh here would leak
    # "1.0.0" into bridge.VERSION and poison every test that runs after this
    # one in the same process.
    monkeypatch.setattr(bridge, "VERSION", "0.0.0-pretest")
    # Tiny TTL so the test doesn't wait out a real 30s cycle. raising=False:
    # on unfixed code RUNTIME_RECEIPT_TTL doesn't exist yet, and this
    # monkeypatch must not itself error the test out before it gets to
    # observe the real, intended failure (a stale sha).
    monkeypatch.setattr(bridge, "RUNTIME_RECEIPT_TTL", 0.05, raising=False)
    monkeypatch.setattr(bridge, "RUNTIME_RECEIPT_STALE_MULTIPLIER", 1000, raising=False)

    with TestClient(bridge.app) as client:
        b1 = client.get("/api/heartbeat").json()
        assert b1["source_commit"] == sha_1

        # The stack's HEAD moves — the production scenario: a merge lands
        # while this bridge process keeps running, no restart.
        (tmp_path / "f.txt").write_text("v2")
        sha_2 = _commit_all(tmp_path, "second")
        assert sha_2 != sha_1

        # Let TTL cycles elapse in real time (bounded poll, not a fixed
        # sleep, so this isn't flaky under load — but it must still fail
        # promptly on unfixed code since nothing there will ever converge).
        deadline = time.time() + 2.0
        b2 = client.get("/api/heartbeat").json()
        while b2["source_commit"] != sha_2 and time.time() < deadline:
            time.sleep(0.05)
            b2 = client.get("/api/heartbeat").json()

    assert b2["source_commit"] == sha_2, (
        f"heartbeat still reports {b2['source_commit']!r} after HEAD moved to "
        f"{sha_2!r} and TTL cycles elapsed with no restart — this is the "
        "2026-07-12 bug: the receipt was computed once at boot and never "
        "refreshed."
    )
    # DEFECT 2 (coordinator review): source_commit_at_bridge_boot must stay
    # frozen at sha_1 (what THIS bridge process actually imported) even as
    # source_commit tracks disk forward to sha_2 — that divergence is the
    # entire point of the field. Proving it's merely POPULATED at boot
    # (test_compute_runtime_receipt_populates_all_fields) doesn't prove it
    # stays frozen while its sibling moves; this does.
    assert b2["source_commit_at_bridge_boot"] == sha_1, (
        f"source_commit_at_bridge_boot={b2['source_commit_at_bridge_boot']!r} but should "
        f"still read {sha_1!r} — it must stay frozen at what this bridge process imported "
        "at boot even after source_commit tracks disk forward to a moved HEAD."
    )
    # Freshness must be disclosed, not just correct: once refreshed, the age
    # is small and the receipt does not claim staleness.
    assert b2["source_commit_read_at"] is not None
    assert b2["source_commit_age_seconds"] is not None
    assert b2["source_commit_age_seconds"] < 1.0
    assert b2["receipt_stale"] is False


def test_heartbeat_version_reflects_pyproject_change_after_ttl_refresh(monkeypatch, tmp_path):
    """DEFECT 1 (coordinator review, 2026-07-13): VERSION was resolved once
    at module import and never touched again — mechanically just as capable
    of going stale as source_commit was; the 2026-07-12 incident just didn't
    happen to move the version string, so it read as 'live and correct' by
    coincidence. Fixing source_commit alone while leaving VERSION
    boot-frozen would make receipt_stale=false a verdict on a payload that's
    still half-lying (fresh sha, stale version). This must fail on the
    branch tip BEFORE that fix: `heartbeat()["version"]` reads the frozen
    module-level VERSION global directly, so it won't reflect this test's
    controlled tmp_path tree AT ALL, let alone after a version bump."""
    from fastapi.testclient import TestClient

    _init_git_repo(tmp_path)
    _write_pyproject(tmp_path, "9.9.9")
    (tmp_path / "f.txt").write_text("v1")
    _commit_all(tmp_path, "first")

    monkeypatch.setattr(bridge, "_STACK_REPO_ROOT", tmp_path)
    monkeypatch.setattr(bridge, "RUNTIME_RECEIPT", _fresh_receipt())
    monkeypatch.setattr(bridge, "VERSION", "0.0.0-pretest")
    monkeypatch.setattr(bridge, "RUNTIME_RECEIPT_TTL", 0.05, raising=False)
    monkeypatch.setattr(bridge, "RUNTIME_RECEIPT_STALE_MULTIPLIER", 1000, raising=False)

    with TestClient(bridge.app) as client:
        b1 = client.get("/api/heartbeat").json()
        assert b1["version"] == "9.9.9", (
            f"heartbeat reports version={b1['version']!r}, not this test's controlled "
            "9.9.9 — version is still boot-frozen, reading the real production tree's "
            "VERSION global instead of the TTL-refreshed receipt."
        )

        # A release bump lands on disk with no bridge restart — the same
        # production scenario as moved_head, but for version instead of sha.
        _write_pyproject(tmp_path, "10.0.0")
        _commit_all(tmp_path, "bump version")

        deadline = time.time() + 2.0
        b2 = client.get("/api/heartbeat").json()
        while b2["version"] != "10.0.0" and time.time() < deadline:
            time.sleep(0.05)
            b2 = client.get("/api/heartbeat").json()

    assert b2["version"] == "10.0.0", (
        f"heartbeat still reports version={b2['version']!r} after pyproject.toml bumped "
        "to 10.0.0 and TTL cycles elapsed with no restart — version is boot-frozen while "
        "source_commit is not, so receipt_stale can certify freshness for a payload "
        "that's still half-lying."
    )
    # /api/discover reads the same module-level VERSION global directly —
    # the defect-1 fix updates that global in lockstep, so it goes live too.
    assert bridge.VERSION == "10.0.0"


def test_heartbeat_receipt_stale_flips_true_when_refresher_falls_behind(monkeypatch, tmp_path):
    """DEFECT 3 (coordinator review, 2026-07-13): RUNTIME_RECEIPT_STALE_AFTER
    used to be a fixed product (TTL * 3) computed ONCE at import — a test
    that monkeypatches RUNTIME_RECEIPT_TTL down to drive a fast refresh cycle
    does NOT change that frozen 90s threshold, so `receipt_stale` could never
    actually become True inside any reasonably-fast test window.
    `assert receipt_stale is False` was true by construction, not because
    the gate worked — the exact vacuous-test failure mode this seat has
    named explicitly (two shipped in 48h; this would have been a third).

    This test DRIVES the transition: boot fresh (False, real margin), then
    break every subsequent refresh (False->True is only honest if nothing
    can silently keep succeeding), let enough time pass to clear the
    threshold with real margin, and assert True. Both directions get >=4x
    margin against scheduling jitter — this is the test that must be able
    to fail, so it does not get to be timing-tight."""
    from fastapi.testclient import TestClient

    _init_git_repo(tmp_path)
    _write_pyproject(tmp_path, "1.0.0")
    (tmp_path / "f.txt").write_text("v1")
    _commit_all(tmp_path, "init")

    monkeypatch.setattr(bridge, "_STACK_REPO_ROOT", tmp_path)
    monkeypatch.setattr(bridge, "RUNTIME_RECEIPT", _fresh_receipt())
    monkeypatch.setattr(bridge, "VERSION", "0.0.0-pretest")
    monkeypatch.setattr(bridge, "RUNTIME_RECEIPT_TTL", 0.05, raising=False)
    monkeypatch.setattr(bridge, "RUNTIME_RECEIPT_STALE_MULTIPLIER", 4, raising=False)
    # stale_after ~= 0.2s at these values.

    with TestClient(bridge.app) as client:
        b1 = client.get("/api/heartbeat").json()
        assert b1["receipt_stale"] is False, (
            "receipt_stale is True immediately after a successful boot-time read — "
            f"age={b1.get('source_commit_age_seconds')!r}, this should be ~0s."
        )

        # Wedge every future refresh: point GIT_BIN somewhere that doesn't
        # exist. tomllib-based version reads would still succeed on their
        # own, but the AND-gate means neither field advances once git fails.
        monkeypatch.setattr(bridge, "GIT_BIN", str(tmp_path / "no-such-git-binary"))

        # Let real time pass well past stale_after (~0.2s) with real margin.
        time.sleep(0.6)
        b2 = client.get("/api/heartbeat").json()

    assert b2["receipt_stale"] is True, (
        f"receipt_stale is still False after {b2.get('source_commit_age_seconds')!r}s "
        "with the refresher wedged — the staleness gate never fires, which is exactly "
        "the vacuous-gate failure this test exists to rule out."
    )
    assert b2["source_commit_age_seconds"] is not None
    assert b2["source_commit_age_seconds"] > 0.2


def test_heartbeat_receipt_stale_true_on_negative_age_clock_step(monkeypatch):
    """A clock stepping backward between the last successful read and 'now'
    produces a NEGATIVE age. Without an explicit clamp, `age > stale_after`
    is simply False for a negative age, so a clock step reads as MORE fresh
    than reality, not less — the opposite of the honest-degrade posture this
    receipt is built around. Plant receipt_computed_at in the FUTURE
    relative to the real clock heartbeat() reads (`now`), which is exactly
    what a backward step produces from `now`'s perspective."""
    from datetime import datetime, timedelta, timezone

    from fastapi.testclient import TestClient

    future_read_at = (datetime.now(timezone.utc) + timedelta(seconds=30)).isoformat()
    receipt = _fresh_receipt()
    receipt["receipt_computed_at"] = future_read_at
    monkeypatch.setattr(bridge, "RUNTIME_RECEIPT", receipt)

    client = TestClient(bridge.app)
    b = client.get("/api/heartbeat").json()
    assert b["source_commit_age_seconds"] < 0
    assert b["receipt_stale"] is True, (
        f"receipt_stale is False with a negative age ({b['source_commit_age_seconds']!r}s) "
        "— a clock step backward is reading as freshness instead of being clamped to stale."
    )


def test_refresh_runtime_receipt_self_heals_after_hung_compute(monkeypatch):
    """ALSO-DO item (coordinator review): create_subprocess_exec sits OUTSIDE
    _run_git's own GIT_PROBE_TIMEOUT-bounded proc.communicate() call, so a
    hang there is not covered by that per-call bound. Without an OUTER
    timeout around the whole refresh, such a hang would wedge
    _runtime_receipt_refresh_in_flight permanently — every future TTL tick
    would see it stuck True and skip forever, no self-heal. Simulate the
    hang directly (a _compute_runtime_receipt that never returns) and prove
    _refresh_runtime_receipt still returns within RUNTIME_RECEIPT_REFRESH_
    TIMEOUT and clears the in-flight flag afterward.

    NOTE ON PROOF SHAPE: unlike the other gates in this file, this one has
    no clean "fails without the fix" counterpart to show. Reverting the
    outer `asyncio.wait_for` doesn't make this test fail an assertion — it
    makes `_run(bridge._refresh_runtime_receipt())` HANG on `sleep(999)`
    (the exact wedge this fix exists to prevent), which means "no fix" here
    is a stuck test process, not a red one. So this test is verified by
    construction (it exercises the real timeout path end-to-end and asserts
    on its actual effects) rather than by a paired before/after run, and
    that's disclosed here rather than implied to be the same shape as
    moved_head / version / receipt_stale / the two cancellation tests, all
    of which DO have a clean revert-and-rerun proof."""
    monkeypatch.setattr(bridge, "RUNTIME_RECEIPT_REFRESH_TIMEOUT", 0.1, raising=False)

    async def hangs_forever():
        await asyncio.sleep(999)

    monkeypatch.setattr(bridge, "_compute_runtime_receipt", hangs_forever)

    start = time.time()
    _run(bridge._refresh_runtime_receipt())
    elapsed = time.time() - start

    assert elapsed < 2.0, f"_refresh_runtime_receipt took {elapsed:.2f}s — the outer timeout didn't fire"
    assert bridge._runtime_receipt_refresh_in_flight is False, (
        "in-flight flag left True after a timed-out refresh — this is exactly the "
        "no-self-heal wedge the outer wait_for exists to prevent"
    )


def test_refresh_runtime_receipt_skips_when_already_in_flight(monkeypatch):
    """Single-flight (requirement #3): a refresh already in progress must not
    be stacked with a second concurrent one. Plant the in-flight flag True
    and prove _compute_runtime_receipt is never entered."""
    monkeypatch.setattr(bridge, "_runtime_receipt_refresh_in_flight", True)
    entered = False

    async def spy():
        nonlocal entered
        entered = True

    monkeypatch.setattr(bridge, "_compute_runtime_receipt", spy)
    _run(bridge._refresh_runtime_receipt())
    assert entered is False


def test_compute_runtime_receipt_leaves_cache_on_failed_stack_read(monkeypatch, tmp_path):
    """A failed/wedged stack git read must NOT advance receipt_computed_at —
    doing so would stamp a 'just read' timestamp on a read that actually
    failed, recreating the exact stale-but-confident failure this receipt
    exists to rule out. source_commit and receipt_computed_at must stay at
    their last known-good values; the disclosed age grows instead of
    silently resetting to ~0.

    Needs a readable pyproject.toml (AND-gate, defect 1): _pyproject_version
    reads via tomllib, not git, so it would keep succeeding even with
    GIT_BIN broken below — proving the gate is genuinely git_sha-gated, not
    accidentally passing because version also happened to fail."""
    _init_git_repo(tmp_path)
    _write_pyproject(tmp_path, "1.0.0")
    (tmp_path / "f.txt").write_text("v1")
    sha_1 = _commit_all(tmp_path, "init")

    monkeypatch.setattr(bridge, "_STACK_REPO_ROOT", tmp_path)
    monkeypatch.setattr(bridge, "RUNTIME_RECEIPT", _fresh_receipt())
    monkeypatch.setattr(bridge, "VERSION", "0.0.0-pretest")

    _run(bridge._compute_runtime_receipt())
    assert bridge.RUNTIME_RECEIPT["source_commit"] == sha_1
    assert bridge.RUNTIME_RECEIPT["version"] == "1.0.0"
    first_read_at = bridge.RUNTIME_RECEIPT["receipt_computed_at"]
    assert first_read_at is not None

    # Break the git read (simulates a wedged/missing git binary) and refresh
    # again — source_commit, version, and receipt_computed_at must ALL be
    # UNCHANGED, even though the pyproject.toml read alone would still
    # succeed (tomllib doesn't touch GIT_BIN) — the joint gate must still
    # withhold the whole receipt.
    monkeypatch.setattr(bridge, "GIT_BIN", str(tmp_path / "no-such-git-binary"))
    _run(bridge._compute_runtime_receipt())
    assert bridge.RUNTIME_RECEIPT["source_commit"] == sha_1
    assert bridge.RUNTIME_RECEIPT["version"] == "1.0.0"
    assert bridge.RUNTIME_RECEIPT["receipt_computed_at"] == first_read_at


# ── Round-3 gates: the four defects round-2 adversarial review confirmed ─────
#
# STANDING LAW #2, AMENDED 2026-07-13: a gate must demonstrably be able to FAIL
# — and that has to be read against the FIXTURE, not only the assertion. The
# `_isolate` fixture above stubs get_tool_count with an instantly-returning
# coroutine. The REAL call awaits ~20ms against the SSE, and defect D1 lives in
# exactly that window. Under the default stub the race is STRUCTURALLY
# IMPOSSIBLE and the gate goes green on broken code — 30 stress runs, 0
# failures, on code that was spuriously stale 28/40 in production timing. That
# is the blind fixture. Ask what the harness has REMOVED, not just what the
# test asserts.


def test_heartbeat_not_spuriously_stale_under_real_await(monkeypatch, tmp_path):
    """D1 — heartbeat must not cry stale on a HEALTHY, continuously-refreshing receipt.

    FAILS on the unfixed code: heartbeat() captures `now` at the top of the
    handler, THEN awaits get_tool_count(). The background refresher lands inside
    that yield and stamps receipt_computed_at LATER than `now`, so
    `now - receipt_computed_at` goes NEGATIVE and the clamp flips receipt_stale
    True while nothing whatsoever is wrong.

    This test DELIBERATELY DEFEATS the _isolate fixture's instant get_tool_count.
    With the fast stub the await window is one loop tick and this race cannot
    occur. Do not "simplify" it back to the fast stub — that is precisely how the
    previous version of this gate was green on broken code.
    """
    from fastapi.testclient import TestClient

    _init_git_repo(tmp_path)
    _write_pyproject(tmp_path, "1.0.0")
    (tmp_path / "f.txt").write_text("v1")
    _commit_all(tmp_path, "init")

    monkeypatch.setattr(bridge, "_STACK_REPO_ROOT", tmp_path)
    monkeypatch.setattr(bridge, "RUNTIME_RECEIPT", _fresh_receipt())
    monkeypatch.setattr(bridge, "RUNTIME_RECEIPT_TTL", 0.01, raising=False)

    async def slow_count():
        await asyncio.sleep(0.02)  # the ~20ms the real SSE call actually takes
        return 82

    monkeypatch.setattr(bridge, "get_tool_count", slow_count)

    bad = []
    with TestClient(bridge.app) as client:
        for _ in range(40):
            b = client.get("/api/heartbeat").json()
            age = b["source_commit_age_seconds"]
            if b["receipt_stale"] or (age is not None and age < 0):
                bad.append((b["receipt_stale"], age))
            time.sleep(0.005)

    assert not bad, (
        f"{len(bad)}/40 heartbeats reported stale / negative-age while the refresher "
        f"was healthy and succeeding every cycle: {bad[:5]}. That is the handler's "
        "stale `now` — captured before the get_tool_count await — racing the "
        "refresher's later timestamp. It is not a clock step and it is not real "
        "staleness. Re-read the clock immediately before the age arithmetic."
    )


def test_bridge_commit_at_boot_frozen_while_bridge_commit_tracks_disk(monkeypatch, tmp_path):
    """D2 — bridge_commit is TTL-live DISK head; bridge_commit_at_boot is what THIS
    process actually EXECUTED. Without the boot anchor, a `git pull` in the bridge
    repo with no launchd restart advances bridge_commit to code that has never run
    here, undisclosed — the 2026-07-12 incident, relocated from source_commit to
    bridge_commit, and surfacing precisely during a deploy: the one moment anyone
    looks. FAILS without bridge_commit_at_boot."""
    stack = tmp_path / "stack"; stack.mkdir()
    brg = tmp_path / "brg"; brg.mkdir()
    for d in (stack, brg):
        _init_git_repo(d)
        (d / "f.txt").write_text("v1")
    _write_pyproject(stack, "1.0.0")
    _commit_all(stack, "init")
    boot_sha = _commit_all(brg, "init")

    monkeypatch.setattr(bridge, "_STACK_REPO_ROOT", stack)
    monkeypatch.setattr(bridge, "_BRIDGE_REPO_ROOT", brg)
    monkeypatch.setattr(bridge, "RUNTIME_RECEIPT", _fresh_receipt())

    _run(bridge._compute_runtime_receipt())
    assert bridge.RUNTIME_RECEIPT["bridge_commit"] == boot_sha
    assert bridge.RUNTIME_RECEIPT["bridge_commit_at_boot"] == boot_sha

    (brg / "f.txt").write_text("v2")
    moved_sha = _commit_all(brg, "second")
    assert moved_sha != boot_sha

    _run(bridge._compute_runtime_receipt())

    assert bridge.RUNTIME_RECEIPT["bridge_commit"] == moved_sha, (
        "bridge_commit should track disk HEAD"
    )
    assert bridge.RUNTIME_RECEIPT["bridge_commit_at_boot"] == boot_sha, (
        "bridge_commit_at_boot MOVED. It must stay frozen at the code this process "
        "actually imported, or the heartbeat reports bridge code that has never "
        "executed here with nothing disclosing it."
    )


def test_refresh_timeout_bounds_a_SYNCHRONOUS_pyproject_hang(monkeypatch, tmp_path):
    """D3 — asyncio.wait_for CANNOT bound a synchronous call: a blocked event loop
    cannot fire its own timeout callback. _pyproject_version does real
    stat/open/tomllib I/O, so it must run off-loop (asyncio.to_thread) or a stalled
    mount freezes the entire bridge — the 2026-07-10 SSE freeze class.

    FAILS on the unfixed code (inline sync call): the refresh eats the FULL stall
    and the timeout never fires.

    The hang here is time.sleep, NOT asyncio.sleep. An awaitable hang is
    cancellable and proves nothing — modelling it that way is what let the earlier
    self-heal test certify the coverable hang while licensing the code as though
    every hang were covered."""
    _init_git_repo(tmp_path)
    _write_pyproject(tmp_path, "1.0.0")
    (tmp_path / "f.txt").write_text("v1")
    _commit_all(tmp_path, "init")

    monkeypatch.setattr(bridge, "_STACK_REPO_ROOT", tmp_path)
    monkeypatch.setattr(bridge, "RUNTIME_RECEIPT", _fresh_receipt())
    monkeypatch.setattr(bridge, "RUNTIME_RECEIPT_REFRESH_TIMEOUT", 0.3, raising=False)

    def sync_stall(_root):
        time.sleep(1.5)  # SYNCHRONOUS. un-cancellable. the realistic hang.
        return "9.9.9"

    monkeypatch.setattr(bridge, "_pyproject_version", sync_stall)

    async def go():
        t0 = time.perf_counter()
        await bridge._refresh_runtime_receipt()
        return time.perf_counter() - t0

    elapsed = _run(go())

    assert elapsed < 0.8, (
        f"_refresh_runtime_receipt took {elapsed:.2f}s against a 0.3s timeout. The "
        "wait_for never fired, which means the synchronous pyproject read is running "
        "ON THE EVENT LOOP and blocking it — and a blocked loop cannot fire its own "
        "timeout. Push the read to a thread (asyncio.to_thread)."
    )
    assert bridge._runtime_receipt_refresh_in_flight is False, (
        "single-flight flag wedged True after the timeout — it can never self-heal"
    )


def test_all_public_version_surfaces_agree_after_a_bump(monkeypatch, tmp_path):
    """D4 — /api/heartbeat, /api/discover and /openapi.json are ALL public and
    unauthenticated. FastAPI captured VERSION BY VALUE at app construction and
    caches openapi_schema after first generation, so mutating the VERSION global
    alone silently desyncs /openapi.json. A change whose entire purpose is version
    honesty must not leave a public endpoint reporting a different version.
    FAILS without app.version + openapi_schema invalidation."""
    from fastapi.testclient import TestClient

    _init_git_repo(tmp_path)
    _write_pyproject(tmp_path, "1.0.0")
    (tmp_path / "f.txt").write_text("v1")
    _commit_all(tmp_path, "init")

    monkeypatch.setattr(bridge, "_STACK_REPO_ROOT", tmp_path)
    monkeypatch.setattr(bridge, "RUNTIME_RECEIPT", _fresh_receipt())
    monkeypatch.setattr(bridge, "RUNTIME_RECEIPT_TTL", 0.05, raising=False)
    # register originals so monkeypatch restores them — no cross-test pollution
    monkeypatch.setattr(bridge.app, "version", bridge.app.version)
    monkeypatch.setattr(bridge.app, "openapi_schema", None)

    with TestClient(bridge.app) as client:
        # generate + cache the schema at the OLD version first — that cache is the bug
        assert client.get("/openapi.json").json()["info"]["version"] == "1.0.0"

        _write_pyproject(tmp_path, "1.3.0")
        deadline = time.time() + 3.0
        hb = client.get("/api/heartbeat").json()
        while hb["version"] != "1.3.0" and time.time() < deadline:
            time.sleep(0.05)
            hb = client.get("/api/heartbeat").json()
        assert hb["version"] == "1.3.0", "heartbeat version never refreshed"

        openapi_v = client.get("/openapi.json").json()["info"]["version"]

    assert openapi_v == hb["version"], (
        f"/openapi.json still serves {openapi_v!r} while /api/heartbeat serves "
        f"{hb['version']!r}. Both are public. The cached OpenAPI schema was never "
        "invalidated when the version changed."
    )
