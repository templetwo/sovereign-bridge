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


# --- _compute_runtime_receipt: full cache populate, matches CLOCK_PROBE shape -


def test_compute_runtime_receipt_populates_all_fields(monkeypatch, tmp_path):
    _init_git_repo(tmp_path)
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\nversion = "3.3.3"\n')
    (tmp_path / "f.txt").write_text("v1")
    expected_sha = _commit_all(tmp_path, "init")

    monkeypatch.setattr(bridge, "_STACK_REPO_ROOT", tmp_path)
    monkeypatch.setattr(
        bridge,
        "RUNTIME_RECEIPT",
        {
            "source_commit": None, "working_tree_dirty": None, "source_repo": None,
            "bridge_commit": None, "bridge_working_tree_dirty": None, "service_start_time": None,
        },
    )
    _run(bridge._compute_runtime_receipt())

    assert bridge.RUNTIME_RECEIPT["source_commit"] == expected_sha
    assert bridge.RUNTIME_RECEIPT["working_tree_dirty"] is False
    assert bridge.RUNTIME_RECEIPT["source_repo"] == str(tmp_path)
    assert bridge.RUNTIME_RECEIPT["service_start_time"] is not None


def test_compute_runtime_receipt_never_raises_when_stack_root_unknown(monkeypatch):
    monkeypatch.setattr(bridge, "_STACK_REPO_ROOT", None)
    monkeypatch.setattr(
        bridge,
        "RUNTIME_RECEIPT",
        {
            "source_commit": None, "working_tree_dirty": None, "source_repo": None,
            "bridge_commit": None, "bridge_working_tree_dirty": None, "service_start_time": None,
        },
    )
    _run(bridge._compute_runtime_receipt())  # must not raise
    assert bridge.RUNTIME_RECEIPT["source_commit"] is None
    assert bridge.RUNTIME_RECEIPT["source_repo"] is None
    assert bridge.RUNTIME_RECEIPT["service_start_time"] is not None


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
