"""served_predates_head on /api/heartbeat — design A4 (next-phase plan 1, Task 10).

`source_commit`, `working_tree_dirty` and `service_start_time` are read ONCE,
at process start: they say what the process loaded. HEAD can move after that
without a restart (a commit, a merge, a checkout in the live tree: a checkout is
a deploy that nothing announces). So the bridge RE-READS the stack's HEAD off
the request path and derives one field from the two readings:

  true   service_start_time is older than HEAD's commit time, or the tree is dirty
  false  both were read and neither holds
  null   anything needed to decide was not read, with the reason; NEVER false

The brief's three cases come first (a fake repo with one commit and a start time
earlier than it, later than it, and an unreadable `.git`); the rest pin the
wiring the three cannot see: a pure function can pass them while production
stays false for ever, because HEAD as read at start is always committed before
the start.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import bridge  # noqa: E402


def _run(coro):
    return asyncio.run(coro)


def _init_git_repo(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.name", "test"], cwd=path, check=True)


def _commit_all(path: Path, message: str, *, committed_at: datetime | None = None) -> str:
    """Commit everything; `committed_at` pins the committer date (git's internal
    `<epoch> <offset>` form), so a test never depends on which second it ran in."""
    env = dict(os.environ)
    if committed_at is not None:
        env["GIT_COMMITTER_DATE"] = f"{int(committed_at.timestamp())} +0000"
    subprocess.run(["git", "add", "-A"], cwd=path, check=True, env=env)
    subprocess.run(["git", "commit", "-q", "-m", message], cwd=path, check=True, env=env)
    out = subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"],
        cwd=path,
        check=True,
        capture_output=True,
        text=True,
    )
    return out.stdout.strip()


def _repo_with_one_commit(path: Path) -> str:
    _init_git_repo(path)
    (path / "f.txt").write_text("v1")
    return _commit_all(path, "init")


def _fresh_receipt() -> dict:
    return {
        "source_commit": None,
        "working_tree_dirty": None,
        "source_repo": None,
        "bridge_commit": None,
        "bridge_working_tree_dirty": None,
        "service_start_time": None,
        "head_now": None,
    }


def _receipt(start: str | None, reading: dict | None) -> dict:
    receipt = _fresh_receipt()
    receipt["service_start_time"] = start
    receipt["head_now"] = reading
    return receipt


def _now() -> datetime:
    return datetime.now(timezone.utc)


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    """The heartbeat's other subsystems, held still (the same isolation
    tests/test_runtime_receipt.py uses), so a verdict here is about this field."""
    monkeypatch.setattr(bridge, "COMMS_DIR", tmp_path / "comms")
    monkeypatch.setattr(
        bridge,
        "CLOCK_PROBE",
        {
            "drift_seconds": 0.04,
            "drift_uncertainty": 0.006,
            "drift_measured_at": _now().isoformat(),
            "drift_source": "time.apple.com",
        },
    )

    async def fake_inventory():
        return {"count": 82, "names": [f"tool_{i}" for i in range(82)]}

    monkeypatch.setattr(bridge, "get_tool_inventory", fake_inventory)


# --- the brief's three cases --------------------------------------------------


def test_a_service_started_before_heads_commit_predates_head(tmp_path):
    sha = _repo_with_one_commit(tmp_path / "stack")
    reading = _run(bridge._read_stack_head(tmp_path / "stack"))
    assert reading["error"] is None, reading
    committed_at = reading["committed_at"]
    start = (datetime.fromisoformat(committed_at) - timedelta(hours=1)).isoformat()

    value, reason = bridge._served_predates_head(_receipt(start, reading), _now())

    assert value is True
    assert reason == f"service started {start} before HEAD {sha} committed at {committed_at}"


def test_a_service_started_after_heads_commit_does_not_predate_it(tmp_path):
    sha = _repo_with_one_commit(tmp_path / "stack")
    reading = _run(bridge._read_stack_head(tmp_path / "stack"))
    committed_at = reading["committed_at"]
    start = (datetime.fromisoformat(committed_at) + timedelta(hours=1)).isoformat()

    value, reason = bridge._served_predates_head(_receipt(start, reading), _now())

    assert value is False
    assert reason == (
        f"service started {start} at or after HEAD {sha} committed at {committed_at}; "
        "working tree clean"
    )


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads a mode-000 directory anyway")
def test_an_unreadable_git_dir_is_null_with_the_reason_never_false(tmp_path):
    """Review Focus 4. The repo sits INSIDE another repo on purpose: with its
    `.git` unreadable, git's own discovery walks up and answers for the
    ENCLOSING repository with exit 0 (measured, and asserted below as the
    control), so a probe that let git discover would report a real sha from
    the wrong repo and this field would read false."""
    outer = tmp_path / "outer"
    outer_sha = _repo_with_one_commit(outer)
    inner = outer / "inner"
    _repo_with_one_commit(inner)
    start = (_now() + timedelta(hours=1)).isoformat()  # would be "false" if HEAD were read
    (inner / ".git").chmod(0o000)
    try:
        discovered = subprocess.run(
            ["git", "-C", str(inner), "log", "-1", "--format=%h"],
            capture_output=True,
            text=True,
        )
        assert discovered.returncode == 0 and discovered.stdout.strip() == outer_sha, (
            "control: plain discovery no longer answers for the enclosing repo, so this "
            f"test no longer proves the probe is pinned ({discovered!r})"
        )

        reading = _run(bridge._read_stack_head(inner))
        value, reason = bridge._served_predates_head(_receipt(start, reading), _now())
    finally:
        (inner / ".git").chmod(0o755)

    assert reading["short_sha"] is None
    assert "not a git repository" in reading["error"]
    assert value is None, "an unreadable .git must never read as false"
    assert reason.startswith("git metadata unreadable: ")
    assert "not a git repository" in reason
    assert str(Path.home()) not in reason, "the public heartbeat must not carry the home path"


# --- the dirty tree, and both reasons at once ----------------------------------


def test_a_dirty_tree_predates_head(tmp_path):
    _repo_with_one_commit(tmp_path / "stack")
    (tmp_path / "stack" / "f.txt").write_text("modified, uncommitted")
    reading = _run(bridge._read_stack_head(tmp_path / "stack"))
    start = (datetime.fromisoformat(reading["committed_at"]) + timedelta(hours=1)).isoformat()

    value, reason = bridge._served_predates_head(_receipt(start, reading), _now())

    assert reading["dirty"] is True
    assert value is True
    assert reason == "working tree dirty"


def test_untracked_scratch_does_not_make_the_tree_dirty(tmp_path):
    """The same tracked-files-only rule working_tree_dirty uses: ambient
    scratch in the live tree would otherwise peg the field true for ever."""
    _repo_with_one_commit(tmp_path / "stack")
    (tmp_path / "stack" / "scratch_notes.json").write_text("{}")
    reading = _run(bridge._read_stack_head(tmp_path / "stack"))
    start = (datetime.fromisoformat(reading["committed_at"]) + timedelta(hours=1)).isoformat()

    value, _ = bridge._served_predates_head(_receipt(start, reading), _now())

    assert reading["dirty"] is False
    assert value is False


def test_both_reasons_are_given_when_both_hold(tmp_path):
    sha = _repo_with_one_commit(tmp_path / "stack")
    (tmp_path / "stack" / "f.txt").write_text("modified, uncommitted")
    reading = _run(bridge._read_stack_head(tmp_path / "stack"))
    committed_at = reading["committed_at"]
    start = (datetime.fromisoformat(committed_at) - timedelta(hours=1)).isoformat()

    value, reason = bridge._served_predates_head(_receipt(start, reading), _now())

    assert value is True
    assert reason == (
        f"service started {start} before HEAD {sha} committed at {committed_at}; working tree dirty"
    )


# --- every unknown is null, never false ----------------------------------------


def _clean_reading(committed_at: datetime, *, measured_at: datetime | None = None) -> dict:
    return {
        "short_sha": "abc1234",
        "committed_at": committed_at.isoformat(),
        "dirty": False,
        "error": None,
        "measured_at": (measured_at or _now()).isoformat(),
    }


def test_no_reading_yet_is_null():
    value, reason = bridge._served_predates_head(_receipt(_now().isoformat(), None), _now())
    assert value is None
    assert reason == "HEAD has not been read since service start"


def test_an_unknown_start_time_is_null():
    reading = _clean_reading(_now() - timedelta(days=1))
    for start in (None, "not a timestamp"):
        value, reason = bridge._served_predates_head(_receipt(start, reading), _now())
        assert value is None
        assert reason == "service start time unknown"


def test_a_stale_reading_is_null_never_its_old_answer():
    """A reading the probe stopped refreshing says what HEAD WAS. Its clean,
    older-than-start answer is exactly the false this field must not give."""
    now = _now()
    stale = now - timedelta(seconds=bridge.HEAD_READING_MAX_AGE + 1)
    reading = _clean_reading(now - timedelta(days=1), measured_at=stale)
    start = (now - timedelta(hours=1)).isoformat()

    value, reason = bridge._served_predates_head(_receipt(start, reading), now)

    assert value is None
    assert reason == f"HEAD reading is stale: last read {stale.isoformat()}"
    # The control: the same reading, fresh, does decide (false), so the null
    # above is the staleness and nothing else.
    fresh = _clean_reading(now - timedelta(days=1))
    assert bridge._served_predates_head(_receipt(start, fresh), now)[0] is False


def test_an_unreadable_tree_state_is_null_unless_the_commit_time_already_decides():
    now = _now()
    unread_status = {
        "short_sha": "abc1234",
        "committed_at": (now - timedelta(days=1)).isoformat(),
        "dirty": None,
        "error": "git status failed: fatal: index file corrupt",
        "measured_at": now.isoformat(),
    }
    start = (now - timedelta(hours=1)).isoformat()
    value, reason = bridge._served_predates_head(_receipt(start, unread_status), now)
    assert value is None
    assert reason == "working tree state unreadable: git status failed: fatal: index file corrupt"

    # HEAD committed after the start decides true whatever the tree holds.
    earlier_start = (now - timedelta(days=2)).isoformat()
    value, _ = bridge._served_predates_head(_receipt(earlier_start, unread_status), now)
    assert value is True


def test_a_missing_git_binary_is_null_with_the_reason(monkeypatch, tmp_path):
    _repo_with_one_commit(tmp_path / "stack")
    monkeypatch.setattr(bridge, "GIT_BIN", str(tmp_path / "no-such-git-binary"))
    reading = _run(bridge._read_stack_head(tmp_path / "stack"))
    value, reason = bridge._served_predates_head(_receipt(_now().isoformat(), reading), _now())
    assert value is None
    assert "git binary not found" in reason


def test_an_unknown_stack_repo_is_null_with_the_reason():
    reading = _run(bridge._read_stack_head(None))
    value, reason = bridge._served_predates_head(_receipt(_now().isoformat(), reading), _now())
    assert value is None
    assert reason.startswith("git metadata unreadable: the stack repo root is unknown")


# --- the probe reads, and never writes --------------------------------------


def test_the_probe_never_rewrites_the_index(tmp_path):
    """The probe re-reads the LIVE stack repo every HEAD_PROBE_INTERVAL. A plain
    `git status` refreshes a stale index and takes `.git/index.lock` to write
    it, which could collide with a deploy's own git command; the probe passes
    --no-optional-locks and must leave the index byte-identical. The control
    after it shows a plain status DOES rewrite this exact index, so the
    unchanged bytes are not vacuous."""
    repo = tmp_path / "stack"
    _repo_with_one_commit(repo)
    tracked = repo / "f.txt"
    later = time.time() + 5
    os.utime(tracked, (later, later))  # stat drift, content unchanged
    index = repo / ".git" / "index"
    before = index.read_bytes()

    reading = _run(bridge._read_stack_head(repo))

    assert reading["error"] is None and reading["dirty"] is False
    assert index.read_bytes() == before, "the probe rewrote the index"
    subprocess.run(
        ["git", "-C", str(repo), "status", "--porcelain"], check=True, capture_output=True
    )
    assert index.read_bytes() != before, (
        "control: a plain git status no longer refreshes this index, so the "
        "assertion above proves nothing"
    )


# --- the wiring: the heartbeat reads the cache, the probe moves it -----------


def test_head_moving_after_start_turns_the_heartbeat_true_and_only_the_probe_moves_it(
    monkeypatch, tmp_path
):
    """The test a pure function cannot satisfy: HEAD as read AT START is always
    committed before the start, so without a re-read this field is false for
    the life of the process."""
    from fastapi.testclient import TestClient

    repo = tmp_path / "stack"
    _repo_with_one_commit(repo)
    monkeypatch.setattr(bridge, "_STACK_REPO_ROOT", repo)
    monkeypatch.setattr(bridge, "RUNTIME_RECEIPT", _fresh_receipt())
    _run(bridge._compute_runtime_receipt())
    client = TestClient(bridge.app)

    body = client.get("/api/heartbeat").json()
    assert body["served_predates_head"] is False, body["served_predates_head_reason"]

    # HEAD moves with no restart: a commit dated after the service started.
    start = bridge.RUNTIME_RECEIPT["service_start_time"]
    moved_at = datetime.fromisoformat(start) + timedelta(minutes=5)
    (repo / "f.txt").write_text("v2")
    sha_2 = _commit_all(repo, "second", committed_at=moved_at)

    # The request path never shells out: until the probe runs, nothing moved.
    def _refuse(*args, **kwargs):
        raise AssertionError("the heartbeat request path ran a subprocess")

    with pytest.MonkeyPatch.context() as m:
        m.setattr(bridge, "_run_git_capture", _refuse)
        m.setattr(asyncio, "create_subprocess_exec", _refuse)
        assert client.get("/api/heartbeat").json()["served_predates_head"] is False

    _run(bridge._refresh_head_reading())  # one probe tick

    body = client.get("/api/heartbeat").json()
    committed_at = datetime.fromtimestamp(int(moved_at.timestamp()), timezone.utc).isoformat()
    assert body["served_predates_head"] is True
    assert body["served_predates_head_reason"] == (
        f"service started {start} before HEAD {sha_2} committed at {committed_at}"
    )
    # The start-time receipt is untouched: source_commit is what was LOADED.
    assert body["source_commit"] != sha_2


def test_the_heartbeat_reports_null_not_false_when_the_receipt_was_never_computed(monkeypatch):
    from fastapi.testclient import TestClient

    monkeypatch.setattr(bridge, "RUNTIME_RECEIPT", _fresh_receipt())
    body = TestClient(bridge.app).get("/api/heartbeat").json()
    assert "served_predates_head" in body
    assert body["served_predates_head"] is None
    assert body["served_predates_head_reason"] == "service start time unknown"


def test_the_heartbeat_reports_null_when_the_derivation_raises(monkeypatch):
    """The handler's own discipline: a subsystem that raises becomes an
    unmeasured answer, never a crash and never a false."""
    from fastapi.testclient import TestClient

    def _boom(receipt, now):
        raise RuntimeError("planted")

    monkeypatch.setattr(bridge, "_served_predates_head", _boom)
    body = TestClient(bridge.app).get("/api/heartbeat").json()
    assert body["served_predates_head"] is None
    assert body["served_predates_head_reason"] == (
        "served_predates_head could not be derived: RuntimeError: planted"
    )


def test_the_head_probe_loop_refreshes_the_reading(monkeypatch, tmp_path):
    repo = tmp_path / "stack"
    sha = _repo_with_one_commit(repo)
    monkeypatch.setattr(bridge, "_STACK_REPO_ROOT", repo)
    monkeypatch.setattr(bridge, "RUNTIME_RECEIPT", _fresh_receipt())
    monkeypatch.setattr(bridge, "HEAD_PROBE_INTERVAL", 0.01)

    async def _run_loop_briefly():
        task = asyncio.create_task(bridge._head_probe_loop())
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            await asyncio.sleep(0.02)
            reading = bridge.RUNTIME_RECEIPT.get("head_now")
            if reading and reading.get("short_sha"):
                break
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    _run(_run_loop_briefly())
    assert bridge.RUNTIME_RECEIPT["head_now"]["short_sha"] == sha


def test_the_lifespan_runs_the_probe_and_cancels_it(monkeypatch, tmp_path):
    """The loop is started by the app's lifespan and stopped by it, checked in
    the lifespan's own event loop (a TestClient's loop is torn down on exit,
    which would cancel an abandoned task too and hide the difference). The NTP
    loop and the seat socket are stubbed out: this test opens no network and
    binds nothing."""
    repo = tmp_path / "stack"
    _repo_with_one_commit(repo)
    monkeypatch.setattr(bridge, "_STACK_REPO_ROOT", repo)
    monkeypatch.setattr(bridge, "RUNTIME_RECEIPT", _fresh_receipt())
    monkeypatch.setattr(bridge, "HEAD_PROBE_INTERVAL", 0.02)

    async def _no_clock_probe():
        await asyncio.Event().wait()

    async def _no_seat_socket(app):
        return None

    monkeypatch.setattr(bridge, "_clock_probe_loop", _no_clock_probe)
    monkeypatch.setattr(bridge, "_start_seat_socket", _no_seat_socket)

    def _probe_tasks():
        return [
            t
            for t in asyncio.all_tasks()
            if not t.done() and getattr(t.get_coro(), "__name__", "") == "_head_probe_loop"
        ]

    async def scenario():
        async with bridge.lifespan(bridge.app):
            assert bridge.RUNTIME_RECEIPT["head_now"] is not None, (
                "the first reading is taken before the app serves"
            )
            assert len(_probe_tasks()) == 1, "the lifespan did not start the probe"
            start = bridge.RUNTIME_RECEIPT["service_start_time"]
            moved_at = datetime.fromisoformat(start) + timedelta(minutes=5)
            (repo / "f.txt").write_text("v2")
            sha_2 = _commit_all(repo, "second", committed_at=moved_at)
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                await asyncio.sleep(0.05)
                if bridge.RUNTIME_RECEIPT["head_now"]["short_sha"] == sha_2:
                    break
            body = await bridge.heartbeat(as_=None)
            assert body["served_predates_head"] is True, body["served_predates_head_reason"]
        leaked = _probe_tasks()
        # Stop a leaked probe HERE, bounded, before asserting: left to
        # asyncio.run's own cleanup, a probe cancelled mid-git hung the run
        # (measured on a mutant whose lifespan never cancels it) instead of
        # failing it.
        for task in leaked:
            task.cancel()
        if leaked:
            await asyncio.wait(leaked, timeout=5)
        assert leaked == [], "the probe kept running after the lifespan ended"

    _run(scenario())


def test_git_errors_on_the_public_heartbeat_carry_no_home_path():
    home = str(Path.home())
    text = f"fatal: not a git repository: '{home}/sovereign-stack/.git'\nhint: x"
    assert bridge._public_git_error(text) == (
        "fatal: not a git repository: '~/sovereign-stack/.git' | hint: x"
    )
