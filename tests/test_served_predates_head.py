"""served_predates_head on /api/heartbeat — design A4 (next-phase plan 1, Task 10).

`source_commit`, `working_tree_dirty` and `service_start_time` are read ONCE,
at process start: they say what the process loaded. HEAD can move after that
without a restart (a commit, a merge, a fast-forward, a reset, a checkout in the
live tree: a checkout is a deploy that nothing announces). So the bridge
RE-READS the stack's HEAD off the request path and derives one field:

  true   any of: service_start_time is older than HEAD's commit time (the
         spec's rule); HEAD is not the commit the process loaded (full shas);
         the tree was dirty at start; the tree is dirty now
  false  every one of those was read and none holds
  null   anything needed to decide was not read, with the reason; NEVER false

The time rule alone reads false when HEAD moves to a commit dated BEFORE the
start (a checkout of an older commit, a reset, a fast-forward to commits made
before the bridge last started), and a process that loaded uncommitted edits
still serves them after the tree is cleaned; the sha rule and the start-time
`working_tree_dirty` close those (Task 10 fix round 1, review findings 1 and 2).

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
        "source_commit_full": None,
    }


_AS_READ = object()


def _receipt(
    start: str | None,
    reading: dict | None,
    *,
    loaded: str | None | object = _AS_READ,
    dirty_at_start: bool | None = False,
) -> dict:
    """A receipt for a process that started at `start` on a CLEAN load of the
    commit `reading` names, unless told otherwise: the loaded commit is the
    reading's own (full sha and short form) and the tree was clean at start.
    The brief's three cases keep their meaning under the rules this round
    added; a test about the loaded commit or the tree at start says so."""
    receipt = _fresh_receipt()
    receipt["service_start_time"] = start
    receipt["head_now"] = reading
    if loaded is _AS_READ:
        receipt["source_commit_full"] = (reading or {}).get("sha")
        receipt["source_commit"] = (reading or {}).get("short_sha")
    else:
        receipt["source_commit_full"] = loaded
        receipt["source_commit"] = loaded[:7] if isinstance(loaded, str) else None
    receipt["working_tree_dirty"] = dirty_at_start
    return receipt


def _now() -> datetime:
    return datetime.now(timezone.utc)


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    """The heartbeat's other subsystems, held still, so a verdict here is about
    this field and nothing here reaches Anthony's live store.

    Beyond the isolation tests/test_runtime_receipt.py uses (comms in tmp, the
    clock probe and the tool inventory faked), the four censuses are stubbed
    too: aperture, gate, attribution and signals each read the LIVE
    ~/.sovereign through the stack modules bridge.py imports. Measured with an
    audit hook before this was added (Task 10 fix round 1, review cannot-verify
    4): about 2,800 opens and listings there per heartbeat, plus no-op mkdir
    and same-mode chmod calls from the oauth and queue modules the gate census
    imports; after it, none from any test in this file."""
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

    def _held(name):
        def _measure(now):
            return {"status": f"{name} held still by tests/test_served_predates_head.py"}

        return _measure

    async def _signals_held():
        return {"source": "held still by tests/test_served_predates_head.py", "error": None}

    monkeypatch.setattr(bridge, "_measure_aperture", _held("aperture"))
    monkeypatch.setattr(bridge, "_measure_gate", _held("gate"))
    monkeypatch.setattr(bridge, "_measure_attribution", _held("attribution"))
    monkeypatch.setattr(bridge, "_measure_signals", _signals_held)


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
        "HEAD is the commit the service loaded; working tree clean at service start and now"
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
        "sha": "abc1234" + "0" * 33,
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
        "sha": "abc1234" + "0" * 33,
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


def test_the_probe_never_rewrites_the_index(monkeypatch, tmp_path):
    """The probe re-reads the LIVE stack repo every HEAD_PROBE_INTERVAL. A plain
    `git status` refreshes a stale index and takes `.git/index.lock` to write
    it, which could collide with a deploy's own git command; the probe passes
    --no-optional-locks and must leave the index byte-identical. The control
    after it shows a plain status DOES rewrite this exact index, so the
    unchanged bytes are not vacuous.

    GIT_OPTIONAL_LOCKS=0 in the environment turns the refresh off for every git
    call, the probe's and the control's alike: the control then fails, and a
    probe that dropped its own flag would pass unseen. Measured in the Task 10
    fix-round-1 scratch-HOME harness, which sets it; so the test sets its own."""
    monkeypatch.delenv("GIT_OPTIONAL_LOCKS", raising=False)
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
    loaded = bridge.RUNTIME_RECEIPT["source_commit"]
    assert body["served_predates_head"] is True
    # A commit made after the start fires both HEAD rules, in the fixed order.
    assert body["served_predates_head_reason"] == (
        f"service started {start} before HEAD {sha_2} committed at {committed_at}; "
        f"HEAD {sha_2} is not the commit the service loaded, {loaded}"
    )
    # The start-time receipt is untouched: source_commit is what was LOADED.
    assert body["source_commit"] == loaded != sha_2


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


# --- the loaded commit: HEAD moved to an OLDER-dated commit (review finding 1) --


def _git(path: Path, *args: str) -> str:
    out = subprocess.run(["git", *args], cwd=path, check=True, capture_output=True, text=True)
    return out.stdout.strip()


def _two_commits_before_now(repo: Path) -> tuple[str, str]:
    """(older, newer) short shas, both committed before the service starts."""
    _init_git_repo(repo)
    now = _now()
    (repo / "f.txt").write_text("v1")
    older = _commit_all(repo, "older", committed_at=now - timedelta(hours=2))
    (repo / "f.txt").write_text("v2")
    newer = _commit_all(repo, "newer", committed_at=now - timedelta(hours=1))
    return older, newer


def _start_on(monkeypatch, repo: Path):
    """The process starts on `repo` as it stands: the real start-time receipt,
    and a client for the real heartbeat route."""
    from fastapi.testclient import TestClient

    monkeypatch.setattr(bridge, "_STACK_REPO_ROOT", repo)
    monkeypatch.setattr(bridge, "RUNTIME_RECEIPT", _fresh_receipt())
    _run(bridge._compute_runtime_receipt())
    return TestClient(bridge.app)


@pytest.mark.parametrize("move", ["checkout", "reset"])
def test_head_moved_back_to_an_older_commit_predates_head(monkeypatch, tmp_path, move):
    """HEAD moves after the start to a commit dated BEFORE the start, and the
    tree is clean: the time rule cannot fire, so without the sha rule the field
    read false while the process served what it had loaded."""
    repo = tmp_path / "stack"
    older, loaded = _two_commits_before_now(repo)
    client = _start_on(monkeypatch, repo)
    assert bridge.RUNTIME_RECEIPT["source_commit"] == loaded
    assert bridge.RUNTIME_RECEIPT["source_commit_full"] == _git(repo, "rev-parse", "HEAD")
    body = client.get("/api/heartbeat").json()
    assert body["served_predates_head"] is False, body["served_predates_head_reason"]

    if move == "checkout":
        _git(repo, "checkout", "-q", older)
    else:
        _git(repo, "reset", "-q", "--hard", older)
    _run(bridge._refresh_head_reading())

    body = client.get("/api/heartbeat").json()
    assert body["served_predates_head"] is True
    # The sha rule alone: the older commit is dated before the start and the
    # tree is clean, so neither the time rule nor a dirty tree speaks.
    assert body["served_predates_head_reason"] == (
        f"HEAD {older} is not the commit the service loaded, {loaded}"
    )


def test_a_fast_forward_to_commits_made_before_start_predates_head(monkeypatch, tmp_path):
    """This house's normal deploy with the kickstart forgotten: a branch tip
    committed before the bridge last started is fast-forwarded into the live
    tree afterwards. Its commit time is before the start, so only the sha rule
    sees it."""
    repo = tmp_path / "stack"
    _init_git_repo(repo)
    now = _now()
    (repo / "f.txt").write_text("v1")
    base = _commit_all(repo, "base", committed_at=now - timedelta(hours=2))
    trunk = _git(repo, "rev-parse", "--abbrev-ref", "HEAD")
    _git(repo, "checkout", "-q", "-b", "feature")
    (repo / "f.txt").write_text("v2")
    tip = _commit_all(repo, "feature tip", committed_at=now - timedelta(hours=1))
    _git(repo, "checkout", "-q", trunk)
    client = _start_on(monkeypatch, repo)
    assert client.get("/api/heartbeat").json()["served_predates_head"] is False

    _git(repo, "merge", "-q", "--ff-only", "feature")
    _run(bridge._refresh_head_reading())

    body = client.get("/api/heartbeat").json()
    assert body["served_predates_head"] is True
    assert body["served_predates_head_reason"] == (
        f"HEAD {tip} is not the commit the service loaded, {base}"
    )


def test_a_longer_short_form_of_the_loaded_commit_is_not_a_move(monkeypatch, tmp_path):
    """The rule compares FULL shas. Git lengthens its short forms as a repo
    grows (or when core.abbrev changes), so the commit the process loaded can
    come back spelled longer; that must not read as HEAD having moved."""
    repo = tmp_path / "stack"
    _repo_with_one_commit(repo)
    client = _start_on(monkeypatch, repo)
    _git(repo, "config", "core.abbrev", "12")
    _run(bridge._refresh_head_reading())

    loaded = bridge.RUNTIME_RECEIPT["source_commit"]
    now_spelled = bridge.RUNTIME_RECEIPT["head_now"]["short_sha"]
    # The control: the two spellings differ, so comparing short forms would
    # have called this a move.
    assert now_spelled != loaded and now_spelled.startswith(loaded)
    body = client.get("/api/heartbeat").json()
    assert body["served_predates_head"] is False, body["served_predates_head_reason"]


def test_two_commits_sharing_the_loaded_short_form_are_told_apart():
    """...and the converse: a short form names one commit only while it is
    unique, so a HEAD that shares the loaded commit's short form is still
    another commit."""
    now = _now()
    reading = _clean_reading(now - timedelta(days=1))  # abc1234 + "0" * 33
    other = "abc1234" + "f" * 33
    start = (now - timedelta(hours=1)).isoformat()

    value, reason = bridge._served_predates_head(_receipt(start, reading, loaded=other), now)

    assert value is True
    assert reason == "HEAD abc1234 is not the commit the service loaded, abc1234"


def test_a_loaded_commit_that_cannot_be_pinned_to_a_full_sha_is_null(monkeypatch, tmp_path):
    """The full sha is taken from the first HEAD reading at start and kept only
    when that reading IS source_commit. If HEAD moved between the two
    start-time reads, the process may have loaded either commit, so the field
    cannot compare against one: null with the reason, never false."""
    repo = tmp_path / "stack"
    older, loaded = _two_commits_before_now(repo)
    older_full = _git(repo, "rev-parse", older)
    real_read = bridge._read_stack_head

    async def _first_read_sees_another_commit(root):
        reading = await real_read(root)
        reading["sha"], reading["short_sha"] = older_full, older
        return reading

    monkeypatch.setattr(bridge, "_read_stack_head", _first_read_sees_another_commit)
    _start_on(monkeypatch, repo)
    monkeypatch.setattr(bridge, "_read_stack_head", real_read)
    assert bridge.RUNTIME_RECEIPT["source_commit"] == loaded
    assert bridge.RUNTIME_RECEIPT["source_commit_full"] is None

    _run(bridge._refresh_head_reading())  # HEAD is the loaded commit, the tree clean
    value, reason = bridge._served_predates_head(bridge.RUNTIME_RECEIPT, _now())

    assert value is None
    assert reason == (
        f"the commit the service loaded is unknown: source_commit {loaded} could not be "
        "pinned to a full sha at service start"
    )


def test_an_unknown_loaded_commit_is_null_but_a_decided_true_stands():
    now = _now()
    reading = _clean_reading(now - timedelta(days=1))
    start = (now - timedelta(hours=1)).isoformat()

    value, reason = bridge._served_predates_head(_receipt(start, reading, loaded=None), now)
    assert value is None
    assert reason == (
        "the commit the service loaded is unknown: source_commit was not read at service start"
    )

    # A rule that does not need the loaded commit still decides.
    earlier = (now - timedelta(days=2)).isoformat()
    value, reason = bridge._served_predates_head(_receipt(earlier, reading, loaded=None), now)
    assert value is True
    assert reason.startswith(f"service started {earlier} before HEAD abc1234")


# --- the tree at start (review finding 2) ------------------------------------


def test_a_tree_dirty_at_start_and_clean_now_still_predates_head(monkeypatch, tmp_path):
    """The process loaded uncommitted edits; they are reverted afterwards with
    HEAD unchanged. The tree reads clean NOW, and the process still serves the
    edits it loaded, which the start-time working_tree_dirty beside the field
    already says."""
    repo = tmp_path / "stack"
    _repo_with_one_commit(repo)  # f.txt holds "v1"
    (repo / "f.txt").write_text("loaded, never committed")
    client = _start_on(monkeypatch, repo)
    assert bridge.RUNTIME_RECEIPT["working_tree_dirty"] is True

    (repo / "f.txt").write_text("v1")  # the edits reverted, HEAD unchanged
    _run(bridge._refresh_head_reading())
    assert bridge.RUNTIME_RECEIPT["head_now"]["dirty"] is False, "control: clean NOW"

    body = client.get("/api/heartbeat").json()
    assert body["working_tree_dirty"] is True
    assert body["served_predates_head"] is True
    assert body["served_predates_head_reason"] == "working tree dirty at service start"


def test_an_unknown_tree_state_at_start_is_null_but_a_decided_true_stands():
    now = _now()
    reading = _clean_reading(now - timedelta(days=1))
    start = (now - timedelta(hours=1)).isoformat()

    value, reason = bridge._served_predates_head(_receipt(start, reading, dirty_at_start=None), now)
    assert value is None
    assert reason == "working tree state at service start unknown"

    earlier = (now - timedelta(days=2)).isoformat()
    value, _ = bridge._served_predates_head(_receipt(earlier, reading, dirty_at_start=None), now)
    assert value is True


def test_every_true_reason_in_its_fixed_order():
    """All four rules at once, in the order the docstring fixes."""
    now = _now()
    reading = dict(_clean_reading(now - timedelta(hours=1)), dirty=True)
    start = (now - timedelta(hours=2)).isoformat()
    other = "1234567" + "f" * 33

    value, reason = bridge._served_predates_head(
        _receipt(start, reading, loaded=other, dirty_at_start=True), now
    )

    assert value is True
    assert reason == (
        f"service started {start} before HEAD abc1234 committed at {reading['committed_at']}; "
        "HEAD abc1234 is not the commit the service loaded, 1234567; "
        "working tree dirty at service start; working tree dirty"
    )


# --- the deployed shape, in-process (review cannot-verify 5) -------------------


def test_through_the_lifespan_and_the_route_the_field_follows_head(monkeypatch, tmp_path):
    """The real lifespan takes the receipt and runs the real probe loop, and
    every answer here comes over GET /api/heartbeat, so this is the deployed
    shape short of a deployed process: false on the loaded commit, true after a
    commit made after the start, true after a checkout of an older commit,
    false again back on the loaded commit. The probe interval is shortened; the
    live check after the deploy stays Task 12's."""
    from fastapi.testclient import TestClient

    repo = tmp_path / "stack"
    older, loaded = _two_commits_before_now(repo)
    monkeypatch.setattr(bridge, "_STACK_REPO_ROOT", repo)
    monkeypatch.setattr(bridge, "RUNTIME_RECEIPT", _fresh_receipt())
    monkeypatch.setattr(bridge, "HEAD_PROBE_INTERVAL", 0.05)

    async def _no_clock_probe():
        await asyncio.Event().wait()

    async def _no_seat_socket(app):
        return None

    monkeypatch.setattr(bridge, "_clock_probe_loop", _no_clock_probe)
    monkeypatch.setattr(bridge, "_start_seat_socket", _no_seat_socket)

    def _until(client, predicate, what):
        deadline = time.monotonic() + 10
        body = None
        while time.monotonic() < deadline:
            body = client.get("/api/heartbeat").json()
            if predicate(body):
                return body
            time.sleep(0.02)
        raise AssertionError(f"the heartbeat never showed {what}: {body}")

    with TestClient(bridge.app) as client:
        body = client.get("/api/heartbeat").json()
        assert body["served_predates_head"] is False, body["served_predates_head_reason"]
        start = body["service_start_time"]

        (repo / "f.txt").write_text("v3")
        moved_at = datetime.fromisoformat(start) + timedelta(minutes=5)
        newest = _commit_all(repo, "after the start", committed_at=moved_at)
        body = _until(client, lambda b: b["served_predates_head"] is True, "the new commit")
        assert body["served_predates_head_reason"].startswith(
            f"service started {start} before HEAD {newest} committed at "
        )

        _git(repo, "checkout", "-q", older)
        body = _until(
            client,
            lambda b: (b["served_predates_head_reason"] or "").startswith(f"HEAD {older} "),
            "the checkout of the older commit",
        )
        assert body["served_predates_head"] is True
        assert body["served_predates_head_reason"] == (
            f"HEAD {older} is not the commit the service loaded, {loaded}"
        )

        _git(repo, "checkout", "-q", loaded)
        body = _until(
            client, lambda b: b["served_predates_head"] is False, "HEAD back on the loaded commit"
        )
        assert body["source_commit"] == loaded
