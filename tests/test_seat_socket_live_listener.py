"""Nothing may take a live seat socket away from the process serving it.

⚠ THIS FILE IS A MEASURED OUTAGE, NOT A HYPOTHETICAL. 2026-09-06, 21:51 EDT.

A test suite run on `49f270d` resolved `SOVEREIGN_ROOT` to the live
`~/.sovereign` (there was no per-test redirect yet), found the live seat
registry, and ran the app's lifespan. `bridge._start_seat_socket` called
`seat_socket.prepare_socket_path` on
`~/.sovereign/hq/seats/sock/bridge.sock`, which unlinked the socket the RUNNING
bridge (pid 26173, up since 15:15:02) still held on fd 10, bound a test-owned
one in its place, and closed it when the test ended.

Measured by HQ: socket birth = mtime = 21:51:28, the `sock/` directory's mtime
moved to the same second, its birth still 15:15:02. Every seat connect returned
ECONNREFUSED until the bridge was restarted by hand at ~22:15 — roughly 24
minutes of a channel that was down while the process serving it was healthy.

WHY IT WAS SILENT, AND WHY THAT MAKES IT THIS HOUSE'S FAVOURITE FAILURE SHAPE.
Unlinking a bound AF_UNIX path does not disturb the process serving it. The old
listener keeps its descriptor on a now-nameless inode and goes on accepting
nothing; every NEW connect resolves the name to whatever was bound in its
place. Nobody errors. The server's logs are clean. The only symptom is on the
caller's side, and it reads as "the bridge is down" when the bridge is fine.

TWO FIXES, AND THEY ARE NOT INTERCHANGEABLE:
  * `conftest.py` guarantee 5 stops the SUITE from resolving the live root.
    That closes the recurrence for this branch and nothing else — `main` still
    does it on any run, and any other caller still could.
  * THIS ONE is structural: `prepare_socket_path` probes before it unlinks, and
    only an UNANSWERED path may be replaced. A function that unlinks without
    looking cannot tell a stale file from a live listener, and the difference is
    the whole incident.

The 23 tests that did it are named in `test_the_incident_path_is_named`.
"""

import errno
import os
import socket
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import seat_socket as ss  # noqa: E402


@pytest.fixture
def short_sock_path():
    """A path short enough to actually bind, plus cleanup.

    ⚠ NOT pytest's `tmp_path`. AF_UNIX paths are capped near 104 bytes on macOS
    and `tmp_path` is far longer, so a bind there fails with "AF_UNIX path too
    long" — and every socket in this file is REAL, because a guard that
    distinguishes a bound socket from a stale file cannot be exercised against
    a mock. Returns a factory so a test can take more than one.

    The directory is removed at teardown; the old module-level helper leaked one
    `/tmp/ss-*` dir per call.
    """
    import shutil
    import tempfile

    made: list[Path] = []

    def make(name: str = "bridge.sock") -> Path:
        d = Path(tempfile.mkdtemp(prefix="ss-", dir="/tmp"))
        made.append(d)
        return d / name

    try:
        yield make
    finally:
        for d in made:
            shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def live_listener(short_sock_path):
    """A REAL AF_UNIX listener, held open for the duration of the test.

    Not a stub: the guard's whole job is to distinguish a socket file with a
    process behind it from one without, and only a real bound socket exercises
    that distinction.
    """
    path = short_sock_path()
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(str(path))
    srv.listen(8)
    try:
        yield path, srv
    finally:
        srv.close()
        try:
            path.unlink()
        except FileNotFoundError:
            pass


@pytest.fixture
def stale_socket_file(short_sock_path):
    """A socket FILE with nobody behind it — bound, listened, then closed
    WITHOUT unlinking, which is exactly what a killed process leaves."""
    path = short_sock_path()
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(str(path))
    srv.listen(8)
    srv.close()  # the file survives the close; nothing is listening now
    try:
        yield path
    finally:
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def _answers(path: Path) -> bool:
    """Independent of the code under test: can a client actually connect?"""
    c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    c.settimeout(0.5)
    try:
        return c.connect_ex(str(path)) == 0
    finally:
        c.close()


# ── THE GUARD ───────────────────────────────────────────────────────────────


def test_a_live_socket_is_never_stolen(live_listener):
    """⚠ THE INCIDENT ITSELF, AND THE ONLY TEST HERE THAT NAMES NO NEW SYMBOL.

    Every other red-on-baseline test in this file fails on `49f270d` with
    AttributeError, because the guard's names do not exist there. That is an
    honest red and a weak one: it proves the fix is absent, not that the bug is
    present. This one is written entirely against the pre-existing API and
    swallows OSError, so on `49f270d` it runs to completion and fails on
    BEHAVIOUR — the socket file is replaced and the incumbent, still alive, is
    unreachable. That is the 21:51 outage in three assertions.

    Measured on 49f270d: the call does not raise, `path` is a NEW inode, and
    `_answers(path)` is False while the fixture's listener object is untouched
    and healthy — which is precisely why the outage was silent.
    """
    path, srv = live_listener
    inode_before = os.lstat(path).st_ino
    assert _answers(path), "premise: the fixture's listener must be answering"

    try:
        ss.prepare_socket_path(path)
    except OSError:
        pass  # a refusal is the correct outcome; this test is about the effect

    assert path.exists(), "the live socket's path was unlinked"
    assert os.lstat(path).st_ino == inode_before, (
        "the live socket was REPLACED: the process serving it keeps its "
        "descriptor on a nameless inode and every new connect goes elsewhere — "
        "the 2026-09-06 21:51 outage, exactly"
    )
    assert _answers(path), "the incumbent listener is no longer reachable"
    assert srv.fileno() != -1, "premise: the incumbent was never closed"


def test_a_live_listener_is_refused_and_left_alone(live_listener):
    """RED ON 49f270d — there it unlinks and returns, and the assertions below
    about the surviving listener are what fail.

    Three separate claims, because "it raised" is not enough: the refusal must
    also leave the incumbent SERVING and leave its inode in place. The 21:51
    outage is exactly the case where the file was replaced and the process was
    fine.
    """
    path, _srv = live_listener
    inode_before = os.lstat(path).st_ino
    assert _answers(path), "premise: the fixture's listener must be answering"

    with pytest.raises(ss.LiveListenerPresent) as exc:
        ss.prepare_socket_path(path)

    assert str(path) in str(exc.value)
    assert "live listener" in str(exc.value)
    # The incumbent is untouched: same inode, still answering.
    assert path.exists(), "the guard unlinked a live socket"
    assert os.lstat(path).st_ino == inode_before, "the socket was replaced"
    assert _answers(path), "the live listener stopped answering"


def test_start_refuses_rather_than_stealing_a_live_socket(live_listener):
    """The same guarantee through the function the bridge actually calls.
    `prepare_socket_path` is an implementation detail; `start()` is the door,
    and `bridge._start_seat_socket` swallows exceptions — so if the refusal did
    not reach this far it would be invisible in production."""
    path, _srv = live_listener
    inode_before = os.lstat(path).st_ino

    async def app(scope, receive, send):  # pragma: no cover — never reached
        raise AssertionError("start() served an app on a socket it must refuse")

    import asyncio

    with pytest.raises(ss.LiveListenerPresent):
        asyncio.run(ss.start(app, path))

    assert os.lstat(path).st_ino == inode_before
    assert _answers(path)


def test_a_stale_socket_file_is_still_replaced(stale_socket_file):
    """THE OTHER HALF, AND THE REASON THE GUARD IS A PROBE AND NOT A BAN.
    A bridge restarting after a crash finds its own socket file with nobody
    behind it and MUST be able to take it. A guard that refused every existing
    socket would turn one outage into a permanent one.

    Green on both sides of the fix, deliberately.
    """
    assert stale_socket_file.exists()
    assert not _answers(stale_socket_file), "premise: nothing may be listening"
    inode_before = os.lstat(stale_socket_file).st_ino

    returned = ss.prepare_socket_path(stale_socket_file)

    assert returned == stale_socket_file
    assert not stale_socket_file.exists(), "the stale file was not cleared"
    # And a real bind now succeeds on the cleared path, with a NEW inode.
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        srv.bind(str(stale_socket_file))
        srv.listen(1)
        assert os.lstat(stale_socket_file).st_ino != inode_before
    finally:
        srv.close()


def test_a_free_path_is_untouched(short_sock_path):
    """No file, no probe, no refusal — the ordinary first start."""
    path = short_sock_path()
    assert ss.prepare_socket_path(path) == path
    assert not path.exists()


# ── THE PROBE'S OWN CONTRACT ────────────────────────────────────────────────


def test_the_probe_calls_a_listener_live(live_listener):
    path, _srv = live_listener
    assert ss.socket_is_live(path) is True


def test_the_probe_calls_a_stale_file_dead(stale_socket_file):
    assert ss.socket_is_live(stale_socket_file) is False


def test_the_probe_calls_a_missing_path_dead(short_sock_path):
    """ENOENT is as conclusive as ECONNREFUSED: there is nothing there."""
    assert ss.socket_is_live(short_sock_path()) is False


def test_a_live_listener_answers_through_the_err_zero_branch(live_listener):
    """WHICH BRANCH ACTUALLY DECIDES, measured rather than assumed.

    `socket_is_live` calls `settimeout()` before `connect_ex`, which puts the
    socket in non-blocking mode — and on some platforms a non-blocking connect
    reports `EINPROGRESS`/`EAGAIN` instead of `0`. Both are classified LIVE, so
    the guard holds either way, but "holds either way" is how a dead branch
    hides. Measured here (macOS, CPython 3.12): a live AF_UNIX listener returns
    exactly **0**, a stale file returns **61 ECONNREFUSED**, a missing path
    returns **2 ENOENT**. So `err == 0` is the branch that fires, not the
    catch-all.
    """
    path, _srv = live_listener
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(ss.PROBE_TIMEOUT_SECONDS)
    try:
        assert sock.connect_ex(str(path)) == 0
    finally:
        sock.close()


def test_a_real_unprobeable_path_counts_as_LIVE():
    """The fail-closed branch with a REAL specimen, not a monkeypatched errno.

    An AF_UNIX path over ~104 bytes makes `connect_ex` RAISE `OSError`
    ("AF_UNIX path too long") rather than return an errno — so the
    `except OSError` arm is genuinely reachable in the world, and this pins it
    with a path the kernel itself rejects. Unsure still means live.
    """
    too_long = Path("/tmp") / ("d" * 90) / ("e" * 90) / "bridge.sock"
    assert ss.socket_is_live(too_long) is True


@pytest.mark.parametrize(
    "err", [errno.EACCES, errno.EAGAIN, errno.ETIMEDOUT, errno.EPERM, 0xDEAD]
)
def test_an_unprobeable_socket_counts_as_LIVE(monkeypatch, short_sock_path, err):
    """⚠ FAIL CLOSED, AND THIS IS THE ASSERTION THAT SAYS SO.

    A permissions problem raises EACCES; an over-long path raises outright.
    Reading either as "dead" would unlink a socket somebody is serving on — the
    exact 21:51 failure, reached by a different road. Unsure must mean live.

    ⚠ AND ECONNREFUSED IS NOT THE CLEAN PROOF THIS DOCSTRING ONCE CLAIMED.
    It said "a full backlog times out", which is Linux; on BSD/macOS a full
    backlog REFUSES. That is why a refusal now has to persist across
    `PROBE_ATTEMPTS` — see the full-backlog block above.
    """
    path = short_sock_path()

    def fake_connect_ex(self, address):
        return err

    monkeypatch.setattr(socket.socket, "connect_ex", fake_connect_ex)
    assert ss.socket_is_live(path) is True


def test_a_probe_that_cannot_even_run_counts_as_LIVE(monkeypatch, short_sock_path):
    """Same rule one layer out: if the probe itself raises, we learned nothing,
    and nothing is not permission to unlink."""
    path = short_sock_path()

    def boom(self, address):
        raise OSError("the probe could not run")

    monkeypatch.setattr(socket.socket, "connect_ex", boom)
    assert ss.socket_is_live(path) is True


# ── THE FULL-BACKLOG AMBIGUITY (Grok review, 2026-09-06) ────────────────────
#
# On BSD/macOS a connect to a LIVE listener whose backlog is full returns
# ECONNREFUSED — the identical errno a stale socket file returns. Measured on
# macOS 26.6.1 / arm64, CPython 3.12: `listen(1)` plus one held connection makes
# every subsequent connect_ex return 61. The first version of `socket_is_live`
# read one refusal as proof of death, so a live bridge that was momentarily
# behind would have been classified stale and replaced — the 21:51 outage by a
# narrower road.


def _saturate(path, srv):
    """Fill `srv`'s backlog and return the held client sockets.

    Deterministic on this kernel BECAUSE the fixture uses `listen(1)`: the
    first connect is queued, the second is refused. Asserted, not assumed — if
    a future kernel queues more, the assertion says so instead of the test
    quietly measuring nothing.
    """
    held = []
    for _ in range(8):
        c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        c.settimeout(0.5)
        if c.connect_ex(str(path)) == 0:
            held.append(c)
        else:
            c.close()
            break
    else:  # pragma: no cover — kernel change
        for c in held:
            c.close()
        pytest.skip("backlog never saturated on this kernel; the premise is gone")
    return held


@pytest.fixture
def saturated_listener(short_sock_path):
    """A REAL listener, alive and healthy, whose backlog is full."""
    path = short_sock_path()
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(str(path))
    srv.listen(1)
    held = _saturate(path, srv)
    try:
        yield path, srv, held
    finally:
        for c in held:
            c.close()
        srv.close()


def test_a_full_backlog_refuses_exactly_like_a_stale_file(saturated_listener):
    """THE PREMISE, PINNED. If this ever stops being true the two tests below
    are measuring a world that no longer exists, and they should fail loudly
    rather than keep passing for the wrong reason."""
    path, _srv, _held = saturated_listener
    c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    c.settimeout(0.5)
    try:
        assert c.connect_ex(str(path)) == errno.ECONNREFUSED
    finally:
        c.close()


def test_a_backlog_that_drains_inside_the_window_reads_live(saturated_listener):
    """WHAT THE RETRY BUYS, proved rather than asserted.

    A momentarily-full backlog is the realistic case: a busy bridge is behind
    for milliseconds, not forever. The listener accepts one connection partway
    through the probe window, and `socket_is_live` must come back True.

    Timing has margin on both sides — the drain fires at ~0.35s, the window is
    3 probes over ~0.6s — so this is not a stopwatch test.
    """
    path, srv, _held = saturated_listener
    accepted = []

    def drain():
        time.sleep(0.35)
        try:
            conn, _ = srv.accept()
            accepted.append(conn)
        except OSError:  # pragma: no cover
            pass

    t = threading.Thread(target=drain, daemon=True)
    t.start()
    try:
        assert ss.socket_is_live(path) is True, (
            "a live listener whose backlog drained mid-window was reported dead"
        )
    finally:
        t.join(timeout=2)
        for conn in accepted:
            conn.close()
    assert accepted, "premise: the drain must actually have accepted something"


def test_RESIDUAL_a_permanently_saturated_backlog_still_reads_dead(saturated_listener):
    """⚠ THE HOLE THAT IS STILL OPEN, NAMED RATHER THAN PAPERED OVER.

    A listener whose backlog stays full for the ENTIRE window is still reported
    dead, and `prepare_socket_path` would replace it. Measured: 4 consecutive
    probes over ~600ms against a permanently saturated listener all return
    ECONNREFUSED.

    THE RETRY NARROWS THIS RACE; IT DOES NOT CLOSE IT, and this test exists so
    nobody reads the retry as a fix it is not. ECONNREFUSED carries nothing
    that separates "stale file" from "saturated listener", and macOS offers no
    cheap second signal — there is no `/proc/net/unix`. Closing it properly
    needs a different kind of evidence (a pidfile the bridge owns, or a
    `libproc` walk of open descriptors), which is a design change and not this
    lane's to make.

    This asserts the CURRENT behaviour on purpose. When someone closes the
    hole, this test goes red, and the red is the notification.
    """
    path, _srv, _held = saturated_listener
    assert ss.socket_is_live(path) is False


def test_a_single_refusal_is_not_enough(monkeypatch, short_sock_path):
    """The retry logic itself, isolated from kernel timing: refuse once, then
    answer. One refusal must not decide."""
    path = short_sock_path()
    seq = [errno.ECONNREFUSED, 0, 0]

    def fake_connect_ex(self, address):
        return seq.pop(0) if seq else 0

    monkeypatch.setattr(socket.socket, "connect_ex", fake_connect_ex)
    monkeypatch.setattr(ss, "PROBE_RETRY_INTERVAL_SECONDS", 0.0)
    assert ss.socket_is_live(path, interval=0.0) is True
    assert len(seq) == 1, "the probe stopped as soon as it got a non-refusal"


def test_every_attempt_must_refuse_before_a_path_is_called_dead(monkeypatch, short_sock_path):
    """The other half: all of them refusing IS the proof, and the count is the
    module constant rather than a number this test made up."""
    path = short_sock_path()
    calls = []

    def fake_connect_ex(self, address):
        calls.append(1)
        return errno.ECONNREFUSED

    monkeypatch.setattr(socket.socket, "connect_ex", fake_connect_ex)
    assert ss.socket_is_live(path, interval=0.0) is False
    assert len(calls) == ss.PROBE_ATTEMPTS


def test_the_guard_can_fail(monkeypatch, live_listener):
    """Experimental law #2 applied to this guard: it must be demonstrably able
    to NOT fire. With the probe forced to report dead, the same call unlinks —
    which is 49f270d's behaviour, reproduced deliberately so a green run above
    is evidence about the probe and not about an unreachable branch.

    `monkeypatch`, not a hand-rolled try/finally: a raise between the
    assignment and the restore would leave the guard DISABLED for the rest of
    the session, and a test that can silently switch off the protection it
    verifies is its own small fail-open.
    """
    path, _srv = live_listener
    monkeypatch.setattr(ss, "socket_is_live", lambda *a, **k: False)
    ss.prepare_socket_path(path)
    assert not path.exists(), "with the probe disabled the old path is unlinked"


# ── THE INCIDENT, NAMED ─────────────────────────────────────────────────────


def test_the_incident_path_is_named():
    """WHICH TESTS DID IT, recorded here rather than only in a commit message,
    because the next person to widen a fixture needs to find this.

    Reproduced 2026-09-06 on pristine `49f270d` with `SOVEREIGN_ROOT` pointed
    at a THROWAWAY root (never the live path again) and
    `prepare_socket_path` wrapped to record `PYTEST_CURRENT_TEST`:

      * 31 calls total in one full suite run.
      * 8 of them from `tests/test_seat_socket.py`, each on a root that test
        created — CORRECT, and untouched by this fix.
      * 23 of them on the AMBIENT root, every one from
        `tests/test_approval_gate.py`, one per test, all through its `client`
        fixture — the only fixture in the suite that enters `TestClient` as a
        CONTEXT MANAGER (`with TestClient(bridge.app) as c:`), which is what
        runs the app lifespan and therefore `_start_seat_socket`. It sets no
        `SOVEREIGN_ROOT`. In production 22 of those 23 unlinked a socket that
        already existed; the first unlinked Anthony's live one.

    The fixture is not at fault for entering the context manager — it does that
    for a stated reason (one event loop for the client's lifetime). It is at
    fault for nothing, in fact: the ambient root was the defect, and the
    unconditional unlink was what made an isolation slip cost an outage.
    """
    approval = Path(__file__).resolve().parent / "test_approval_gate.py"
    assert approval.exists(), "the file this incident names has moved"
    src = approval.read_text()
    # The exact construct that runs the lifespan. If it ever goes away, this
    # docstring is describing a world that no longer exists and should be
    # re-measured rather than trusted.
    assert "with TestClient(bridge.app) as c:" in src, (
        "test_approval_gate.py no longer enters TestClient as a context "
        "manager; re-measure which tests run the lifespan before trusting the "
        "incident account above"
    )
