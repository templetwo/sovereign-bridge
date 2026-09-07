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
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import seat_socket as ss  # noqa: E402


def _short_sock_path(tmp_path: Path, name: str = "bridge.sock") -> Path:
    """AF_UNIX paths are capped near 104 bytes on macOS and pytest's tmp_path is
    long. A real short directory, not a mock, so the bind under test is real."""
    import tempfile

    d = Path(tempfile.mkdtemp(prefix="ss-", dir="/tmp"))
    return d / name


@pytest.fixture
def live_listener():
    """A REAL AF_UNIX listener, held open for the duration of the test.

    Not a stub: the guard's whole job is to distinguish a socket file with a
    process behind it from one without, and only a real bound socket exercises
    that distinction.
    """
    path = _short_sock_path(Path("/tmp"))
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
def stale_socket_file():
    """A socket FILE with nobody behind it — bound, listened, then closed
    WITHOUT unlinking, which is exactly what a killed process leaves."""
    path = _short_sock_path(Path("/tmp"))
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


def test_a_free_path_is_untouched(tmp_path):
    """No file, no probe, no refusal — the ordinary first start."""
    path = _short_sock_path(tmp_path)
    assert ss.prepare_socket_path(path) == path
    assert not path.exists()


# ── THE PROBE'S OWN CONTRACT ────────────────────────────────────────────────


def test_the_probe_calls_a_listener_live(live_listener):
    path, _srv = live_listener
    assert ss.socket_is_live(path) is True


def test_the_probe_calls_a_stale_file_dead(stale_socket_file):
    assert ss.socket_is_live(stale_socket_file) is False


def test_the_probe_calls_a_missing_path_dead(tmp_path):
    """ENOENT is as conclusive as ECONNREFUSED: there is nothing there."""
    assert ss.socket_is_live(_short_sock_path(tmp_path)) is False


@pytest.mark.parametrize(
    "err", [errno.EACCES, errno.EAGAIN, errno.ETIMEDOUT, errno.EPERM, 0xDEAD]
)
def test_an_unprobeable_socket_counts_as_LIVE(monkeypatch, tmp_path, err):
    """⚠ FAIL CLOSED, AND THIS IS THE ASSERTION THAT SAYS SO.

    ECONNREFUSED is the ONLY answer that proves nobody is listening. A full
    backlog times out; a permissions problem raises EACCES. Reading either as
    "dead" would unlink a socket somebody is serving on — the exact 21:51
    failure, reached by a different road. Unsure must mean live.
    """
    path = _short_sock_path(tmp_path)

    def fake_connect_ex(self, address):
        return err

    monkeypatch.setattr(socket.socket, "connect_ex", fake_connect_ex)
    assert ss.socket_is_live(path) is True


def test_a_probe_that_cannot_even_run_counts_as_LIVE(monkeypatch, tmp_path):
    """Same rule one layer out: if the probe itself raises, we learned nothing,
    and nothing is not permission to unlink."""
    path = _short_sock_path(tmp_path)

    def boom(self, address):
        raise OSError("the probe could not run")

    monkeypatch.setattr(socket.socket, "connect_ex", boom)
    assert ss.socket_is_live(path) is True


def test_the_guard_can_fail(live_listener):
    """Experimental law #2 applied to this guard: it must be demonstrably able
    to NOT fire. With the probe forced to report dead, the same call unlinks —
    which is 49f270d's behaviour, reproduced deliberately so a green run above
    is evidence about the probe and not about an unreachable branch."""
    path, _srv = live_listener
    ss_socket_is_live = ss.socket_is_live
    try:
        ss.socket_is_live = lambda *a, **k: False
        ss.prepare_socket_path(path)
    finally:
        ss.socket_is_live = ss_socket_is_live
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
