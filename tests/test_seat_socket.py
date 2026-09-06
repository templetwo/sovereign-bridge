"""The seat SOCKET — the transport that makes seat identity a fact about a
PROCESS instead of a claim in a header.

tests/test_seat_identity.py proves what the bridge does with a verified peer.
It cannot prove the verification itself, because it stamps the scope extension
by hand. THIS file proves the other half, for real: a real Unix socket, a real
subprocess on the other end, real kernel peer credentials, a real read of that
process's environment. Neither file is sufficient alone — one would pass
against a listener that stamped anything it liked, the other against a bridge
that ignored the stamp.

⚠ THE END-TO-END TESTS ARE THE POINT. Everything else here is a unit test of a
part, and a part can be right while the assembly is wrong. The Codex review's
exact impersonation scenario is reproduced at the bottom of this file over an
actual socket with an actual curl, and it must 401.

WHY NOT pytest's tmp_path FOR THE SOCKET: macOS caps a Unix socket path
(sun_path) at 104 bytes. pytest's tmp_path is routinely longer than that on its
own, and the socket sits three directories below it. A test that quietly fails
to bind would look exactly like a test that passed, so `short_root` below binds
under /tmp instead. Files that are not sockets still use tmp_path.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import bridge  # noqa: E402
import seat_identity as si  # noqa: E402
import seat_socket as ss  # noqa: E402
import session_tokens as st  # noqa: E402

SEAT = "grok-build-studio"
OTHER_SEAT = "hq-claude-studio"
READ_TOOL = "recall_insights"
WRITE_TOOL = "record_insight"


@contextmanager
def short_root():
    """A root short enough for a Unix socket path. See the module docstring."""
    d = tempfile.mkdtemp(prefix="seat-", dir="/tmp")
    try:
        yield Path(d)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def write_registry(root: Path) -> Path:
    path = root / "hq" / "seats" / "registry.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "seats": {
                    SEAT: {"substrate": "xai", "kind": "seated", "enabled": True},
                    OTHER_SEAT: {"substrate": "anthropic", "kind": "hq", "enabled": True},
                }
            }
        )
    )
    return path


# ── Kernel peer credentials ─────────────────────────────────────────────────


def test_peer_credentials_name_this_process(tmp_path):
    """The kernel's answer, taken over a real socketpair. If this ever returns
    something other than our own pid the whole binding is decorative."""
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        pid, uid = ss.peer_credentials(a)
        assert pid == os.getpid()
        assert uid == os.getuid()
    finally:
        a.close()
        b.close()


def test_peer_credentials_refuse_a_tcp_socket():
    """A TCP socket has no peer credentials to give. It must RAISE, not return
    a zero or a guess — a guessed pid would resolve to some other process's
    environment, which is worse than no answer."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        with pytest.raises(ss.PeerUnavailable):
            ss.peer_credentials(s)
    finally:
        s.close()


def test_peer_credentials_refuse_a_missing_socket():
    with pytest.raises(ss.PeerUnavailable):
        ss.peer_credentials(None)


# ── Reading the peer's environment ──────────────────────────────────────────


def test_process_environ_reads_a_real_subprocess():
    """A REAL child with a REAL exported seat. Nothing is mocked here because
    the whole mechanism is 'what does the OS actually say'."""
    env = {**os.environ, ss.SEAT_ENV_VAR: SEAT}
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"], env=env)
    try:
        found = ss.process_environ(proc.pid)
        assert found.get(ss.SEAT_ENV_VAR) == SEAT
    finally:
        proc.kill()
        proc.wait()


def test_process_environ_raises_for_a_pid_that_does_not_exist():
    """Fail closed. A missing process must not read as an empty environment,
    because an empty environment and a denied read are the same bytes."""
    with pytest.raises(ss.PeerUnavailable):
        ss.process_environ(999_999)


def test_resolve_peer_refuses_a_process_with_no_seat(tmp_path):
    """THE FALSIFIER FOR THE ENV LOOKUP. A child WITHOUT SOVEREIGN_SEAT must be
    refused — if this passes, the reader is finding a seat somewhere it should
    not be looking (an inherited env, a default, our own os.environ)."""
    env = {k: v for k, v in os.environ.items() if k != ss.SEAT_ENV_VAR}
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"], env=env)
    try:
        assert ss.process_environ(proc.pid).get(ss.SEAT_ENV_VAR) is None
    finally:
        proc.kill()
        proc.wait()


def test_the_env_read_is_exec_time_not_current(monkeypatch):
    """A LIMIT, PINNED AS A TEST so it is a documented property rather than a
    surprise. process_environ reads what the process was STARTED with. Setting
    SOVEREIGN_SEAT in our own os.environ right now does NOT make us a seat.

    This is deliberate: a value a process can rewrite inside itself is not an
    identity. It is also why the end-to-end tests below spawn curl rather than
    calling the socket from inside pytest.
    """
    monkeypatch.setenv(ss.SEAT_ENV_VAR, "seat-invented-at-runtime")
    assert os.environ[ss.SEAT_ENV_VAR] == "seat-invented-at-runtime"
    assert ss.process_environ(os.getpid()).get(ss.SEAT_ENV_VAR) != "seat-invented-at-runtime"


# ── The socket path itself ──────────────────────────────────────────────────


def test_prepare_socket_path_refuses_to_unlink_a_non_socket(tmp_path):
    """A regular file at the socket path is somebody's data or somebody's
    mistake. Deleting it to make room would be a bridge that destroys files on
    startup, so it raises instead and the seat path simply stays shut."""
    target = tmp_path / "hq" / "seats" / "sock" / "bridge.sock"
    target.parent.mkdir(parents=True)
    target.write_text("not a socket")
    with pytest.raises(OSError):
        ss.prepare_socket_path(target)
    assert target.read_text() == "not a socket", "a real file was destroyed"


def test_prepare_socket_path_clears_a_stale_socket_and_locks_the_dir():
    """short_root, not tmp_path: this test BINDS, and a bind is what the
    104-byte sun_path limit applies to. Written against tmp_path first and it
    raised "AF_UNIX path too long" — the module docstring says so and the test
    did it anyway."""
    with short_root() as root:
        target = root / "hq" / "seats" / "sock" / "bridge.sock"
        target.parent.mkdir(parents=True)
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.bind(str(target))
        s.close()
        ss.prepare_socket_path(target)
        assert not target.exists(), "a stale socket blocks the next start"
        assert stat.S_IMODE(os.stat(target.parent).st_mode) == 0o700


# ── The scope injection, against a stub ─────────────────────────────────────


class _StubProtocol:
    """Stands in for uvicorn's H11Protocol: the two things the subclass touches
    are `connection_made` and `self.app`."""

    def __init__(self, app):
        self.app = app
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport


class _FakeTransport:
    def __init__(self, sock):
        self._sock = sock

    def get_extra_info(self, name):
        return self._sock if name == "socket" else None


def _stamp_for(sock) -> dict:
    """Drive a stub protocol over `sock` and return the stamped extension."""
    captured = {}

    async def inner(scope, receive, send):
        captured["scope"] = scope

    cls = ss.make_protocol_class(_StubProtocol)
    proto = cls(app=inner)
    proto.connection_made(_FakeTransport(sock))
    asyncio.run(proto.app({"type": "http"}, None, None))
    return captured["scope"]["extensions"][ss.SEAT_PEER_EXT]


# The peer of a socketpair created here is THIS process, so a test that reads
# its own identity is a test of whoever happened to run it. This script holds
# one end of a passed descriptor open with a KNOWN exec-time environment, so
# the answer is a property of the fixture instead.
#
# ⚠ IT SENDS A BYTE FIRST, AND THAT IS NOT DECORATION. Measured on macOS
# 2026-09-06: LOCAL_PEERPID names the process that last SENT on the socket, and
# until something is sent it still names whoever created the pair. Holding the
# descriptor is not enough — a child that merely inherits an idle socket is
# invisible to the kernel's answer. This matches the real bridge exactly, where
# identity is only ever asked for because a request arrived, i.e. because the
# peer sent; but a fixture that skipped the send would silently measure the
# test process and pass for the wrong reason.
_HOLD_FD = (
    "import socket,sys;s=socket.socket(fileno=int(sys.argv[1]));"
    "s.sendall(b'x');sys.stdin.read(1)"
)


@contextmanager
def peer_with_env(env: dict):
    """A live socket whose peer is a fresh python process with `env` at exec.

    python (not a system binary) so macOS will show us its environment — see
    seat_of_process. The child sends one byte (see above), then holds the
    descriptor until stdin closes.
    """
    ours, theirs = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    proc = subprocess.Popen(
        [sys.executable, "-B", "-c", _HOLD_FD, str(theirs.fileno())],
        pass_fds=(theirs.fileno(),),
        env=env,
        stdin=subprocess.PIPE,
    )
    theirs.close()
    try:
        ours.recv(4)  # the handshake that makes the child the kernel's answer
        yield ours, proc
    finally:
        if proc.stdin:
            proc.stdin.close()
        proc.wait(timeout=5)
        ours.close()


def test_the_protocol_stamps_the_verified_peer_into_the_scope():
    """The seam this whole design rests on: after connection_made, `self.app`
    is a wrapper that injects the extension, so every request on the connection
    carries it.

    ⚠ THE FIXTURE OWNS THE IDENTITY, NOT THE RUNNER. Codex review 2026-09-06
    (P3 TEST ENVIRONMENT) failed this test — not because the code was wrong,
    but because the reviewer's own dispatched process legitimately inherited
    `SOVEREIGN_SEAT=codex-astra-studio`. The old version resolved the identity
    of *whatever process pytest happened to be*, then asserted
    `ok=False / no_seat_env` unconditionally, so it passed for an unseated
    runner and failed for a seated one. A test whose verdict depends on the
    developer's shell is measuring the shell.

    Both directions are now asserted against explicit subprocess fixtures, and
    the seated half is the one that had no coverage at all: an assertion that
    only ever ran unseated could not have told a stamped failure from a stamped
    success.
    """
    with peer_with_env({"PATH": "/usr/bin"}) as (sock, _proc):
        unseated = _stamp_for(sock)
    # Stamping the FAILURE is deliberate: an unstamped scope is
    # indistinguishable from a TCP request and would deny with the wrong reason.
    assert unseated["ok"] is False
    assert unseated["reason"] == "no_seat_env"

    with peer_with_env({"PATH": "/usr/bin", ss.SEAT_ENV_VAR: SEAT}) as (sock, proc):
        seated = _stamp_for(sock)
    assert seated["ok"] is True
    assert seated["seat"] == SEAT
    assert seated["pid"] == proc.pid


def test_the_stamp_does_not_depend_on_the_runners_own_seat():
    """The falsifier for the fix above: the same fixture must give the same
    answer whether or not THIS process is seated. Without the subprocess
    fixture this assertion cannot even be written."""
    saved = os.environ.get(ss.SEAT_ENV_VAR)
    os.environ[ss.SEAT_ENV_VAR] = "some-other-seat-entirely"
    try:
        with peer_with_env({"PATH": "/usr/bin", ss.SEAT_ENV_VAR: SEAT}) as (sock, _p):
            assert _stamp_for(sock)["seat"] == SEAT
        with peer_with_env({"PATH": "/usr/bin"}) as (sock, _p):
            assert _stamp_for(sock)["reason"] == "no_seat_env"
    finally:
        if saved is None:
            os.environ.pop(ss.SEAT_ENV_VAR, None)
        else:
            os.environ[ss.SEAT_ENV_VAR] = saved


# ── FINDING 1: the retained connection identity ─────────────────────────────


def test_the_kernel_names_the_new_sender_after_a_descriptor_handoff():
    """The measured fact the per-request fix rests on, asserted rather than
    quoted. macOS LOCAL_PEERPID re-read AFTER a child transmits reports the
    CHILD, not the process that created the socket. If this ever stopped being
    true, re-resolution would silently stop being a fix and everything below
    would keep passing for the wrong reason."""
    ours, theirs = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    send_then_hold = (
        "import socket,sys;s=socket.socket(fileno=int(sys.argv[1]));"
        "s.sendall(b'x');sys.stdin.read(1)"
    )
    proc = subprocess.Popen(
        [sys.executable, "-B", "-c", send_then_hold, str(theirs.fileno())],
        pass_fds=(theirs.fileno(),),
        env={ss.SEAT_ENV_VAR: OTHER_SEAT},
        stdin=subprocess.PIPE,
    )
    try:
        at_accept = ss.peer_credentials(ours)[0]
        ours.recv(4)
        after_child_sent = ss.peer_credentials(ours)[0]
    finally:
        if proc.stdin:
            proc.stdin.close()
        proc.wait(timeout=5)
        ours.close()
        theirs.close()

    assert at_accept == os.getpid()
    assert after_child_sent == proc.pid
    assert at_accept != after_child_sent


def test_a_descriptor_handoff_is_re_attributed_to_the_process_that_sent():
    """FINDING 1, the defect itself.

    A seated parent opens the connection; a CHILD with a different exec-time
    seat then writes on the inherited descriptor. The identity stamped for that
    request must be the CHILD's, not the parent's. Before this fix the wrapper
    closed over the accept-time answer, so the child's request was dispatched
    as the parent's seat with `source_instance` to match.
    """
    # THE ORDER IS THE TEST, and it is Astra's scenario exactly: the connection
    # is accepted while THIS process is the peer, and only then is the
    # descriptor handed to a differently-seated child that sends the request.
    # `peer_with_env` cannot express this — it makes the child send before
    # anything is accepted, so both reads would name the child and the test
    # would pass without exercising the handoff at all.
    captured = []

    async def inner(scope, receive, send):
        captured.append(scope["extensions"][ss.SEAT_PEER_EXT])

    ours, theirs = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    cls = ss.make_protocol_class(_StubProtocol)
    proto = cls(app=inner)
    proto.connection_made(_FakeTransport(ours))  # accept time: peer is us

    proc = subprocess.Popen(
        [sys.executable, "-B", "-c", _HOLD_FD, str(theirs.fileno())],
        pass_fds=(theirs.fileno(),),
        env={"PATH": "/usr/bin", ss.SEAT_ENV_VAR: SEAT},
        stdin=subprocess.PIPE,
    )
    theirs.close()
    try:
        ours.recv(4)  # the child has now spoken; it is the kernel's answer
        asyncio.run(proto.app({"type": "http"}, None, None))
    finally:
        if proc.stdin:
            proc.stdin.close()
        proc.wait(timeout=5)
        ours.close()

    stamp = captured[0]
    # The child that SENT the request is the process attributed...
    assert stamp["ok"] is True
    assert stamp["pid"] == proc.pid
    assert stamp["seat"] == SEAT
    # ...and the process that OPENED the connection is recorded, and decides
    # nothing. Before the fix it decided everything.
    assert stamp["accept_pid"] == os.getpid()
    assert stamp["accept_pid"] != stamp["pid"]


def test_each_request_on_one_connection_is_resolved_again():
    """The property, stated as a property: two requests on ONE connection ask
    the kernel twice. A cached answer would make the second call free, and free
    is exactly what made the handoff work."""
    asked = []
    real = ss.resolve_peer

    def counting(sock):
        asked.append(sock)
        return real(sock)

    with peer_with_env({"PATH": "/usr/bin", ss.SEAT_ENV_VAR: SEAT}) as (sock, _p):
        captured = []

        async def inner(scope, receive, send):
            captured.append(scope["extensions"][ss.SEAT_PEER_EXT])

        cls = ss.make_protocol_class(_StubProtocol)
        proto = cls(app=inner)
        proto.connection_made(_FakeTransport(sock))
        original, ss.resolve_peer = ss.resolve_peer, counting
        try:
            asyncio.run(proto.app({"type": "http"}, None, None))
            asyncio.run(proto.app({"type": "http"}, None, None))
        finally:
            ss.resolve_peer = original

    assert len(asked) == 2, "identity must be resolved per request, not per connection"
    assert [c["seat"] for c in captured] == [SEAT, SEAT]


def test_a_peer_that_dies_mid_connection_denies_rather_than_reusing_its_seat():
    """Re-resolution failure is a DENIAL, never a fall back to the identity the
    connection used to have. The fall-back is the bug."""
    with peer_with_env({"PATH": "/usr/bin", ss.SEAT_ENV_VAR: SEAT}) as (sock, proc):
        assert _stamp_for(sock)["seat"] == SEAT
        if proc.stdin:
            proc.stdin.close()
        proc.wait(timeout=5)
        after = _stamp_for(sock)
    assert after["ok"] is False
    assert after["reason"] in {"no_peer_creds", "no_peer_env", "no_seat_env"}
    assert "seat" not in after


def test_the_walk_stops_at_the_immediate_peers_own_environment():
    """FINDING 1(b). When the immediate peer HAS a readable environment, that
    environment is authoritative and the walk never reaches the parent — even
    though this test process is itself seated as something else."""
    saved = os.environ.get(ss.SEAT_ENV_VAR)
    os.environ[ss.SEAT_ENV_VAR] = OTHER_SEAT
    try:
        with peer_with_env({"PATH": "/usr/bin", ss.SEAT_ENV_VAR: SEAT}) as (sock, proc):
            seat, seat_pid = ss.seat_of_process(ss.peer_credentials(sock)[0])
    finally:
        if saved is None:
            os.environ.pop(ss.SEAT_ENV_VAR, None)
        else:
            os.environ[ss.SEAT_ENV_VAR] = saved
    assert (seat, seat_pid) == (SEAT, proc.pid)


def test_a_child_declaring_a_seat_its_environment_does_not_name_is_denied():
    """FINDING 1(c). A mismatch between the declared header and the nearest
    readable ancestor's seat is a DENY.

    "All studio seats are trusted" widened the TOOL surface; it did not turn a
    mismatch into a warning. A mismatch is a bug — a script signing as the
    wrong seat, or an impersonation attempt — and either way the write must not
    land under a name the process cannot back up.
    """
    with peer_with_env({"PATH": "/usr/bin", ss.SEAT_ENV_VAR: SEAT}) as (sock, _p):
        stamp = _stamp_for(sock)
    with pytest.raises(si.SeatDenied) as mismatch:
        si.resolve_seat(stamp, OTHER_SEAT, {})
    assert mismatch.value.reason == "seat_mismatch"

    # The falsifier: the SAME stamp, declaring truthfully, gets past the
    # mismatch gate and stops on the next condition instead. Without this the
    # test above would pass against a resolve_seat that denied everything.
    with pytest.raises(si.SeatDenied) as truthful:
        si.resolve_seat(stamp, SEAT, {})
    assert truthful.value.reason != "seat_mismatch"


def test_a_stamped_failure_denies_with_its_own_reason():
    """The failure the protocol stamps must survive into resolve_seat's reason,
    not be flattened into 'not_socket'. A seat told 'use the socket' while it
    IS on the socket would chase the wrong problem forever."""
    stamped = {"ok": False, "reason": "wrong_uid", "detail": "another user"}
    with pytest.raises(si.SeatDenied) as exc:
        si.resolve_seat(stamped, SEAT, {})
    assert exc.value.reason == "wrong_uid"


# ── END TO END: a real socket, a real curl, a real environment ──────────────


# The client, as a seat actually runs one. A SEATED LAUNCHER (a process whose
# environment macOS will show us) spawns curl as a CHILD — which is the real
# topology: `seat-codex` exports SOVEREIGN_SEAT and execs the agent, the agent
# spawns a shell, the shell spawns curl. Every one of those but the agent is a
# system binary whose environment is hidden, so the seat is found by walking to
# the agent. See seat_socket.seat_of_process.
#
# ⚠ THIS IS WHY THE TEST CANNOT JUST SET SOVEREIGN_SEAT ON curl ITSELF. The
# first version of this file did exactly that, and every request was refused
# with no_seat_env: macOS returns ZERO environment strings for /usr/bin/curl.
# The unit tests all passed while the feature was completely dead. Do not
# "simplify" this back.
_LAUNCHER = r"""
import json, subprocess, sys
sock, header, body = sys.argv[1], sys.argv[2], sys.argv[3]
r = subprocess.run(
    ["curl", "--silent", "--unix-socket", sock, "--write-out", "\n%{http_code}",
     "-X", "POST", "http://localhost/api/call",
     "-H", "X-Sovereign-Seat: " + header,
     "-H", "Content-Type: application/json",
     "-d", body],
    capture_output=True, text=True,
)
sys.stdout.write(r.stdout)
sys.stderr.write(r.stderr)
"""


def _serve_and_curl(app, sock_path: Path, seat_env: str | None, header: str, body: dict):
    """Start the real listener, run a real curl against it, return (code, text)."""

    async def scenario():
        server = await ss.start(app, sock_path)
        try:
            env = {k: v for k, v in os.environ.items() if k != ss.SEAT_ENV_VAR}
            if seat_env is not None:
                env[ss.SEAT_ENV_VAR] = seat_env
            proc = await asyncio.create_subprocess_exec(
                sys.executable,
                "-c",
                _LAUNCHER,
                str(sock_path),
                header,
                json.dumps(body),
                env=env,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            out, err = await asyncio.wait_for(proc.communicate(), timeout=30)
        finally:
            server.close()
            await server.wait_closed()
        text = out.decode()
        assert "\n" in text, f"curl produced no status line: {text!r} err={err.decode()!r}"
        payload, _, code = text.rpartition("\n")
        return int(code), payload

    return asyncio.run(scenario())


@pytest.fixture
def live(monkeypatch, tmp_path):
    """bridge.app with a stubbed stack and a tmp SOVEREIGN_ROOT. Records every
    (tool, arguments) that would have reached the stack."""
    seen: list[tuple[str, dict]] = []

    async def fake(tool, args, seat=None):
        seen.append((tool, args))
        return {"ok": True, "result": {"echo": tool}}

    monkeypatch.setattr(bridge, "call_mcp_tool", fake)
    monkeypatch.setattr(bridge, "BEARER_TOKEN", "test-master-token-0123456789abcdef-0123456789abcdef")
    # No test here sends idempotency_key today, so nothing writes the live
    # cache — but this house has shipped exactly that bug twice (a6f42cf,
    # 28592c7: a suite asserting against Anthony's live production store).
    # Isolate EVERY write path a test can reach, not just the ones it uses.
    monkeypatch.setattr(bridge, "_IDEM_PATH", tmp_path / "idem.json")
    return seen


def test_end_to_end_a_seated_process_writes_and_signs(live, monkeypatch):
    """THE WHOLE THING, for real. A curl whose environment says it is SEAT,
    declaring SEAT, over the actual socket, reaching the actual route — and the
    write is stamped with the seat the KERNEL vouched for."""
    with short_root() as root:
        monkeypatch.setenv("SOVEREIGN_ROOT", str(root))
        write_registry(root)
        code, payload = _serve_and_curl(
            bridge.app,
            root / "hq" / "seats" / "sock" / "bridge.sock",
            seat_env=SEAT,
            header=SEAT,
            body={"tool": WRITE_TOOL, "arguments": {"content": "c", "domain": "d"}},
        )
    assert code == 200, payload
    assert live and live[0][0] == WRITE_TOOL
    assert live[0][1]["source_instance"] == SEAT


def test_end_to_end_the_impersonation_from_the_review_is_refused(live, monkeypatch):
    """⚠ THE CODEX REVIEW'S EXACT SCENARIO, OVER A REAL SOCKET.

    Verbatim: "With SOVEREIGN_SEAT=codex-astra-studio in the caller's
    environment, header hq-claude-studio returned 200 and dispatched
    source_instance=hq-claude-studio."

    Here the calling process is seated as SEAT and declares OTHER_SEAT. Both
    are registered and enabled, so only the process binding can refuse it. This
    is the test to delete first when checking whether the fix is real.
    """
    with short_root() as root:
        monkeypatch.setenv("SOVEREIGN_ROOT", str(root))
        write_registry(root)
        code, payload = _serve_and_curl(
            bridge.app,
            root / "hq" / "seats" / "sock" / "bridge.sock",
            seat_env=SEAT,
            header=OTHER_SEAT,
            body={"tool": READ_TOOL, "arguments": {}},
        )
    assert code == 401, f"a process seated as {SEAT} called as {OTHER_SEAT}: {payload}"
    # ⚠ ASSERT THE REASON, NOT JUST THE 401. An earlier draft of this test
    # asserted only the status and PASSED while the refusal was actually
    # `no_seat_env` — the socket was denying every caller, impersonator and
    # legitimate seat alike, and the test called that a fix. A deny-side test
    # that does not name its reason cannot tell a working guard from a broken
    # feature.
    assert "not seated as" in payload, f"refused, but not for impersonating: {payload}"
    assert not live, "a refused request reached the stack"


def test_end_to_end_an_unseated_process_is_refused(live, monkeypatch):
    """No SOVEREIGN_SEAT in the caller's environment at all. Being on the
    socket is not being a seat."""
    with short_root() as root:
        monkeypatch.setenv("SOVEREIGN_ROOT", str(root))
        write_registry(root)
        code, payload = _serve_and_curl(
            bridge.app,
            root / "hq" / "seats" / "sock" / "bridge.sock",
            seat_env=None,
            header=SEAT,
            body={"tool": READ_TOOL, "arguments": {}},
        )
    assert code == 401, payload
    assert not live


def test_end_to_end_a_large_body_still_works(live, monkeypatch):
    """curl switches to `Expect: 100-continue` above roughly 1 KiB, and the
    header allowlist has to know that. A small-payload suite would never see
    it, and the first thing to break would be a seat writing a real insight —
    the exact case the feature exists for."""
    with short_root() as root:
        monkeypatch.setenv("SOVEREIGN_ROOT", str(root))
        write_registry(root)
        code, payload = _serve_and_curl(
            bridge.app,
            root / "hq" / "seats" / "sock" / "bridge.sock",
            seat_env=SEAT,
            header=SEAT,
            body={"tool": WRITE_TOOL, "arguments": {"content": "x" * 40_000, "domain": "d"}},
        )
    assert code == 200, payload
    assert len(live[0][1]["content"]) == 40_000


def test_the_bound_socket_is_owner_only(monkeypatch):
    """0600. A world-writable seat socket would hand the read+write surface to
    every process on the box, which is the feature exactly inverted."""

    async def scenario(sock_path):
        server = await ss.start(bridge.app, sock_path)
        try:
            return stat.S_IMODE(os.stat(sock_path).st_mode)
        finally:
            server.close()
            await server.wait_closed()

    with short_root() as root:
        monkeypatch.setenv("SOVEREIGN_ROOT", str(root))
        mode = asyncio.run(scenario(root / "hq" / "seats" / "sock" / "bridge.sock"))
    assert mode == 0o600, f"seat socket mode is {oct(mode)}"


# ── The listener is off unless Anthony turned the feature on ────────────────


def test_no_registry_means_no_socket_is_bound(monkeypatch):
    """ONE deploy switch, not two. seat_identity's contract is that an absent
    registry makes the feature inert; binding a listener anyway would be a
    second, undocumented switch — and it would create a socket under a live
    ~/.sovereign on a machine where the operator never enabled anything."""

    async def scenario():
        return await bridge._start_seat_socket(bridge.app)

    with short_root() as root:
        monkeypatch.setenv("SOVEREIGN_ROOT", str(root))
        assert not si.registry_path().exists()
        assert asyncio.run(scenario()) is None
        assert not (root / "hq" / "seats" / "sock" / "bridge.sock").exists()


def test_with_a_registry_the_listener_binds_where_the_root_says(monkeypatch):
    """And the path follows SOVEREIGN_ROOT, so the tests can never bind the
    live path by accident — the trap seat_identity.sovereign_root() documents."""

    async def scenario():
        server = await bridge._start_seat_socket(bridge.app)
        assert server is not None
        server.close()
        await server.wait_closed()

    with short_root() as root:
        monkeypatch.setenv("SOVEREIGN_ROOT", str(root))
        write_registry(root)
        assert bridge.seat_socket_path() == root / "hq" / "seats" / "sock" / "bridge.sock"
        asyncio.run(scenario())


def test_a_process_owned_by_another_user_is_refused(monkeypatch):
    """The uid guard, falsified directly.

    It cannot be reached by spawning a real process — that would need root — so
    the kernel's answer is stubbed at exactly one point: process_info. Found by
    deleting the guard and watching the whole 18-test file still pass, which is
    the definition of an untested check.

    It matters because the ancestor walk climbs toward pid 1: without it, the
    walk would happily read a root-owned ancestor's environment on any system
    where that read is permitted, and inherit a seat from a process the
    operator never started.
    """
    monkeypatch.setattr(ss, "process_info", lambda pid: (1, os.getuid() + 1))
    with pytest.raises(ss.PeerUnavailable) as exc:
        ss.seat_of_process(os.getpid())
    assert exc.value.reason == "wrong_uid"


def test_the_walk_stops_at_the_first_readable_environment(monkeypatch):
    """`env -u SOVEREIGN_SEAT` must WORK on a client that exposes its
    environment. If the walk continued past a readable-but-unseated process it
    would reach the seated grandparent and re-grant a seat that was
    deliberately stripped."""
    chain = {10: (20, os.getuid()), 20: (30, os.getuid()), 30: (1, os.getuid())}
    envs = {10: {}, 20: {"PATH": "/usr/bin"}, 30: {ss.SEAT_ENV_VAR: SEAT}}
    monkeypatch.setattr(ss, "process_info", lambda pid: chain[pid])
    monkeypatch.setattr(ss, "process_environ", lambda pid: envs[pid])
    with pytest.raises(ss.PeerUnavailable) as exc:
        ss.seat_of_process(10)
    assert exc.value.reason == "no_seat_env", "the walk climbed past an unseated process"


def test_the_walk_skips_a_hidden_environment_and_finds_the_launcher(monkeypatch):
    """The other edge, and the one that makes curl work at all: an UNREADABLE
    environment (macOS returns zero strings for /usr/bin/curl) is not evidence
    of anything, so the walk passes over it to the launcher."""
    chain = {10: (20, os.getuid()), 20: (30, os.getuid()), 30: (1, os.getuid())}
    envs = {10: {}, 20: {}, 30: {ss.SEAT_ENV_VAR: SEAT}}
    monkeypatch.setattr(ss, "process_info", lambda pid: chain[pid])
    monkeypatch.setattr(ss, "process_environ", lambda pid: envs[pid])
    assert ss.seat_of_process(10) == (SEAT, 30)


def test_RESIDUAL_a_process_can_still_declare_a_seat_it_was_not_given(live, monkeypatch):
    """⚠ THIS TEST ASSERTS A HOLE, ON PURPOSE. READ IT BEFORE QUOTING THE FIX.

    The P1 fix kills IMPERSONATION BY HEADER: a caller can no longer name a
    seat its own environment does not name. It does NOT and cannot kill
    DELIBERATE impersonation, because any process running as this user can
    spawn a child with whatever SOVEREIGN_SEAT it likes and let the walk find
    it. That is what this test does, and it must return 200 — the launcher here
    is structurally identical to a legitimate seat, and nothing in the kernel
    distinguishes them.

    WHY IT CANNOT BE CLOSED HERE: under Anthony's no-token rule the only thing
    that could separate a real seat from a self-declared one is a credential
    the operator issues, which is the rule's whole point to avoid. The
    remaining lever is per-seat UIDs, and that is an ops change at his gate,
    not a code change at ours.

    WHAT IS THEREFORE TRUE, and the only claim any doc should make: header-only
    impersonation is dead, and accidental mis-signing fails closed — a script
    with the wrong header no longer writes as the wrong seat. Anything running
    as this user could already read the master token out of
    ~/.config/sovereign-bridge.env, so this residual grants nothing it did not
    already have.

    IF THIS TEST EVER FAILS, the mechanism got stronger and the docs above it
    are now understated. Do not delete it — change the claim.
    """
    with short_root() as root:
        monkeypatch.setenv("SOVEREIGN_ROOT", str(root))
        write_registry(root)
        code, payload = _serve_and_curl(
            bridge.app,
            root / "hq" / "seats" / "sock" / "bridge.sock",
            seat_env=OTHER_SEAT,   # a seat this launcher simply asserts about itself
            header=OTHER_SEAT,
            # A WRITE, deliberately, so the residual is shown at its sharpest:
            # the chronicle entry lands SIGNED as a seat this process was never
            # given. (READ_TOOL would prove less — recall_insights is not in
            # SEAT_SIGNABLE_TOOLS, so nothing is stamped on it at all.)
            body={"tool": WRITE_TOOL, "arguments": {"content": "c", "domain": "d"}},
        )
    assert code == 200, f"the residual closed; update the doctrine above: {payload}"
    assert live[0][1].get("source_instance") == OTHER_SEAT


# ── FINDING 2 (F2): the residual the fix does NOT close, stated exactly ─────

REPO_ROOT = Path(__file__).resolve().parent.parent

# The F2 scenario, run in a process that was BORN seated. Prints one JSON
# receipt on stdout: the stamp resolved at ASGI entry, the two pids, the raw
# status line, and what reached the (faked) stack.
_SPLIT_BODY_SCENARIO = r"""
import asyncio, json, os, socket, sys
sys.path.insert(0, sys.argv[1])
PARENT_SEAT, CHILD_SEAT = sys.argv[2], sys.argv[3]
import bridge, seat_identity as si, seat_socket as ss
import uvicorn
from uvicorn.protocols.http.h11_impl import H11Protocol
from uvicorn.server import ServerState

dispatched = []
stamps = []


async def fake(tool, args, seat=None):
    dispatched.append((tool, args))
    return {"ok": True, "result": {"synthetic": True}}


bridge.call_mcp_tool = fake
_original = ss.peer_extension


# The seat surface is pinned here for the same reason the root conftest pins it
# for the rest of the suite: this subprocess has no stack tree and no upstream,
# so an unpinned resolution is a 503 and the test would measure the wrong
# refusal. What is under test is ATTRIBUTION, not surface resolution.
async def _pinned_surface(fetch=None):
    return si.Surface(frozenset({"record_insight"}), frozenset(), "test pin")


si.published_surface = _pinned_surface


async def main():
    stamped = asyncio.Event()

    def capture(*a, **k):
        value = _original(*a, **k)
        stamps.append(value)
        stamped.set()
        return value

    ss.peer_extension = capture
    config = uvicorn.Config(bridge.app, log_level="critical", proxy_headers=False, ws="none")
    config.load()
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    cls = ss.make_protocol_class(H11Protocol)
    transport, _p = await asyncio.get_running_loop().connect_accepted_socket(
        lambda: cls(config=config, server_state=ServerState(), app_state={}), left
    )
    body = json.dumps(
        {"tool": "record_insight", "arguments": {"content": "child-chosen", "domain": "f"}}
    ).encode()
    headers = (
        "POST /api/call HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n"
        "Content-Type: application/json\r\n"
        "X-Sovereign-Seat: " + PARENT_SEAT + "\r\n"
        "Content-Length: " + str(len(body)) + "\r\n\r\n"
    ).encode()
    child_src = (
        "import sys,socket\n"
        "s=socket.socket(fileno=int(sys.argv[1]))\n"
        "s.sendall(bytes.fromhex(sys.argv[2]))\n"
        "out=b''\n"
        "while True:\n"
        "    p=s.recv(65536)\n"
        "    if not p: break\n"
        "    out+=p\n"
        "sys.stdout.write(out.decode())\n"
    )
    try:
        # THE PARENT sends ONLY the headers, and waits for its own identity to
        # be stamped before anything else touches the descriptor.
        right.sendall(headers)
        await asyncio.wait_for(stamped.wait(), 10)
        proc = await asyncio.create_subprocess_exec(
            sys.executable, "-B", "-c", child_src, str(right.fileno()), body.hex(),
            pass_fds=(right.fileno(),),
            env={"PATH": "/usr/bin", "SOVEREIGN_SEAT": CHILD_SEAT},
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        out, err = await asyncio.wait_for(proc.communicate(), 20)
        assert proc.returncode == 0, err.decode()
        print(json.dumps({
            "status_line": out.decode().splitlines()[0],
            "stamp": stamps[0] if stamps else None,
            "parent_pid": os.getpid(),
            "child_pid": proc.pid,
            "dispatched": list(dispatched[0]) if dispatched else None,
        }))
    finally:
        transport.close()
        right.close()


asyncio.run(main())
"""


def test_a_body_sent_by_a_child_mid_request_is_attributed_to_the_ASGI_ENTRY_PEER(
    monkeypatch,
):
    """⚠ THIS TEST DOCUMENTS A BOUND, NOT A FIX. IT IS SUPPOSED TO PASS.

    Codex review 2026-09-06, F2. The per-request re-resolution closed the
    scenario where a child sends a WHOLE request on an inherited descriptor —
    that is now a 401 seat_mismatch, proved above. It did not close, and cannot
    close, the narrower one: the wrapper resolves the peer when the ASGI
    application STARTS, which is after the headers and BEFORE the body. A
    parent can send the headers, let the identity resolve as itself, and hand
    the descriptor to a differently-seated child that sends the body. The
    request is dispatched under the PARENT's seat with a body the CHILD chose.

    Astra measured it: parent pid 75471 sent headers, child pid 75480 (whose
    own environment named Codex) sent the JSON, `record_insight` dispatched
    with `source_instance=hq-claude-studio`, HTTP 200.

    THE HONEST CLAIM, and the one README.md now makes: identity is the
    kernel-reported peer AT ASGI ENTRY — not every process that contributed
    bytes to the stream. "The sender of each request is the process it is
    attributed to" was too strong and is corrected in prose.

    ⚠ ASSERTED AS THE CURRENT BOUND RATHER THAN MARKED xfail. An xfail passes
    whether the behaviour holds or changes, so it could not tell anyone if the
    bound moved. This says exactly what happens today; if the mechanism ever
    gets stronger this goes RED, and the right response is to change the claim
    in README.md and here — not to delete the test.

    ⚠ AND IT RUNS IN A SUBPROCESS, for a reason worth knowing before editing:
    KERN_PROCARGS2 reports a process's EXEC-TIME environment. Setting
    os.environ[SOVEREIGN_SEAT] inside the running pytest process does NOT make
    the kernel report that seat, so an in-process version of this test resolves
    `no_seat_env` and proves nothing. The parent must be BORN seated.

    Closing it for real needs identity resampled per body chunk plus a policy
    for what to do when it changes mid-stream — an architectural decision at
    Anthony's gate, not a patch.
    """
    with short_root() as root:
        write_registry(root)
        proc = subprocess.run(
            [sys.executable, "-B", "-c", _SPLIT_BODY_SCENARIO, str(REPO_ROOT), SEAT, OTHER_SEAT],
            capture_output=True,
            text=True,
            timeout=60,
            env={
                "PATH": "/usr/bin:/bin",
                "HOME": str(root),
                ss.SEAT_ENV_VAR: SEAT,        # the parent is BORN seated
                "SOVEREIGN_ROOT": str(root),
                "SOVEREIGN_CHRONICLE": str(root / "chronicle"),
                "SOVEREIGN_BRIDGE_ENV_FILE": str(root / "synthetic.env"),
                "PYTHONDONTWRITEBYTECODE": "1",
            },
        )
    assert proc.returncode == 0, f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    receipt = json.loads(proc.stdout.strip().splitlines()[-1])

    assert receipt["status_line"].startswith("HTTP/1.1 200"), receipt
    # The identity was resolved at ASGI entry, when the PARENT was the peer...
    assert receipt["stamp"]["ok"] is True
    assert receipt["stamp"]["seat"] == SEAT
    assert receipt["stamp"]["pid"] == receipt["parent_pid"]
    assert receipt["child_pid"] != receipt["parent_pid"], "the handoff did not happen"
    # ...and the body the CHILD chose was dispatched under it. That is the bound.
    assert receipt["dispatched"][0] == WRITE_TOOL
    assert receipt["dispatched"][1]["content"] == "child-chosen"
    assert receipt["dispatched"][1]["source_instance"] == SEAT
