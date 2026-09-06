"""Seat identity, bound to the CALLING PROCESS — the Unix-socket transport.

WHY THIS MODULE EXISTS (Codex review, 2026-09-06, finding P1):

    seat_identity.resolve_seat validated that the X-Sovereign-Seat header named
    a registered, enabled seat — and never bound it to the process that sent
    it. With SOVEREIGN_SEAT=codex-astra-studio in its own environment, a caller
    sending the header `hq-claude-studio` got a 200 and dispatched
    source_instance=hq-claude-studio. Seat ids are not secrets; the header was
    a claim, and nothing checked the claim against the claimant.

Anthony's rule forbids the obvious fix. *"Inside my network, meaning seats I've
put on the Studio, no tokens. They have the filesystem, I seated them."* So the
binding cannot be a shared secret. It has to be something the kernel knows and
the caller cannot forge.

THE MECHANISM: a Unix domain socket carries the peer's PID as kernel-attested
metadata. Given the pid we read that process's ENVIRONMENT and compare its
SOVEREIGN_SEAT to the declared header. The header stays — as a DECLARATION that
must match — because a request that says who it is and is checked is far easier
to audit than one whose identity is only ever inferred.

    peer pid   ← kernel (LOCAL_PEERPID / SO_PEERCRED), not forgeable by the peer
    peer uid   ← kernel (LOCAL_PEERCRED / SO_PEERCRED), must equal ours
    SOVEREIGN_SEAT ← that pid's environment (or its nearest ancestor whose
                     environment macOS will show us — see seat_of_process, and
                     read that docstring before trusting this one)
    X-Sovereign-Seat ← the caller's declaration; must EQUAL the env value

WHAT THIS DEFENDS, STATED HONESTLY SO NOBODY OVER-READS IT: attribution
integrity. A seat signs as the seat it was launched under and cannot sign as
another. It is NOT a privilege boundary between local processes and cannot be
one — anything running as this user can already read the master token out of
~/.config/sovereign-bridge.env. The chronicle's attribution is the asset here.

A loopback TCP request can no longer take the seat path at all, whatever
headers it carries: there is no pid behind a TCP connection that the kernel
will tell us about, and `cloudflared` makes every tunneled request look like
loopback anyway. TCP + seat header is now a 401 that says "use the socket".

──────────────────────────────────────────────────────────────────────────────
HOW THE LISTENER IS BUILT, AND WHY NOT THE OBVIOUS WAYS.

The ASGI scope does not carry the transport, so the peer credentials are not
reachable from inside a route. Three options were weighed:

  * Hand-roll an HTTP server over `asyncio.start_unix_server`. Rejected: ~150
    lines of request parsing (Expect: 100-continue, keep-alive, chunked bodies,
    duplicate Content-Length) owned forever in a security path. That is the
    fail-open surface this house hunts, built by hand.

  * Run a second `uvicorn.Server` on the socket. Rejected: `Server.serve()`
    installs signal handlers on the main thread and would clobber the real
    server's shutdown.

  * WHAT THIS DOES: reuse uvicorn's own, tested `H11Protocol` and drive it from
    `loop.create_unix_server` directly. The subclass overrides exactly one
    method — `connection_made` — where the raw socket IS available, resolves
    the peer once, and swaps `self.app` for a wrapper that injects the verified
    identity into `scope["extensions"]`. uvicorn reads `self.app` per request
    (h11_impl.py:231), so every request on the connection is stamped.

COUPLING, STATED PLAINLY: `H11Protocol.__init__(config, server_state,
app_state)` and the per-request `self.app` read are uvicorn internals, not
public API. Pinned against uvicorn 0.40. If a future uvicorn stops reading
`self.app` per request the wrapper simply never runs, no extension is injected,
and every seat request is DENIED — the coupling fails closed, which is the only
direction it is allowed to fail.

THE EXTENSION KEY IS UNFORGEABLE BY CONSTRUCTION. uvicorn builds the http scope
at h11_impl.py:203 and never sets `extensions`; no header, path or body can
introduce a scope key. Only this module puts it there, and only after the
kernel answered.
"""

from __future__ import annotations

import asyncio
import ctypes
import os
import socket
import stat
import sys
from pathlib import Path
from typing import Any

# The ASGI scope-extension key carrying the VERIFIED peer identity. Namespaced
# like every other ASGI extension so it can never collide with a real one.
SEAT_PEER_EXT = "sovereign.seat_peer"

# The environment variable a seated terminal exports. Anthony's launchers
# (~/.sovereign/hq/seats/seat-*, dispatch-*) already set exactly this.
SEAT_ENV_VAR = "SOVEREIGN_SEAT"

# macOS socket options. SOL_LOCAL is 0; the optnames are from <sys/un.h>.
_SOL_LOCAL = 0
_LOCAL_PEERCRED = 0x001  # struct xucred
_LOCAL_PEERPID = 0x002  # pid_t

# Linux. SO_PEERCRED yields struct ucred {pid, uid, gid}.
_SO_PEERCRED = 17

# sysctl(CTL_KERN, KERN_PROCARGS2, pid) — how `ps` itself reads another
# process's argv+environ on macOS. Same-uid only; EINVAL otherwise, which is a
# fail-closed answer we want rather than a privilege we do not.
_CTL_KERN = 1
_KERN_PROCARGS2 = 49

# A process environment block is small. Anything past this is not a seat.
_MAX_PROCARGS = 4 * 1024 * 1024

# libproc: proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &proc_bsdinfo, size) — how we
# get a parent pid and an owning uid without shelling out to `ps` inside the
# event loop. sizeof(struct proc_bsdinfo) is 136; the call returns the byte
# count it wrote, and the struct's own pbi_pid is checked against the pid asked
# for, so a layout change raises rather than mis-parsing.
_PROC_PIDTBSDINFO = 3
_PROC_BSDINFO_SIZE = 136

# Bounded, because an ancestry walk is a loop over data we do not control. A
# seat's client is one or two hops from its terminal; twelve is generous and
# still terminates.
_MAX_ANCESTOR_HOPS = 12


class PeerUnavailable(Exception):
    """The kernel would not tell us who the peer is, or its environment names
    no seat. `reason` is the audit word; it never carries a value read out of
    another process."""

    def __init__(self, reason: str, detail: str):
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


# ── Kernel-attested peer credentials ────────────────────────────────────────


def peer_credentials(sock: socket.socket) -> tuple[int, int]:
    """(pid, uid) of the process on the other end of a Unix socket.

    Kernel-attested: the peer cannot set these, and there is no header or body
    field that influences them. Raises PeerUnavailable on any platform or any
    socket where they cannot be obtained — never guesses.
    """
    if sock is None:
        raise PeerUnavailable("no_socket", "No socket object behind this connection.")
    try:
        if sys.platform == "darwin":
            pid = int.from_bytes(
                sock.getsockopt(_SOL_LOCAL, _LOCAL_PEERPID, 4), sys.byteorder
            )
            # struct xucred { u_int cr_version; uid_t cr_uid; short cr_ngroups; ... }
            xucred = sock.getsockopt(_SOL_LOCAL, _LOCAL_PEERCRED, 76)
            uid = int.from_bytes(xucred[4:8], sys.byteorder)
        elif sys.platform.startswith("linux"):
            ucred = sock.getsockopt(socket.SOL_SOCKET, _SO_PEERCRED, 12)
            pid = int.from_bytes(ucred[0:4], sys.byteorder)
            uid = int.from_bytes(ucred[4:8], sys.byteorder)
        else:
            raise PeerUnavailable(
                "unsupported_platform",
                f"Peer credentials are not implemented for {sys.platform!r}, so "
                "seat identity cannot be bound to a process here.",
            )
    except OSError as exc:
        raise PeerUnavailable(
            "no_peer_creds",
            f"The kernel would not name the peer process ({exc.strerror}). "
            "Seat identity requires a Unix-socket peer.",
        ) from None
    if pid <= 0:
        raise PeerUnavailable("no_peer_creds", "The kernel returned no peer pid.")
    return pid, uid


def process_environ(pid: int) -> dict[str, str]:
    """The EXEC-TIME environment of `pid`, as the kernel recorded it.

    LIMIT, NAMED: this is the environment the process was STARTED with. A
    process that sets SOVEREIGN_SEAT in its own os.environ after launch is not
    a seat by this measure. That is deliberate — the launcher exports the seat
    id before exec, and a value a process can rewrite in itself is not an
    identity. It also means os.environ changes inside THIS process are
    invisible here, which is why the tests spawn a real subprocess.
    """
    if sys.platform == "darwin":
        return _procargs2_environ(pid)
    if sys.platform.startswith("linux"):
        try:
            raw = Path(f"/proc/{pid}/environ").read_bytes()
        except OSError as exc:
            raise PeerUnavailable(
                "no_peer_env", f"Cannot read the peer process environment ({exc.strerror})."
            ) from None
        return _parse_env_block(raw.split(b"\0"))
    raise PeerUnavailable(
        "unsupported_platform",
        f"Reading a peer process environment is not implemented for {sys.platform!r}.",
    )


def _procargs2_environ(pid: int) -> dict[str, str]:
    libc = ctypes.CDLL("libc.dylib", use_errno=True)
    mib = (ctypes.c_int * 3)(_CTL_KERN, _KERN_PROCARGS2, pid)
    size = ctypes.c_size_t(0)
    if libc.sysctl(mib, 3, None, ctypes.byref(size), None, 0) != 0:
        raise PeerUnavailable(
            "no_peer_env",
            "Cannot read the peer process environment. It may have exited, or it "
            "may belong to another user — either way it is not a seat here.",
        )
    if size.value > _MAX_PROCARGS:
        raise PeerUnavailable("no_peer_env", "Peer process argument block is implausibly large.")
    buf = ctypes.create_string_buffer(size.value)
    if libc.sysctl(mib, 3, buf, ctypes.byref(size), None, 0) != 0:
        raise PeerUnavailable("no_peer_env", "Cannot read the peer process environment.")
    data = buf.raw[: size.value]
    if len(data) < 4:
        raise PeerUnavailable("no_peer_env", "Peer process argument block is truncated.")
    # KERN_PROCARGS2 layout: int32 argc | exec_path \0 | NUL padding |
    #                        argc argv strings | environ strings
    argc = int.from_bytes(data[:4], sys.byteorder)
    parts = data[4:].split(b"\0")
    i = 1  # skip exec_path
    while i < len(parts) and parts[i] == b"":
        i += 1  # skip the alignment padding
    return _parse_env_block(parts[i + argc :])


def _parse_env_block(entries: list[bytes]) -> dict[str, str]:
    env: dict[str, str] = {}
    for item in entries:
        if not item or b"=" not in item:
            continue
        key, _, value = item.partition(b"=")
        # First wins: duplicate keys in an environ block resolve to the first,
        # matching what getenv() in that process would have returned.
        env.setdefault(
            key.decode("utf-8", "replace"), value.decode("utf-8", "replace")
        )
    return env


def process_info(pid: int) -> tuple[int, int]:
    """(ppid, uid) for `pid`, via libproc. Raises PeerUnavailable if the kernel
    will not answer — which it will not for a process owned by another user,
    and that refusal is exactly the fail-closed end of the ancestor walk."""
    if not sys.platform == "darwin":
        try:
            stat_result = os.stat(f"/proc/{pid}")
            with open(f"/proc/{pid}/stat", "rb") as fh:
                fields = fh.read().rsplit(b")", 1)[1].split()
            return int(fields[1]), stat_result.st_uid
        except (OSError, IndexError, ValueError):
            raise PeerUnavailable("no_peer_creds", "Cannot inspect the peer process.") from None
    libc = ctypes.CDLL("libc.dylib", use_errno=True)
    libc.proc_pidinfo.argtypes = [
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_uint64,
        ctypes.c_void_p,
        ctypes.c_int,
    ]
    buf = ctypes.create_string_buffer(_PROC_BSDINFO_SIZE)
    written = libc.proc_pidinfo(pid, _PROC_PIDTBSDINFO, 0, buf, _PROC_BSDINFO_SIZE)
    if written <= 0:
        raise PeerUnavailable(
            "no_peer_creds",
            "The kernel will not describe that process. It has exited, or it "
            "belongs to another user.",
        )
    raw = buf.raw

    def _u32(offset: int) -> int:
        return int.from_bytes(raw[offset : offset + 4], sys.byteorder)

    # struct proc_bsdinfo: flags, status, xstatus, pid, ppid, uid, ...
    # pbi_pid is read back and CHECKED rather than assumed — if the layout ever
    # shifts, this raises instead of silently returning some other process's
    # parent, which is the kind of quiet wrongness that would grant a seat.
    if _u32(12) != pid:
        raise PeerUnavailable(
            "no_peer_creds", "Kernel process info did not describe the process asked about."
        )
    return _u32(16), _u32(20)


def seat_of_process(pid: int) -> tuple[str, int]:
    """(seat id, the pid it was read from), walking to the nearest ancestor
    whose environment the kernel will actually show us.

    ⚠ WHY A WALK AND NOT JUST THE PEER'S OWN ENVIRONMENT. Measured on macOS
    15 (SIP enabled), 2026-09-06: KERN_PROCARGS2 returns ZERO environment
    strings for a SYSTEM binary — `/usr/bin/curl` and `/bin/sleep` both come
    back empty — while `/usr/bin/python3` and a Homebrew python return the full
    block. curl is exactly what the seat launchers invoke, so reading only the
    immediate peer would have denied every real seat call while passing every
    test written against a python client. This was found by an end-to-end test
    and by nothing else; the unit tests all passed.

    THE RULE, and its two edges:

      * Stop at the FIRST process whose environment is readable, and treat that
        process as authoritative. Continuing past a readable-but-unseated
        process would defeat `env -u SOVEREIGN_SEAT`, re-granting a seat that
        was deliberately stripped.
      * An unreadable environment is not evidence of anything, so walk past it.

    WHAT THIS IS AND IS NOT. It is ATTRIBUTION INTEGRITY: a seat signs as the
    seat it was launched under, and cannot sign as another. It is NOT a
    privilege boundary between local processes, and it never could be — every
    process running as this user can already read the master bridge token out
    of ~/.config/sovereign-bridge.env. The honest limitation that follows: a
    process spawned by a seated terminal, whose own environment is hidden, is
    treated as that terminal's seat. That is what environment inheritance
    already means, and it is why `env -u` only works on clients that expose
    their environment.
    """
    me = os.getuid()
    seen: set[int] = set()
    current = pid
    for _ in range(_MAX_ANCESTOR_HOPS):
        if current <= 1 or current in seen:
            break
        seen.add(current)
        ppid, uid = process_info(current)
        if uid != me:
            raise PeerUnavailable(
                "wrong_uid",
                "The calling process, or the process that launched it, belongs to "
                "another user. Seats are terminals the operator started as "
                "themselves.",
            )
        environ = process_environ(current)
        if environ:
            seat = (environ.get(SEAT_ENV_VAR) or "").strip()
            if not seat:
                raise PeerUnavailable(
                    "no_seat_env",
                    f"The calling process has no {SEAT_ENV_VAR} in its environment, "
                    "so it is not a seated terminal. Launch it through its seat "
                    "launcher.",
                )
            return seat, current
        current = ppid
    raise PeerUnavailable(
        "no_seat_env",
        "No process in the caller's ancestry exposed an environment naming a "
        f"{SEAT_ENV_VAR}, so the call cannot be attributed to a seat.",
    )


def resolve_peer(sock: socket.socket) -> dict[str, Any]:
    """The verified identity of the process on the other end, or PeerUnavailable.

    Resolved ONCE per connection, at accept time, before a single request byte
    is read — which is the whole TOCTOU mitigation. A pid could in principle be
    recycled between the kernel's answer and this read; doing it at accept
    narrows that to the accept itself, and the uid check means the recycled pid
    would have to belong to the same user anyway.
    """
    pid, uid = peer_credentials(sock)
    if uid != os.getuid():
        # Asserted explicitly rather than left to procargs2's own cross-uid
        # EINVAL. A guard that holds by luck reads identically to one that
        # holds by design, and only a falsifier tells them apart.
        raise PeerUnavailable(
            "wrong_uid",
            "The peer process belongs to another user. Seats are terminals the "
            "operator started as themselves.",
        )
    seat, seat_pid = seat_of_process(pid)
    return {"pid": pid, "uid": uid, "seat": seat, "seat_pid": seat_pid}


# ── The listener ────────────────────────────────────────────────────────────


def _wrap_app(app, peer: dict[str, Any] | None, failure: PeerUnavailable | None):
    """An ASGI app that stamps the verified peer onto every http scope.

    A connection whose peer could NOT be resolved still gets a wrapper — one
    that stamps the FAILURE. That is deliberate: the alternative is an
    unstamped scope, which is indistinguishable from a TCP request and would be
    denied with the wrong reason. The caller deserves to be told that the
    socket was right and the process was wrong.
    """

    async def wrapped(scope, receive, send):
        if scope.get("type") == "http":
            extensions = dict(scope.get("extensions") or {})
            extensions[SEAT_PEER_EXT] = (
                {"ok": True, **peer}
                if peer is not None
                else {"ok": False, "reason": failure.reason, "detail": failure.detail}
            )
            scope = {**scope, "extensions": extensions}
        await app(scope, receive, send)

    return wrapped


def make_protocol_class(base):
    """Build the peer-resolving protocol subclass over a uvicorn HTTP protocol.

    Parameterised on `base` so the test suite can prove the injection against a
    stub instead of standing up uvicorn's whole stack.
    """

    class SeatPeerProtocol(base):  # type: ignore[misc,valid-type]
        def connection_made(self, transport):  # type: ignore[override]
            super().connection_made(transport)
            sock = transport.get_extra_info("socket")
            try:
                peer, failure = resolve_peer(sock), None
            except PeerUnavailable as exc:
                peer, failure = None, exc
            # uvicorn reads self.app per request, so this covers every request
            # on this connection, keep-alive included.
            self.app = _wrap_app(self.app, peer, failure)

    SeatPeerProtocol.__name__ = f"SeatPeer{getattr(base, '__name__', 'Protocol')}"
    return SeatPeerProtocol


def prepare_socket_path(path: Path) -> Path:
    """Make `path` safe to bind: owner-only directory, no stale non-socket file.

    Fails closed and LOUD. A socket that quietly ends up world-writable is the
    whole feature undone, so every failure here raises rather than degrading to
    a wider mode.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    if path.exists() or path.is_symlink():
        if not stat.S_ISSOCK(os.lstat(path).st_mode):
            raise OSError(
                f"{path} exists and is not a socket; refusing to unlink it. "
                "Seat identity will not start until that path is clear."
            )
        path.unlink()
    return path


async def start(app, path: Path, base_protocol=None, config=None) -> asyncio.AbstractServer:
    """Bind the seat socket and serve `app` on it. Returns the asyncio server.

    Owner-only (0600) by umask AND by an explicit chmod: the umask closes the
    race between bind and chmod, the chmod says the intent out loud.
    """
    import uvicorn
    from uvicorn.protocols.http.h11_impl import H11Protocol
    from uvicorn.server import ServerState

    base_protocol = base_protocol or H11Protocol
    if config is None:
        # proxy_headers=False, deliberately: ProxyHeadersMiddleware REWRITES
        # scope["client"] from X-Forwarded-For. On the one transport where the
        # kernel tells us the truth about the peer, a header must not be able
        # to restate it. (The header allowlist denies X-Forwarded-For as well;
        # this is the belt to it.)
        config = uvicorn.Config(app=app, log_level="warning", proxy_headers=False)
        config.load()
    protocol_class = make_protocol_class(base_protocol)
    server_state = ServerState()
    app_state: dict[str, Any] = {}

    path = prepare_socket_path(path)
    loop = asyncio.get_running_loop()
    previous_umask = os.umask(0o177)
    try:
        server = await loop.create_unix_server(
            lambda: protocol_class(
                config=config, server_state=server_state, app_state=app_state
            ),
            path=str(path),
        )
    finally:
        os.umask(previous_umask)
    os.chmod(path, 0o600)
    return server
