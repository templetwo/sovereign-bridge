"""Suite-wide isolation from Anthony's live credentials and from the network.

Codex review 2026-09-06, F6: *"the suite is not isolated from live
credentials/upstream by default."* The review instrumented ONE test
(`test_the_field_is_on_the_heartbeat_at_all`), watched it pass, and recorded
**one intercepted read of `~/.config/sovereign-bridge.env` and two attempted
connections to 127.0.0.1:3434** while it did. The test was green and the
environment was not isolated; only the reviewer's sandbox stopped the
connections from landing. That is the shape this house calls a fail-open on the
instrument: the suite reported a clean result about a condition it was not
measuring.

⚠ WHY THIS IS A ROOT `conftest.py` AND WHY HALF OF IT IS NOT A FIXTURE.

`bridge.py` reads the credential file at **import**, and a test module imports
bridge at **collection** — before any fixture, including an autouse one, has
ever run. So no fixture can close that read. The credential redirect below is
therefore executed at conftest MODULE scope, which pytest evaluates before it
collects a single test, and it works by pointing `SOVEREIGN_BRIDGE_ENV_FILE`
(the seam added to bridge.py / bridge_config.py / watchman_sweep.py in the same
commit) at a synthetic file. Nothing here decrypts, copies, prints or reads the
real file; the suite simply never opens it.

Root rather than `tests/` because `watchman/tests/` needs the same guarantee and
`watchman_sweep.load_bridge_token()` reads the same path.

THE FOUR GUARANTEES, and the honest bound on the last:

  1. ZERO reads of `~/.config/sovereign-bridge.env`. The path is never resolved.
  2. ZERO upstream MCP traffic. The block is on `bridge.sse_client`, the ONE
     transport both `call_mcp_tool` and `_list_tools_raw` open — not on those
     two functions. Blocking the functions was the first draft and it was
     wrong: `tests/test_p1_envelope.py` calls `call_mcp_tool` deliberately with
     its own fake transport to prove the isError fail-closed gate, and a
     fixture that replaced the function under test would have deleted that
     proof while the suite went green. Blocking the transport leaves every
     real code path intact and only removes the socket. A test that installs
     its own `sse_client` overrides this, which is the intended order.
  3. ZERO writes to a live store. `bridge._IDEM_PATH`, `bridge.COMMS_DIR`,
     `bridge.LEGACY_LEDGER_FILE` and `session_tokens.DB_PATH` are module-level
     constants pointing into `~/.sovereign`, and only the tests that already
     knew redirected them. See `_no_live_stores` for how that was found.
  4. ZERO TCP/UDP connect attempts. AF_UNIX connects are ALLOWED and that is
     not a loophole being smuggled past: `tests/test_seat_socket.py` exists to
     exercise a Unix-domain socket, and every path it opens is a pytest
     `tmp_path` the test created. "Zero connection attempts" is therefore true
     of the internet and false of the filesystem, and the isolation instrument
     (`tests/isolation_audit.py`) reports the two counts SEPARATELY rather than
     summing them into a reassuring zero.
"""

from __future__ import annotations

import json
import os
import socket
import sys
import tempfile
from pathlib import Path

import pytest

# ── 1. The credential redirect. MODULE SCOPE, BEFORE COLLECTION. ────────────
_SYNTHETIC_ENV_DIR = Path(tempfile.mkdtemp(prefix="sovereign-bridge-test-env-"))
_SYNTHETIC_ENV_FILE = _SYNTHETIC_ENV_DIR / "sovereign-bridge.env"
_SYNTHETIC_ENV_FILE.write_text(
    # Deliberately worthless, and deliberately SHAPED like the real thing so a
    # code path that parses the file is still exercised. A bridge running on
    # this token can authenticate nothing.
    "BRIDGE_TOKEN=synthetic-test-token-not-a-credential\n"
    "ARRIVAL_GATE_ENABLED=0\n"
)
os.environ["SOVEREIGN_BRIDGE_ENV_FILE"] = str(_SYNTHETIC_ENV_FILE)

# The repo root, so `import bridge` resolves to THIS tree from any suite dir.
sys.path.insert(0, str(Path(__file__).resolve().parent))

import seat_identity  # noqa: E402  (must follow the sys.path insert above)

# ⚠ THE PINNED SURFACE LIVES IN suite_support.py, NOT HERE, FOR ONE REASON:
# watchman/tests/ has its OWN conftest.py, so `from conftest import X` in a test
# module resolves to whichever conftest pytest imported last and dies at
# collection. A plain module has one name and one meaning.
from suite_support import PINNED_SURFACE  # noqa: E402


class UpstreamBlocked(RuntimeError):
    """A test reached for the live stack. Stub the seam; do not open a socket."""


@pytest.fixture(autouse=True)
def _no_live_upstream(monkeypatch):
    """Fail CLOSED on the upstream TRANSPORT, for every test, unless it stubs it.

    `call_mcp_tool` then returns its own `{"ok": False, failure_class:
    "egress"}` and `_list_tools_raw` raises, exactly as they do when the SSE
    server is down — so every caller's real degradation path is exercised
    instead of bypassed.

    `bridge` is looked up in `sys.modules` rather than imported: the watchman
    suite has no reason to pull in FastAPI, and an autouse fixture that forced
    the import would make every watchman test depend on the bridge's import
    side effects.
    """
    bridge = sys.modules.get("bridge")
    if bridge is None:
        return

    def _blocked_sse(url, headers=None):
        raise UpstreamBlocked(
            f"SSE connection to {url!r} blocked by conftest.py: the suite does "
            "not talk to the live stack. Install a fake transport in the test."
        )

    monkeypatch.setattr(bridge, "sse_client", _blocked_sse, raising=False)


@pytest.fixture(autouse=True)
def _no_live_stores(monkeypatch, tmp_path_factory):
    """Every module-level path that points at a LIVE store is redirected.

    ⚠ FOUND BY DOING IT. Writing `tests/test_seat_protected.py` put one
    synthetic idempotency entry into Anthony's real
    `~/.sovereign/bridge/idempotency.json`, because `bridge._IDEM_PATH` is a
    module-level constant and only the tests that already knew about it
    monkeypatched it. The entry was removed; the hole is closed here rather
    than in the one test that happened to expose it.

    This is the exact class SOP #12's closing bullet names: *"isolate EVERY
    write path a test can reach, not just the obvious store."* It fired in
    sovereign-stack in August (a token-DB test writing 14 real chronicle
    records) and it fired here. A per-test opt-in is not isolation — it is a
    convention, and a convention is only as good as the next author's memory.

    `st.DB_PATH` is redirected for the same reason: the session-token store is
    a live SQLite file at `~/.sovereign/bridge/session_tokens.db`.
    """
    root = tmp_path_factory.mktemp("live-store-isolation")
    bridge = sys.modules.get("bridge")
    if bridge is not None:
        monkeypatch.setattr(bridge, "_IDEM_PATH", root / "idempotency.json", raising=False)
        monkeypatch.setattr(bridge, "COMMS_DIR", root / "comms", raising=False)
        monkeypatch.setattr(
            bridge, "LEGACY_LEDGER_FILE", root / "legacy_callers.json", raising=False
        )
    session_tokens = sys.modules.get("session_tokens")
    if session_tokens is not None:
        monkeypatch.setattr(
            session_tokens, "DB_PATH", root / "session_tokens.db", raising=False
        )


@pytest.fixture(autouse=True)
def _no_inet_sockets(monkeypatch, request):
    """No test opens a TCP/UDP connection. AF_UNIX is untouched.

    Marker `@pytest.mark.allow_inet` opts a test out — nothing uses it today,
    and it exists so that the day something legitimately needs a socket the
    exemption is VISIBLE in the test rather than achieved by deleting this
    fixture.
    """
    if request.node.get_closest_marker("allow_inet"):
        return

    real_connect = socket.socket.connect
    real_connect_ex = socket.socket.connect_ex

    def _guard(sock, address):
        if sock.family in (socket.AF_INET, socket.AF_INET6):
            raise UpstreamBlocked(
                f"TCP connect to {address!r} blocked by conftest.py. The suite "
                "must not reach the live bridge, the live SSE server, or "
                "anything else off this process."
            )

    def _connect(self, address):
        _guard(self, address)
        return real_connect(self, address)

    def _connect_ex(self, address):
        _guard(self, address)
        return real_connect_ex(self, address)

    monkeypatch.setattr(socket.socket, "connect", _connect)
    monkeypatch.setattr(socket.socket, "connect_ex", _connect_ex)


@pytest.fixture(autouse=True)
def surface(monkeypatch):
    """EVERY test in EVERY suite decides against PINNED_SURFACE.

    ⚠ AUTOUSE, AND SUITE-WIDE, BECAUSE THE ALTERNATIVE IS AMBIENT. Left
    unpinned, `published_surface()` resolves whatever stack tree happens to be
    importable on the machine running pytest — which on this one is the LIVE
    checkout, a tree that has no `RETIRED_TOOLS` at all. Three suites would
    then have verdicts that move when somebody deploys the stack, which is the
    exact failure `tests/test_heartbeat_signals.py`'s own docstring warns
    about: red today, green after an unrelated merge, for reasons unrelated to
    the code under test.

    The RESOLUTION logic itself is not stubbed away — it has its own tests in
    `tests/test_seat_surface.py`, which reset the cache and drive both routes
    deliberately.
    """
    seat_identity.reset_published_cache()

    async def _pinned(fetch=None):
        return PINNED_SURFACE

    monkeypatch.setattr(seat_identity, "published_surface", _pinned)
    yield PINNED_SURFACE
    seat_identity.reset_published_cache()



def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "allow_inet: this test may open a TCP/UDP socket (see conftest._no_inet_sockets)",
    )
