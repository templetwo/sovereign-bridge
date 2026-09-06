"""Prove the suite touches neither Anthony's credentials nor the network.

Adapted from the reviewer's instrument
(`~/.sovereign/hq/lanes/runs/rc_bridge_e728255/audit_heartbeat_tests.py`,
gpt-6-astra, Codex seat 3/3), which found the defect this file now guards:
running ONE heartbeat test recorded **one read of
`~/.config/sovereign-bridge.env` and two attempted connections to
127.0.0.1:3434** while the test passed. The test was green and the environment
was not isolated.

⚠ NOT A TEST MODULE. It runs the suite inside itself, so pytest must not
collect it — hence the name. Run it directly:

    TMPDIR=<worktree>/.tmp python3 tests/isolation_audit.py

Exit 0 means clean; exit 1 prints what was touched.

TWO CHANGES FROM THE ORIGINAL, both to make the claim bigger and more honest:

  1. IT RUNS THE WHOLE SUITE, not one test. A single test proves one path is
     clean and says nothing about the other four hundred.
  2. IT COUNTS AF_INET AND AF_UNIX CONNECTS SEPARATELY, AND DOES NOT BLOCK THE
     LATTER. The original raised PermissionError on every `socket.connect`,
     which would kill `tests/test_seat_socket.py` — a suite whose whole subject
     is a Unix domain socket. "Zero connection attempts" is true of the
     internet and false of the filesystem, and summing the two into one
     reassuring zero would be the same shape of lie the suite exists to catch.
     Every AF_UNIX path is printed so a reader can see they are test-owned.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
os.chdir(REPO)
sys.path.insert(0, str(REPO))

REAL_CREDENTIAL_FILE = str(Path.home() / ".config" / "sovereign-bridge.env")

credential_reads: list[str] = []
inet_connects: list[str] = []
unix_connects: list[str] = []
file_opens_of_credential: list[str] = []


def _audit(event, args):
    # `socket.connect` fires for every family. An AF_UNIX address is a str (or
    # bytes) path; an AF_INET address is a (host, port) tuple. That distinction
    # is the whole reason this instrument can run the socket suite at all.
    if event == "socket.connect":
        address = args[1] if len(args) > 1 else None
        if isinstance(address, tuple):
            inet_connects.append(repr(address))
        else:
            unix_connects.append(repr(address))
    elif event == "open":
        path = args[0] if args else None
        if isinstance(path, (str, bytes, os.PathLike)) and str(path) == REAL_CREDENTIAL_FILE:
            file_opens_of_credential.append(str(path))


sys.addaudithook(_audit)

# The reviewer's own belt: intercept `Path.read_text` on the real credential
# file. Kept because it catches a read that some future refactor routes around
# `open` (a memory-mapped read, a C extension), and because it is the exact
# check that produced the original finding.
_original_read_text = Path.read_text


def _guarded_read_text(self, *a, **k):
    if str(self) == REAL_CREDENTIAL_FILE:
        credential_reads.append(str(self))
        return "BRIDGE_TOKEN=intercepted-by-isolation-audit\n"
    return _original_read_text(self, *a, **k)


Path.read_text = _guarded_read_text

import pytest  # noqa: E402  (must follow the hooks above)

status = pytest.main(
    ["-q", "-p", "no:randomly", "-p", "no:cacheprovider", "tests", "watchman/tests"]
)

report = {
    "pytest_exit": int(status),
    "credential_file": REAL_CREDENTIAL_FILE,
    "credential_read_text_intercepted": len(credential_reads),
    "credential_open_calls": len(file_opens_of_credential),
    "inet_connect_attempts": inet_connects,
    "unix_connect_count": len(unix_connects),
    "unix_connect_paths_sample": sorted(set(unix_connects))[:10],
    "bridge_module": sys.modules["bridge"].__file__ if "bridge" in sys.modules else None,
    "bridge_env_file_in_use": os.environ.get("SOVEREIGN_BRIDGE_ENV_FILE"),
}
print(json.dumps(report, indent=2))

clean = (
    report["credential_read_text_intercepted"] == 0
    and report["credential_open_calls"] == 0
    and not report["inet_connect_attempts"]
)
if not clean:
    print("ISOLATION FAILED: the suite reached the live credential file or the network")
sys.exit(0 if clean and status == 0 else 1)
