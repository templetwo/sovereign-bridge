"""`unacked_signals` on the heartbeat — what the watch seats raised and nobody closed.

The fourth census on the door, after aperture, gate and attribution, and it
inherits their one non-negotiable invariant:

    A LEDGER THAT CANNOT BE READ SAYS SO. IT NEVER SAYS ZERO.

That is not a stylistic preference. `unacked_signals: 0` is the most reassuring
sentence this field can produce — "every signal is closed, nothing is waiting" —
and it is exactly what a missing file, an unreadable ledger, a failed import or
a daemon that never ran would produce if any of them were allowed to render as a
count. The whole point of putting the number on the door is that somebody acts on
it, and a manufactured zero is an instruction to stop looking.

⚠ THE IMPORT IS EXPECTED TO FAIL TODAY, AND THE TESTS MUST NOT DEPEND ON WHICH
WAY IT WENT. bridge.py adds ~/sovereign-stack/src to sys.path, so
`sovereign_stack` resolves to the LIVE checked-out tree — where signal_ledger.py
does not exist until the stack's release/2026-09-06 is merged and deployed. A
test that asserted "the field is populated" would therefore be red today and
green after an unrelated deploy, and a test that asserted "the field is an
error" would invert the moment the stack lands. So every test below injects the
behaviour it is testing (monkeypatching `bridge._signal_heartbeat_field`, the
same seam `_measure_aperture` uses) and asserts the CONTRACT, which is true in
both worlds.
"""

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import bridge  # noqa: E402

client = TestClient(bridge.app)


def _hb():
    r = client.get("/api/heartbeat")
    assert r.status_code == 200
    return r.json()


# A populated read, shaped exactly as sovereign_stack.signal_ledger.heartbeat_field
# returns it. Verified against the real module on the stack release branch
# (release/2026-09-06) rather than invented: total/stale_24h/stale_7d/by_source/
# error/ingestion/scanned_at, plus whatever else that module later adds, which
# is why the bridge spreads the dict instead of rebuilding it field by field.
LIVE = {
    "error": None,
    "ingestion": "ok",
    "scanned_at": "2026-09-06T12:00:00Z",
    "total": 7,
    "stale_24h": 3,
    "stale_7d": 1,
    "by_source": {"honk": 4, "watchman": 3},
}


def test_the_field_is_on_the_heartbeat_at_all():
    """A field written and unwired is this house's most expensive shape. It is
    on the door, under the name Anthony's instruction used."""
    assert "unacked_signals" in _hb()


def test_a_populated_ledger_reports_its_counts(monkeypatch):
    monkeypatch.setattr(bridge, "_signal_heartbeat_field", lambda root=None: dict(LIVE))
    field = _hb()["unacked_signals"]
    assert field["total"] == 7
    assert field["stale_24h"] == 3
    assert field["stale_7d"] == 1
    assert field["by_source"] == {"honk": 4, "watchman": 3}
    assert field["error"] is None


def test_extra_fields_the_ledger_grows_are_carried_through(monkeypatch):
    """The bridge spreads the ledger's own dict rather than transcribing it.
    The stack added corrupt_rows / source_status / sources_degraded to this
    payload the same day it shipped; a bridge that transcribed field-by-field
    would have silently dropped them and nobody would have known."""
    monkeypatch.setattr(
        bridge, "_signal_heartbeat_field", lambda root=None: {**LIVE, "corrupt_rows": 2}
    )
    assert _hb()["unacked_signals"]["corrupt_rows"] == 2


# ── The invariant: never a zero ─────────────────────────────────────────────


def test_a_raising_ledger_is_an_error_state_and_not_a_zero(monkeypatch):
    """THE TEST THIS FIELD EXISTS FOR. A read that raises must render an error
    with NO count — not 0, not "-", not an omitted key that a consumer will
    coalesce to 0."""

    def boom(root=None):
        raise OSError("permission denied")

    monkeypatch.setattr(bridge, "_signal_heartbeat_field", boom)
    field = _hb()["unacked_signals"]
    assert field["total"] is None
    assert field["stale_24h"] is None and field["stale_7d"] is None
    assert field["by_source"] is None
    assert field["error"] == "unreadable:OSError"
    assert field["ingestion"] == "error"


def test_a_missing_signal_ledger_module_is_an_error_state(monkeypatch):
    """The state this bridge actually ships in until the stack merges: the
    import failed, so the stub raises. The door must say
    `signal_ledger_unavailable`, which is a fact about the deploy, and must not
    say the queue is empty."""

    def unavailable(root=None):
        raise RuntimeError("sovereign_stack.signal_ledger unavailable")

    monkeypatch.setattr(bridge, "_signal_heartbeat_field", unavailable)
    field = _hb()["unacked_signals"]
    assert field["error"] == "signal_ledger_unavailable"
    assert field["total"] is None


def test_a_never_scanned_ledger_is_not_a_healthy_zero(monkeypatch):
    """Upstream already distinguishes "scanned, found nothing" from "never
    scanned", and the bridge must not flatten the two. `not_scanned` carries
    total None; the bridge passes it through untouched."""
    monkeypatch.setattr(
        bridge,
        "_signal_heartbeat_field",
        lambda root=None: {
            "error": "not_scanned",
            "ingestion": "never",
            "scanned_at": None,
            "total": None,
            "stale_24h": None,
            "stale_7d": None,
            "by_source": None,
        },
    )
    field = _hb()["unacked_signals"]
    assert field["error"] == "not_scanned"
    assert field["total"] is None


def test_a_genuine_empty_queue_is_still_reportable_as_zero(monkeypatch):
    """THE FALSIFIER for every test above. If "never zero" were implemented by
    refusing to emit 0 at all, the field would be useless in the state everyone
    wants it to reach — a clean, scanned, fully-acknowledged ledger. A MEASURED
    zero is the good news; only a MANUFACTURED one is the lie."""
    monkeypatch.setattr(
        bridge,
        "_signal_heartbeat_field",
        lambda root=None: {**LIVE, "total": 0, "stale_24h": 0, "stale_7d": 0, "by_source": {}},
    )
    field = _hb()["unacked_signals"]
    assert field["total"] == 0
    assert field["error"] is None


def test_a_nonsense_return_is_refused_rather_than_passed_on(monkeypatch):
    """A ledger that returns a list, a string or None is a broken instrument,
    and passing its value through would put an uninterpretable `unacked_signals`
    on a public route. Fail closed into the error state instead."""
    for junk in (None, [], "7", 7):
        monkeypatch.setattr(bridge, "_signal_heartbeat_field", lambda root=None, j=junk: j)
        field = _hb()["unacked_signals"]
        assert field["total"] is None, junk
        assert field["error"].startswith("unreadable:"), junk


def test_a_broken_ledger_does_not_sink_the_heartbeat(monkeypatch):
    """The heartbeat is the one surface an arriving seat hits before it believes
    anything, and it must survive every subsystem it reports on. A signal-ledger
    failure must leave the clock, the version and the other three censuses
    intact."""

    def boom(root=None):
        raise RuntimeError("nope")

    monkeypatch.setattr(bridge, "_signal_heartbeat_field", boom)
    body = _hb()
    assert body["unacked_signals"]["total"] is None
    for key in ("server_time_utc", "version", "aperture", "gate", "attribution"):
        assert key in body, key


# ── Against the real module, when it is on disk ─────────────────────────────


def test_the_contract_holds_against_the_real_stack_module(tmp_path):
    """The tests above prove the BRIDGE's half against a stub, which is the
    only way to test it deterministically today. This one closes the loop on
    the other half: the actual `sovereign_stack.signal_ledger.heartbeat_field`
    must honour the same never-zero contract, or the bridge's guarantee is only
    a guarantee about its own stub.

    Skipped, not failed, when the stack tree carrying the module is not on
    disk — a bridge checkout without its companion repo is a legitimate state.

    ⚠ RUN IN A SUBPROCESS, AND THAT IS NOT FASTIDIOUSNESS. Importing bridge has
    ALREADY bound `sovereign_stack` to the LIVE tree (bridge.py:49), so
    prepending another src to sys.path here changes nothing — the package's
    __path__ is fixed and `sovereign_stack.signal_ledger` raises
    ModuleNotFoundError while the file sits right there on disk. That failure
    reads exactly like "the module is broken" and is entirely the harness. A
    fresh interpreter with the release src first is both the honest measurement
    and precisely what the deployed bridge will do once the stack is checked
    out.
    """
    import json as _json
    import subprocess

    candidates = [
        Path.home() / ".cache" / "wt-release-stack" / "src",
        Path.home() / "sovereign-stack" / "src",
    ]
    src = next(
        (p for p in candidates if (p / "sovereign_stack" / "signal_ledger.py").exists()), None
    )
    if src is None:
        pytest.skip("sovereign_stack.signal_ledger not on disk yet")

    probe = (
        "import json,sys;sys.path.insert(0,%r);"
        "from sovereign_stack.signal_ledger import heartbeat_field;"
        "print(json.dumps(heartbeat_field(__import__('pathlib').Path(%r))))"
        % (str(src), str(tmp_path))
    )
    out = subprocess.run(
        [sys.executable, "-B", "-c", probe], capture_output=True, text=True, timeout=60
    )
    assert out.returncode == 0, out.stderr
    empty = _json.loads(out.stdout)
    assert empty["total"] is None, "a never-scanned ledger reported a count"
    assert empty["error"] == "not_scanned"
