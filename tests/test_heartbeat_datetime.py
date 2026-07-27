"""Bulletproof datetime delivery + clock-trust self-attestation on /api/heartbeat.

The heartbeat is the one place an arriving instance reads the current datetime,
so server_time_utc must ALWAYS be present and trustworthy — even when the
upstream tool count is down, hangs, the comms scan hits a corrupt file, or an
unanticipated exception is raised. clock_synced is a three-state signal whose
empty/stale/egress-down case maps to the STRING "unknown", never False.

Mock seams: bridge.COMMS_DIR (-> tmp_path), bridge.get_tool_inventory
(the single list_tools fetch the heartbeat derives both its int count and its
public tools_summary from), bridge.CLOCK_PROBE, bridge.HEARTBEAT_TOOL_TIMEOUT.
All time/state mocks are
function-scoped via monkeypatch (auto-teardown) — nothing leaks across tests.
"""

import asyncio
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import bridge  # noqa: E402


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    """Point COMMS_DIR at an empty tmp dir and default the clock probe to a
    fresh, low-drift reading so the base case is well-defined. Auto-applied,
    auto-torn-down — no module-level patch leaks."""
    monkeypatch.setattr(bridge, "COMMS_DIR", tmp_path)
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


@pytest.fixture
def client():
    return TestClient(bridge.app)


def _ok_count(monkeypatch, n=82):
    async def fake():
        return {"count": n, "names": [f"tool_{i}" for i in range(n)]}

    monkeypatch.setattr(bridge, "get_tool_inventory", fake)


# --- datetime delivery / consistency ----------------------------------------


def test_time_advances_across_two_calls(client, monkeypatch):
    _ok_count(monkeypatch)
    t1 = client.get("/api/heartbeat").json()["timestamp"]
    t2 = client.get("/api/heartbeat").json()["timestamp"]
    assert t2 >= t1


def test_within_two_seconds_of_wall_clock(client, monkeypatch):
    _ok_count(monkeypatch)
    b = client.get("/api/heartbeat").json()
    assert abs(b["timestamp"] - time.time()) < 2.0


def test_utcoffset_is_zero(client, monkeypatch):
    _ok_count(monkeypatch)
    b = client.get("/api/heartbeat").json()
    dt = datetime.fromisoformat(b["server_time_utc"])
    assert dt.utcoffset() == timedelta(0)


def test_epoch_and_iso_consistent(client, monkeypatch):
    _ok_count(monkeypatch)
    b = client.get("/api/heartbeat").json()
    iso_epoch = datetime.fromisoformat(b["server_time_utc"]).timestamp()
    assert abs(iso_epoch - b["timestamp"]) < 0.001


def test_existing_fields_present(client, monkeypatch):
    """All pre-existing fields stay; new ones are additive."""
    _ok_count(monkeypatch)
    b = client.get("/api/heartbeat").json()
    for field in ("status", "version", "tools", "comms_messages", "timestamp",
                  "server_time_utc", "welcome", "next"):
        assert field in b, f"missing pre-existing field {field}"
    for field in ("clock_synced", "drift_seconds", "drift_measured_at",
                  "clock_probe_age_seconds"):
        assert field in b, f"missing new field {field}"


# --- datetime survives upstream failure modes -------------------------------


def test_datetime_present_when_tool_count_negative(client, monkeypatch):
    async def fake():
        return {"count": -1, "names": None}

    monkeypatch.setattr(bridge, "get_tool_inventory", fake)
    b = client.get("/api/heartbeat").json()
    assert b["status"] == "degraded"
    assert b["tools"] == -1
    assert "server_time_utc" in b and b["server_time_utc"]


def test_datetime_present_when_tool_count_raises(client, monkeypatch):
    async def boom():
        raise RuntimeError("upstream exploded")

    monkeypatch.setattr(bridge, "get_tool_inventory", boom)
    b = client.get("/api/heartbeat").json()
    assert b["status"] == "degraded"
    assert b["tools"] == -1
    assert "server_time_utc" in b and b["server_time_utc"]


def test_datetime_present_when_tool_count_hangs(client, monkeypatch):
    """A hanging upstream must funnel through the bounded wait into the
    degraded path — datetime still delivered. Timeout shrunk for speed."""
    monkeypatch.setattr(bridge, "HEARTBEAT_TOOL_TIMEOUT", 0.01)

    async def hang():
        await asyncio.sleep(5.0)
        return {"count": 82, "names": [f"tool_{i}" for i in range(82)]}

    monkeypatch.setattr(bridge, "get_tool_inventory", hang)
    b = client.get("/api/heartbeat").json()
    assert b["status"] == "degraded"
    assert b["tools"] == -1
    assert "server_time_utc" in b and b["server_time_utc"]


def test_corrupt_comms_file_yields_sentinel(client, monkeypatch, tmp_path):
    """A non-UTF8 / corrupt .jsonl in COMMS_DIR => 200 + datetime intact +
    comms_messages sentinel -1."""
    _ok_count(monkeypatch)
    (tmp_path / "bad.jsonl").write_bytes(b"\xff\xfe\x00 not valid utf8 \x80\x81")
    r = client.get("/api/heartbeat")
    assert r.status_code == 200
    b = r.json()
    assert b["comms_messages"] == -1
    assert "server_time_utc" in b and b["server_time_utc"]


def test_unhandled_exception_carries_timestamp(monkeypatch):
    """A generic exception raised before any handler-internal guard must still
    yield a timestamped body via @app.exception_handler(Exception). Driven
    through /api/call (unguarded path). raise_server_exceptions=False so the
    handler's response is observed instead of being re-raised by TestClient."""
    monkeypatch.setattr(bridge, "check_auth", lambda *a, **k: None)

    async def boom(tool, args):
        raise RuntimeError("unanticipated raise")

    monkeypatch.setattr(bridge, "call_mcp_tool", boom)
    c = TestClient(bridge.app, raise_server_exceptions=False)
    r = c.post("/api/call", json={"tool": "x", "arguments": {}})
    assert r.status_code == 500
    b = r.json()
    assert b["failure_class"] == "internal"
    assert "server_time_utc" in b and b["server_time_utc"]
    assert "timestamp" in b
    # the emitted server_time_utc is a real, parseable UTC instant
    assert datetime.fromisoformat(b["server_time_utc"]).utcoffset() == timedelta(0)


# --- clock_synced three-state mapping ---------------------------------------


def _set_probe(monkeypatch, *, drift, age_seconds, present=True):
    if not present:
        probe = {"drift_seconds": None, "drift_uncertainty": None,
                 "drift_measured_at": None, "drift_source": None}
    else:
        measured = datetime.now(timezone.utc) - timedelta(seconds=age_seconds)
        probe = {"drift_seconds": drift, "drift_uncertainty": 0.006,
                 "drift_measured_at": measured.isoformat(),
                 "drift_source": "time.apple.com"}
    monkeypatch.setattr(bridge, "CLOCK_PROBE", probe)


def test_clock_synced_fresh_low_drift_true(client, monkeypatch):
    _ok_count(monkeypatch)
    _set_probe(monkeypatch, drift=0.04, age_seconds=10)
    b = client.get("/api/heartbeat").json()
    assert b["clock_synced"] is True
    assert b["drift_seconds"] == 0.04
    assert b["clock_probe_age_seconds"] is not None


def test_clock_synced_fresh_high_drift_false(client, monkeypatch):
    _ok_count(monkeypatch)
    _set_probe(monkeypatch, drift=1.5, age_seconds=10)
    b = client.get("/api/heartbeat").json()
    assert b["clock_synced"] is False  # real measured drift -> False is honest


def test_clock_synced_stale_is_unknown_not_false(client, monkeypatch):
    _ok_count(monkeypatch)
    # age well past 2x interval, with a drift that WOULD read False if fresh —
    # staleness must override into "unknown", never False.
    _set_probe(monkeypatch, drift=1.5, age_seconds=2 * bridge.CLOCK_PROBE_INTERVAL + 60)
    b = client.get("/api/heartbeat").json()
    assert b["clock_synced"] == "unknown"
    assert b["clock_synced"] is not False


def test_clock_synced_empty_is_unknown_not_false(client, monkeypatch):
    _ok_count(monkeypatch)
    _set_probe(monkeypatch, drift=None, age_seconds=0, present=False)
    b = client.get("/api/heartbeat").json()
    assert b["clock_synced"] == "unknown"
    assert b["clock_synced"] is not False
    assert b["drift_seconds"] is None
    assert b["clock_probe_age_seconds"] is None


# --- the read-only sntp parser ----------------------------------------------


def test_parse_sntp_signed_offset():
    assert bridge._parse_sntp(
        "+0.039766 +/- 0.006780 time.apple.com 2620:149:a33::21"
    ) == (0.039766, 0.006780)
    assert bridge._parse_sntp(
        "-1.250000 +/- 0.010000 pool.ntp.org 1.2.3.4"
    ) == (-1.25, 0.01)


def test_parse_sntp_no_match_returns_none():
    assert bridge._parse_sntp("sntp: no servers can be used, exiting") is None
    assert bridge._parse_sntp("") is None
