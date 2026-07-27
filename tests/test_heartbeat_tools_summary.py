"""FIX-5: public-safe tools_summary on GET /api/heartbeat.

The no-auth heartbeat now carries a small human-readable catalog summary
ALONGSIDE the pre-existing bare `tools` int. It must:
  * keep `tools` (int) exactly as before, and add `tools_summary` additively;
  * report total == the tools int, with by_scope counts summing to total;
  * name at most ~8 essential tools, EVERY one a genuine read-scope tool
    (st.tool_allowed(name, "read")), NONE in NEVER_TOOLS / guardian_* /
    set_policy / designate_protected — the guard is runtime, not a blind list;
  * derive everything from ONE list_tools fetch (get_tool_inventory);
  * fail closed: on a failed fetch (sentinel count) tools_summary is null,
    never a fabricated summary — and the endpoint still returns 200.
"""

import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import bridge  # noqa: E402
import session_tokens as st  # noqa: E402

# A catalog spanning every scope class, using real names so the real scope
# tables classify them. Read candidates + read non-candidates + write + session
# + unmapped + NEVER tools.
_READ_CANDIDATES = [
    "arrive_lineage", "start_here", "my_toolkit", "recall_insights",
    "current_policies", "inspect_claim", "compass_check",
]
_READ_NONCANDIDATES = ["get_open_threads", "spiral_status"]
_WRITE = ["record_insight", "handoff"]
_SESSION = ["close_session", "spiral_inherit"]
_OTHER = ["where_did_i_leave_off", "set_policy", "designate_protected", "some_unmapped_tool"]

_CATALOG = _READ_CANDIDATES + _READ_NONCANDIDATES + _WRITE + _SESSION + _OTHER


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
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


def _healthy_inventory(monkeypatch, names=None):
    names = list(_CATALOG) if names is None else names

    async def fake():
        return {"count": len(names), "names": names}

    monkeypatch.setattr(bridge, "get_tool_inventory", fake)
    return names


# --- healthy path ------------------------------------------------------------


def test_both_fields_present(client, monkeypatch):
    _healthy_inventory(monkeypatch)
    b = client.get("/api/heartbeat").json()
    assert isinstance(b["tools"], int)
    assert "tools_summary" in b
    assert b["tools_summary"] is not None


def test_total_equals_tools_int(client, monkeypatch):
    names = _healthy_inventory(monkeypatch)
    b = client.get("/api/heartbeat").json()
    assert b["tools"] == len(names)
    assert b["tools_summary"]["total"] == b["tools"]


def test_by_scope_sums_to_total(client, monkeypatch):
    _healthy_inventory(monkeypatch)
    b = client.get("/api/heartbeat").json()
    summary = b["tools_summary"]
    by_scope = summary["by_scope"]
    assert set(by_scope.keys()) == {"read", "write", "session", "other"}
    assert sum(by_scope.values()) == summary["total"]


def test_by_scope_classification_is_correct(client, monkeypatch):
    """Pin the real scope-table classification for the known catalog."""
    _healthy_inventory(monkeypatch)
    b = client.get("/api/heartbeat").json()
    by_scope = b["tools_summary"]["by_scope"]
    assert by_scope == {
        "read": len(_READ_CANDIDATES) + len(_READ_NONCANDIDATES),  # 9
        "write": len(_WRITE),                                      # 2
        "session": len(_SESSION),                                  # 2
        "other": len(_OTHER),                                      # 4 (unmapped + NEVER)
    }


def test_essential_names_are_all_read_scope_and_never_sensitive(client, monkeypatch):
    _healthy_inventory(monkeypatch)
    b = client.get("/api/heartbeat").json()
    essential = b["tools_summary"]["essential"]
    assert essential, "expected a non-empty essential set for a healthy catalog"
    assert len(essential) <= 8
    for name in essential:
        assert st.tool_allowed(name, ["read"]), f"{name} is not read-allowed"
        assert name not in st.NEVER_TOOLS
        assert not name.startswith("guardian_")
        assert name not in ("set_policy", "designate_protected")


def test_essential_excludes_nonread_orientation_and_write_and_never(client, monkeypatch):
    """where_did_i_leave_off is an orientation tool but is unmapped/master-only
    (it consumes handoffs), so the runtime guard filters it OUT — it lives only
    in next_if_no_token. Write and NEVER tools are likewise absent."""
    _healthy_inventory(monkeypatch)
    b = client.get("/api/heartbeat").json()
    essential = b["tools_summary"]["essential"]
    assert "where_did_i_leave_off" not in essential
    assert "record_insight" not in essential
    assert "set_policy" not in essential
    # but it is still surfaced to an unauthenticated caller as prose
    assert "where_did_i_leave_off" in b["tools_summary"]["next_if_no_token"]


def test_summary_has_note_and_next_pointer(client, monkeypatch):
    _healthy_inventory(monkeypatch)
    b = client.get("/api/heartbeat").json()
    summary = b["tools_summary"]
    assert isinstance(summary["note"], str) and summary["note"]
    assert isinstance(summary["next_if_no_token"], str) and summary["next_if_no_token"]


def test_no_sensitive_name_anywhere_in_summary(client, monkeypatch):
    """No guardian_* / set_policy / designate_protected / NEVER name may appear
    ANYWHERE in the summary payload (essential is the only place names appear,
    but assert over the whole blob as belt-and-suspenders)."""
    _healthy_inventory(monkeypatch)
    b = client.get("/api/heartbeat").json()
    blob = str(b["tools_summary"]["essential"]) + str(b["tools_summary"]["by_scope"].keys())
    for bad in list(st.NEVER_TOOLS) + ["guardian_"]:
        assert bad not in blob


# --- degraded / fail-closed path ---------------------------------------------


def test_degraded_fetch_yields_null_summary_and_200(client, monkeypatch):
    async def fake():
        return {"count": -1, "names": None}

    monkeypatch.setattr(bridge, "get_tool_inventory", fake)
    r = client.get("/api/heartbeat")
    assert r.status_code == 200
    b = r.json()
    assert b["tools"] == -1
    assert b["status"] == "degraded"
    assert b["tools_summary"] is None


def test_raising_fetch_yields_null_summary_and_200(client, monkeypatch):
    async def boom():
        raise RuntimeError("upstream exploded")

    monkeypatch.setattr(bridge, "get_tool_inventory", boom)
    r = client.get("/api/heartbeat")
    assert r.status_code == 200
    b = r.json()
    assert b["tools"] == -1
    assert b["tools_summary"] is None


def test_tools_int_unchanged_shape(client, monkeypatch):
    """The pre-existing `tools` int is untouched — additive only."""
    names = _healthy_inventory(monkeypatch)
    b = client.get("/api/heartbeat").json()
    assert b["tools"] == len(names)
    assert isinstance(b["tools"], int)
