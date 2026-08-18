"""FIX-4: scoped-token tool ENUMERATION on GET /api/tools (filtered, fail-closed).

A session token may now list tools — but only the ones its scope allows. It must
NEVER see the full catalog, NEVER see NEVER_TOOLS, and NEVER be able to confirm
the existence of an out-of-scope tool (?name= on a hidden tool returns 404, not
403). The master token's behavior is byte-identical to before (full catalog).

The single list_tools fetch is mocked at bridge._list_tools_raw (the seam shared
by /api/tools and the heartbeat inventory) so there is no live-SSE dependency.
"""

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import bridge  # noqa: E402
import session_tokens as st  # noqa: E402

MASTER = "test-master-token-0123456789abcdef-0123456789abcdef"

# A catalog spanning every classification the filter must handle. Names are real
# so they exercise the real TOOL_SCOPES / NEVER_TOOLS tables.
READ_TOOL = "recall_insights"        # read scope
READ_TOOL_2 = "arrive_lineage"       # read scope
WRITE_TOOL = "record_insight"        # write scope — out of a read grant
SESSION_TOOL = "close_session"       # session scope — out of a read grant
NEVER_TOOL = "set_policy"            # hard denylist — never visible to any scope
NEVER_TOOL_2 = "designate_protected"  # hard denylist
UNMAPPED_TOOL = "some_future_unmapped_tool"  # default-deny (master-only)

_CATALOG_NAMES = [
    READ_TOOL, READ_TOOL_2, WRITE_TOOL, SESSION_TOOL,
    NEVER_TOOL, NEVER_TOOL_2, UNMAPPED_TOOL,
]


def _fake_tool(name):
    return SimpleNamespace(
        name=name,
        description=f"description for {name}",
        inputSchema={"type": "object", "properties": {"q": {"type": "string"}}, "required": []},
    )


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setattr(st, "DB_PATH", tmp_path / "session_tokens.db")
    monkeypatch.setattr(bridge, "BEARER_TOKEN", MASTER)

    async def fake_raw():
        return [_fake_tool(n) for n in _CATALOG_NAMES]

    monkeypatch.setattr(bridge, "_list_tools_raw", fake_raw)

    # Isolate the chronicle write path too. admin_mint records every grant via
    # call_mcp_tool -> live SSE (:3434) -> record_insight. Without this stub the
    # suite writes REAL "Arrival grant ... decided via hq_mint" ground_truth
    # entries (with a human receipt) into the production chronicle on every run
    # -- observed 2026-08-16: 14 false grant records in ~/.sovereign/chronicle
    # from two runs of this file. Same shape as the boot_ritual tests asserting
    # against the live store: the token DB was isolated, the record was not.
    async def fake_call_mcp_tool(tool_name, arguments):
        return {"ok": True, "stubbed": tool_name}

    monkeypatch.setattr(bridge, "call_mcp_tool", fake_call_mcp_tool)
    return TestClient(bridge.app)


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def _mint(client, scope):
    r = client.post(
        "/api/admin/tokens/mint",
        json={"scope": scope, "ttl_hours": 12},
        headers=_auth(MASTER),
    )
    assert r.status_code == 200
    return r.json()["session_token"]


# --- the filtered list -------------------------------------------------------


def test_read_token_lists_only_read_tools(client):
    tok = _mint(client, ["read"])
    r = client.get("/api/tools", headers=_auth(tok))
    assert r.status_code == 200
    body = r.json()
    names = {t["name"] for t in body["tools"]}
    # only the read-scope tools are visible
    assert names == {READ_TOOL, READ_TOOL_2}
    # every hidden class is absent
    assert WRITE_TOOL not in names
    assert SESSION_TOOL not in names
    assert NEVER_TOOL not in names
    assert NEVER_TOOL_2 not in names
    assert UNMAPPED_TOOL not in names
    # the count reflects the FILTERED set, not the full catalog
    assert body["count"] == 2


def test_read_token_never_tool_absent_from_list(client):
    """Belt-and-suspenders: a NEVER tool is invisible even though it exists in
    the catalog the master would see."""
    tok = _mint(client, ["read"])
    body = client.get("/api/tools", headers=_auth(tok)).json()
    blob = str(body)
    assert NEVER_TOOL not in blob
    assert NEVER_TOOL_2 not in blob


# --- the ?name= path (404 hides existence) -----------------------------------


def test_name_lookup_in_scope_returns_schema(client):
    tok = _mint(client, ["read"])
    r = client.get(f"/api/tools?name={READ_TOOL}", headers=_auth(tok))
    assert r.status_code == 200
    body = r.json()
    assert body["name"] == READ_TOOL
    assert body["inputSchema"]["type"] == "object"


def test_name_lookup_out_of_scope_returns_404(client):
    """A write tool a read token cannot use must 404 (hide existence), NOT 403
    — a 403 would confirm the tool exists."""
    tok = _mint(client, ["read"])
    r = client.get(f"/api/tools?name={WRITE_TOOL}", headers=_auth(tok))
    assert r.status_code == 404
    # failure_class is 'malformed' (the unknown-tool class), identical to a
    # genuinely-unknown name — no signal that the tool is real-but-forbidden.
    assert r.json()["failure_class"] == "malformed"


def test_name_lookup_never_tool_returns_404(client):
    tok = _mint(client, ["read"])
    r = client.get(f"/api/tools?name={NEVER_TOOL}", headers=_auth(tok))
    assert r.status_code == 404


def test_name_lookup_session_scope_tool_returns_404_for_read_token(client):
    tok = _mint(client, ["read"])
    r = client.get(f"/api/tools?name={SESSION_TOOL}", headers=_auth(tok))
    assert r.status_code == 404


# --- master is byte-identical to before --------------------------------------


def test_master_token_sees_full_catalog(client):
    r = client.get("/api/tools", headers=_auth(MASTER))
    assert r.status_code == 200
    body = r.json()
    names = {t["name"] for t in body["tools"]}
    assert names == set(_CATALOG_NAMES)  # nothing filtered
    assert body["count"] == len(_CATALOG_NAMES)


def test_master_token_can_name_lookup_never_tool(client):
    """The master path is unchanged: it may still resolve a NEVER tool by name."""
    r = client.get(f"/api/tools?name={NEVER_TOOL}", headers=_auth(MASTER))
    assert r.status_code == 200
    assert r.json()["name"] == NEVER_TOOL


# --- auth still rejected as before -------------------------------------------


def test_no_token_rejected(client):
    r = client.get("/api/tools")
    assert r.status_code == 401
    assert r.json()["failure_class"] == "auth"


def test_invalid_token_rejected(client):
    r = client.get("/api/tools", headers=_auth("Bearer-nonsense-not-a-real-token-value-x"))
    assert r.status_code == 403


def test_expired_session_token_rejected(client):
    """A dead session token cannot enumerate anything."""
    import sqlite3

    minted = client.post(
        "/api/admin/tokens/mint",
        json={"scope": ["read"], "ttl_hours": 12},
        headers=_auth(MASTER),
    ).json()
    with sqlite3.connect(st.DB_PATH) as conn:
        conn.execute(
            "UPDATE session_tokens SET expires_at = '2000-01-01T00:00:00+00:00' WHERE token_id = ?",
            (minted["token_id"],),
        )
    r = client.get("/api/tools", headers=_auth(minted["session_token"]))
    assert r.status_code == 403
    assert "expired" in r.json()["detail"].lower()
