"""Phase-2 acceptance tests for The Door That Asks (spec §14, tests 9-13).

The arrival gate: request → decide (POST-only, signed) → poll releases a
scoped token exactly once. ntfy is monkeypatched (delivery is best-effort by
design); the store is isolated to a tmp SQLite file.
"""

import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import arrival_gate as ag  # noqa: E402
import bridge  # noqa: E402
import session_tokens as st  # noqa: E402

MASTER = "test-master-token-0123456789abcdef-0123456789abcdef"
SECRET = "test-decide-secret"


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setattr(st, "DB_PATH", tmp_path / "session_tokens.db")
    monkeypatch.setattr(bridge, "BEARER_TOKEN", MASTER)
    monkeypatch.setenv("ARRIVAL_DECIDE_SECRET", SECRET)
    monkeypatch.setenv("ARRIVAL_GATE_ENABLED", "true")
    monkeypatch.delenv("NTFY_TOPIC", raising=False)

    async def no_ntfy(payload):
        return True

    monkeypatch.setattr(bridge, "_ntfy_publish", no_ntfy)

    recorded = []

    async def fake_tool(tool, args, seat=None):
        recorded.append((tool, args))
        return {"ok": True, "result": "recorded"}

    monkeypatch.setattr(bridge, "call_mcp_tool", fake_tool)
    c = TestClient(bridge.app)
    c.recorded = recorded
    return c


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def _request(client, **kw):
    r = client.post(
        "/api/arrival/request",
        json={"source_instance": "claude-test", "seat_description": "pytest seat", **kw},
    )
    assert r.status_code == 201, r.text
    return r.json()


def _signed(rid, action, exp=None):
    exp = exp or int(time.time()) + 600
    return {"rid": rid, "action": action, "exp": exp, "sig": ag.sign_decide(rid, action, exp)}


# 9. Full happy path: request → approve (POST) → token exactly once → consumed.
def test_happy_path_token_exactly_once(client):
    req = _request(client, requested_scope=["read", "write"])
    rid = req["arrival_request_id"]
    assert "-" in req["code"]  # two-word code (decision #5)

    r = client.post("/api/arrival/decide", params=_signed(rid, "approve"))
    assert r.status_code == 200

    poll = client.get(f"/api/arrival/poll/{rid}").json()
    assert poll["status"] == "approved"
    assert poll["session_token"].startswith("svs_")
    assert poll["scope"] == ["read", "write"]

    again = client.get(f"/api/arrival/poll/{rid}").json()
    assert again["status"] == "consumed"
    assert "session_token" not in again

    # The released token actually works, within scope.
    ok = client.post(
        "/api/call",
        json={"tool": "recall_insights", "arguments": {}},
        headers=_auth(poll["session_token"]),
    )
    assert ok.status_code == 200


# 10a. Deny path.
def test_deny_path(client):
    rid = _request(client)["arrival_request_id"]
    client.post("/api/arrival/decide", params=_signed(rid, "deny"))
    poll = client.get(f"/api/arrival/poll/{rid}").json()
    assert poll["status"] == "denied"
    assert poll["failure_class"] == "arrival_denied"


# 10b. Tampered / expired signatures rejected; GET never decides.
def test_signature_discipline_and_get_never_decides(client):
    rid = _request(client)["arrival_request_id"]
    bad = _signed(rid, "approve")
    bad["sig"] = "0" * 64
    assert client.post("/api/arrival/decide", params=bad).status_code == 403
    stale = _signed(rid, "approve", exp=int(time.time()) - 10)
    assert client.post("/api/arrival/decide", params=stale).status_code == 403

    # GET with a VALID signature renders the confirm page and changes nothing.
    good = _signed(rid, "approve")
    page = client.get("/api/arrival/decide", params=good)
    assert page.status_code == 200
    assert "form" in page.text and "cannot press this button" in page.text.lower().replace(
        "a preview fetcher cannot press this button. only you can.", "cannot press this button"
    ) or "<form" in page.text
    assert client.get(f"/api/arrival/poll/{rid}").json()["status"] == "pending"


# 10c. Global pending cap at 3.
def test_global_pending_cap(client):
    for i in range(3):
        _request(client, source_instance=f"seat-{i}")
    r = client.post(
        "/api/arrival/request",
        json={"source_instance": "seat-overflow", "seat_description": "x"},
    )
    assert r.status_code == 429
    assert r.json()["failure_class"] == "rate_limited"


# 10d. Duplicate suppression reuses the pending request.
def test_duplicate_suppression(client):
    first = _request(client)
    second = _request(client)
    assert second["arrival_request_id"] == first["arrival_request_id"]
    assert second.get("duplicate_of_recent_request") is True


# 11. Chronicle receipt written on grant, traceable shape.
def test_chronicle_receipt_on_grant(client):
    req = _request(client)
    rid = req["arrival_request_id"]
    client.post("/api/arrival/decide", params=_signed(rid, "approve"))
    poll = client.get(f"/api/arrival/poll/{rid}").json()
    writes = [(t, a) for t, a in client.recorded if t == "record_insight"]
    assert len(writes) == 1
    _, args = writes[0]
    assert poll["token_id"] in args["content"]
    assert req["code"] in args["content"]
    assert args["verified_by"][0]["kind"] == "human"


# 12. ntfy unreachable → request still approvable via HQ admin path.
def test_hq_admin_fallback(client, monkeypatch):
    async def ntfy_down(payload):
        return False

    monkeypatch.setattr(bridge, "_ntfy_publish", ntfy_down)
    req = _request(client, source_instance="fallback-seat")
    assert req["notification_sent"] is False
    r = client.post(
        "/api/arrival/approve",
        json={"arrival_request_id": req["arrival_request_id"]},
        headers=_auth(MASTER),
    )
    assert r.json()["outcome"] == "approved"
    poll = client.get(f"/api/arrival/poll/{req['arrival_request_id']}").json()
    assert poll["status"] == "approved" and poll["session_token"].startswith("svs_")


# 13. Gate disabled → all /api/arrival/* 404, /api/call unchanged.
def test_gate_disabled_flag(client, monkeypatch):
    monkeypatch.setenv("ARRIVAL_GATE_ENABLED", "false")
    assert client.post("/api/arrival/request", json={}).status_code == 404
    assert client.get("/api/arrival/poll/arq_x").status_code == 404
    r = client.post(
        "/api/call", json={"tool": "recall_insights", "arguments": {}}, headers=_auth(MASTER)
    )
    assert r.status_code == 200


# Fail-closed: no decide secret, no gate.
def test_gate_fail_closed_without_secret(client, monkeypatch):
    monkeypatch.delenv("ARRIVAL_DECIDE_SECRET", raising=False)
    assert client.post("/api/arrival/request", json={}).status_code == 404


# Decision single-use: second decide returns already_decided.
def test_decide_single_use(client):
    rid = _request(client)["arrival_request_id"]
    client.post("/api/arrival/decide", params=_signed(rid, "approve"))
    r2 = client.post("/api/arrival/decide", params=_signed(rid, "deny"))
    assert "Already decided" in r2.text
    assert client.get(f"/api/arrival/poll/{rid}").json()["status"] == "approved"


# XSS: attacker-controlled request fields must render escaped on the confirm
# page Anthony opens from his phone.
def test_confirm_page_escapes_user_input(client):
    req = _request(
        client,
        source_instance='<script>alert(1)</script>',
        seat_description='"><img src=x onerror=alert(2)>',
    )
    page = client.get(
        "/api/arrival/decide", params=_signed(req["arrival_request_id"], "approve")
    )
    assert page.status_code == 200
    # Dangerous forms must not survive as live markup…
    assert "<script>" not in page.text
    assert "<img" not in page.text
    # …but the payloads should be visible as escaped, inert text.
    assert "&lt;script&gt;" in page.text
    assert "&lt;img" in page.text


# Ungrantable scopes reduced at request time (spec §4.1 behaviour, unchanged).
# The reduction is no longer silent — what it now SAYS is asserted in
# test_a_non_grantable_scope_is_dropped_and_reported below; this test pins
# the unchanged behaviour it says it about.
def test_request_scope_clamped(client):
    req = _request(client, requested_scope=["read", "admin", "mint"])
    rid = req["arrival_request_id"]
    client.post("/api/arrival/decide", params=_signed(rid, "approve"))
    poll = client.get(f"/api/arrival/poll/{rid}").json()
    assert poll["scope"] == ["read"]


# ── The ask is parsed, or refused, never dropped (2026-09-07) ───────────────
#
# The defect these close, measured on main @ 357be83: `ArrivalRequest` declared
# `requested_scope` while the mint endpoint next door called the same concept
# `scope`, the ntfy line printed the bare word "scope", and /api/discover
# documented the flow without ever naming a body field. Pydantic ignores
# unknown fields, so a caller sending `{"scope": ["read","write"]}` got 201, a
# row holding ["read"], a tap that said "scope: read", and a read grant — with
# nothing on any surface telling it the ask had been discarded. An outside seat
# (Hermes desktop, grok-4.6) hit exactly that on 2026-09-06, twice, and could
# not tell why.


def _row_count():
    with ag._connect() as conn:
        return conn.execute("SELECT COUNT(*) c FROM arrival_requests").fetchone()["c"]


# A field nobody accepts is REFUSED, and the refusal names what IS accepted.
# `ttl_hours` and `seat` are in the list because they are the shapes a caller
# actually reaches for: `ttl_hours` is what the mint endpoint calls its own TTL
# field, `seat`/`label` are what the seat map calls a description.
@pytest.mark.parametrize("bad_field", ["requested_scopes", "ttl_hours", "seat", "label"])
def test_an_unknown_field_is_refused_and_the_422_names_the_accepted_names(client, bad_field):
    r = client.post(
        "/api/arrival/request",
        json={"source_instance": "claude-test", bad_field: ["read", "write"]},
    )
    assert r.status_code == 422, r.text
    assert bad_field in r.text
    # The message must name every accepted field — a refusal that does not say
    # what to send instead just moves the caller's confusion one step later.
    for name in bridge.ARRIVAL_REQUEST_FIELDS:
        assert name in r.text, f"422 did not name {name}: {r.text}"
    # …and nothing was created. A refused ask is not a pending request.
    assert _row_count() == 0


# The spelling the outside seat actually reached for is ACCEPTED.
def test_the_scope_alias_is_accepted_and_carried_all_the_way_to_the_token(client):
    req = _request(client, scope=["read", "write"])
    assert req["requested_scope"] == ["read", "write"]
    assert req["granted_scope"] == ["read", "write"]
    assert req["scope_note"] == "requested read+write, would grant read+write"

    rid = req["arrival_request_id"]
    client.post("/api/arrival/decide", params=_signed(rid, "approve"))
    poll = client.get(f"/api/arrival/poll/{rid}").json()
    assert poll["scope"] == ["read", "write"]
    # The poll response is the LAST thing the seat reads before it starts
    # working; it carries the ask too, or the seat is back where it started.
    assert poll["requested_scope"] == ["read", "write"]
    assert poll["scope_note"] == "requested read+write, would grant read+write"


# Both spellings, disagreeing → 422 naming both. Guessing which one the caller
# meant would be the same silent edit in a new costume.
def test_both_spellings_disagreeing_is_refused_naming_both(client):
    r = client.post(
        "/api/arrival/request",
        json={"requested_scope": ["read"], "scope": ["read", "write"]},
    )
    assert r.status_code == 422, r.text
    assert "requested_scope" in r.text and "scope" in r.text
    assert _row_count() == 0


# Both spellings AGREEING is not a conflict — it is a caller hedging, and the
# honest answer is to take it.
def test_both_spellings_agreeing_is_accepted(client):
    req = _request(client, requested_scope=["read", "write"], scope=["read", "write"])
    assert req["granted_scope"] == ["read", "write"]


# No scope at all still gets the documented read default — AND is told the ask
# was empty, because "asked for read" and "asked for nothing" are different
# events and collapsing them is how the original confusion starts.
def test_no_scope_gets_the_read_default_and_the_response_says_the_ask_was_empty(client):
    req = _request(client)
    assert req["requested_scope"] == []
    assert req["granted_scope"] == ["read"]
    assert req["scope_note"] == "requested nothing, default read"

    rid = req["arrival_request_id"]
    client.post("/api/arrival/decide", params=_signed(rid, "approve"))
    assert client.get(f"/api/arrival/poll/{rid}").json()["scope"] == ["read"]


# A scope that is not grantable at all is still dropped (behaviour unchanged) —
# and now the caller is told which ones, by name.
def test_a_non_grantable_scope_is_dropped_and_reported(client):
    req = _request(client, requested_scope=["read", "admin", "mint"])
    assert req["granted_scope"] == ["read"]
    assert req["dropped_scope"] == ["admin", "mint"]
    assert req["scope_note"] == (
        "requested read+admin+mint, would grant read "
        "(dropped, not grantable: admin+mint)"
    )


# The human taps on the truth: the phone push and the confirm page carry the
# ASK and the GRANT, from arrival_gate's one implementation.
def test_the_ntfy_push_and_the_confirm_page_show_the_ask_and_the_grant(client, monkeypatch):
    sent = []

    async def capture(payload):
        sent.append(payload)
        return True

    monkeypatch.setattr(bridge, "_ntfy_publish", capture)
    req = _request(client, scope=["read", "write"])

    assert sent, "no ntfy payload was built"
    assert "requested read+write, would grant read+write" in sent[0]["message"]
    # The bare word the old line printed must be gone: "scope: read" was the
    # string that told Anthony a thing that was true and not the whole truth.
    assert "scope: read" not in sent[0]["message"]

    page = client.get(
        "/api/arrival/decide", params=_signed(req["arrival_request_id"], "approve")
    )
    assert page.status_code == 200
    assert "requested read+write, would grant read+write" in page.text


# Duplicate suppression is the same fail-open one step over, and it bites the
# caller who spells the field CORRECTLY: the second ask is discarded whole.
# Which scope wins is a behaviour question above this change; being told is not.
def test_duplicate_suppression_says_when_the_second_ask_was_not_applied(client):
    first = _request(client, requested_scope=["read"])
    second = _request(client, requested_scope=["read", "write"])
    assert second["arrival_request_id"] == first["arrival_request_id"]
    assert second["ask_not_applied"] is True
    assert "NOT applied" in second["note"]
    assert second["granted_scope"] == ["read"]

    # An identical repeat is not a discarded ask, and must not claim to be.
    third = _request(client, requested_scope=["read"])
    assert third["arrival_request_id"] == first["arrival_request_id"]
    assert "ask_not_applied" not in third


# TTL is reduced by the same kind of quiet clamp. Reported in the response,
# where the caller is — NOT on the tap surfaces, which read the row, and the
# requested TTL is deliberately not persisted (the table is created with
# CREATE TABLE IF NOT EXISTS, so a new column would never reach an existing
# store without a migration this change does not make).
def test_the_ttl_clamp_is_reported_to_the_caller(client):
    req = _request(client, requested_ttl_hours=999)
    assert req["requested_ttl_hours"] == 999
    assert req["granted_ttl_hours"] == st.TTL_MAX_HOURS


# /api/discover documented the FLOW and never the BODY — which is why a caller
# guessing the field name was guessing at all.
def test_discover_documents_the_arrival_body_including_the_alias(client):
    doc = client.get("/api/discover").json()
    arrival = doc["endpoints"]["arrival_request"]
    assert arrival["path"] == "/api/arrival/request"
    assert arrival["auth"] is False
    for name in ("source_instance", "seat_description", "requested_scope", "requested_ttl_hours"):
        assert name in arrival["body"]
    assert "alias" in arrival["body"]["requested_scope"].lower()
    assert "422" in arrival["on_unknown_field"]


# ── Every caller measured before extra="forbid" went in (2026-09-07) ────────
#
# `extra="forbid"` can only break a caller that sends a field this model does
# not accept, so the bodies were enumerated first — this repo (tests, README,
# SECURITY.md, seat_identity's prose), the sovereign-stack repo, the
# temple-harness MCP shim, and `/api/discover` itself. Two live senders were
# found and both are pinned below. The harness shim reaches this endpoint at
# all: its `ALLOWED_BRIDGE_PATHS` is `{"/api/heartbeat"}` and every other call
# it makes routes through `POST /api/call`.
#
# ⚠ GREEN ON MAIN TOO, ON PURPOSE. This is a regression guard, not evidence for
# the fix — the thirteen tests above are that. Anything added here later must
# be a body some real caller actually sends.
KNOWN_CALLER_BODIES = {
    # sovereign-stack clients/claude_bridge/elevation.py::_door_request — the
    # claude.ai connector's step-up request, the one non-test sender in the house.
    "stack-elevation-step-up": {
        "source_instance": "claude-ai-bridge",
        "seat_description": "STEP-UP: 'record_insight' [summary] — claude.ai connector",
        "requested_scope": ["read"],
        "requested_ttl_hours": 1,
    },
    # README.md, "The Door That Asks": model line + one-line description.
    "readme-model-line-and-description": {
        "source_instance": "hermes-desktop — grok-4.6",
        "seat_description": "outside seat, needs to file one insight",
    },
    # The wholly empty body — what a seat sends when it is guessing.
    "empty-body": {},
}


@pytest.mark.parametrize("name", sorted(KNOWN_CALLER_BODIES))
def test_a_measured_caller_body_still_parses(client, name):
    r = client.post("/api/arrival/request", json=KNOWN_CALLER_BODIES[name])
    assert r.status_code == 201, f"{name} broke: {r.text}"


# describe_scope: "nobody measured the ask" is not "the ask was empty". None
# reaches it from `build_ntfy_message` whenever a caller omits the key, and
# answering "requested nothing" to that would invent a fact on the one screen
# where consent is given.
def test_describe_scope_distinguishes_an_unmeasured_ask_from_an_empty_one():
    assert ag.describe_scope([], ["read"]) == "requested nothing, default read"
    assert ag.describe_scope(None, ["read", "write"]) == (
        "would grant read+write (ask not recorded)"
    )


# ⚠ THE GATE DECIDES BEFORE THE BODY IS PARSED, AND A REFUSAL MESSAGE IS NOT AN
# ORACLE. arrival_gate.py's header states the invariant in its own words: "All
# routes 404 when the gate is disabled or the decide secret is missing
# (fail-closed)." FastAPI validates a declared body model BEFORE the handler
# runs, so a malformed body was answered by the validator instead of the gate.
#
# RED ON MAIN FOR ONE OF THESE THREE, AND SAY WHICH: with the gate off, main
# returned 404 for the unknown field and for the disagreeing spellings (it
# ignored both) and 422 NAMING THE FIELD for the wrong type. The extra="forbid"
# added in this same change would have widened that to all three — an
# unauthenticated route-existence oracle shipped by the commit that closed the
# fail-open. Both halves close here.
@pytest.mark.parametrize(
    "body",
    [
        {"requested_scopes": ["read"]},          # unknown field
        {"requested_scope": "read"},             # wrong type — RED ON MAIN
        {"requested_scope": ["read"], "scope": ["read", "write"]},  # both, differing
    ],
    ids=["unknown-field", "wrong-type", "both-spellings-differ"],
)
def test_a_disabled_gate_answers_a_malformed_body_with_404_not_a_field_list(
    client, monkeypatch, body
):
    monkeypatch.setenv("ARRIVAL_GATE_ENABLED", "false")
    r = client.post("/api/arrival/request", json=body)
    assert r.status_code == 404, r.text
    # And the 404 says nothing about the shape of a route that is switched off.
    assert "requested_scope" not in r.text
    assert "arrival" not in r.text.lower()


# The same refusal with the gate ON still names what to send instead — the fix
# above must not have turned an honest 422 into a mute one.
def test_with_the_gate_on_the_refusal_still_names_the_accepted_fields(client):
    r = client.post("/api/arrival/request", json={"requested_scopes": ["read"]})
    assert r.status_code == 422
    for name in bridge.ARRIVAL_REQUEST_FIELDS:
        assert name in r.text
    assert r.json()["failure_class"] == "malformed"


# A body that is not an object at all is refused the same way, not 500.
def test_a_non_object_body_is_refused_with_the_accepted_fields(client):
    r = client.post("/api/arrival/request", json=["read"])
    assert r.status_code == 422, r.text
    assert "source_instance" in r.text
    assert r.json()["failure_class"] == "malformed"


# ⚠ THE DOC AND THE VALIDATOR READ ONE CONSTANT — MEASURED, NOT ASSERTED IN
# PROSE. This branch's first draft claimed a single source in its PR body while
# `discover()` held a private literal a thousand lines from the model, and the
# two had already drifted: the literal documented four fields, the validator
# accepted five, and the missing one was `scope` — the alias the doc exists to
# teach. Caught by second-seat review (Grok, 2026-09-07), red on 0eb36d3.
def test_discover_renders_the_arrival_body_from_the_one_constant(client):
    body = client.get("/api/discover").json()["endpoints"]["arrival_request"]["body"]
    # Names AND order, so a field added to the validator cannot be missing here.
    assert tuple(body) == bridge.ARRIVAL_REQUEST_FIELDS
    # And the text is the same object's text, not a paraphrase of it.
    assert body == dict(bridge.ARRIVAL_REQUEST_FIELD_DOCS)


# The alias must be documented as a FIELD NAME a caller can send, not only
# mentioned in another field's prose — that mention is what the four-key literal
# had, and it is why nobody noticed `scope` was missing from the doc.
def test_discover_lists_the_alias_as_a_field_in_its_own_right(client):
    body = client.get("/api/discover").json()["endpoints"]["arrival_request"]["body"]
    assert "scope" in body
    assert "alias" in body["scope"].lower()
