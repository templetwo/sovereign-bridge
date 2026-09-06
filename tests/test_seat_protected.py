"""Protected material never reaches a seat — HQ decision D4, review finding F1.

THE FINDING, in the reviewer's own construction: the seat gate refused
`open_protected_record` BY NAME, and `inspect_claim`, `recall_insights` and
`archive_exchange` returned a designated record's body or its archived STAKES
through the real bridge route, HTTP 200. Anthony reserves his children and
protected family material to himself (`pol_20260831`), so this is P1, and
"the drawer's dedicated tool is denied" was never the guarantee it looked like:
the drawer is a DESIGNATION, not a door, and every read that can address a
claim by id is another way in.

⚠ EVERY FIXTURE HERE IS SYNTHETIC AND EVERY ROOT IS A tmp_path. Nothing in this
file reads, names, derives from, or asserts about Anthony's four real
designated records. That is not politeness — a test that had to open the
protected drawer to prove the drawer is shut would be the leak it was written
to prevent. The designation index is a ledger of IDS, so a synthetic id is a
complete fixture.

TWO MECHANISMS, TESTED SEPARATELY BECAUSE THEY FAIL DIFFERENTLY:
  (i)  ADDRESSED BY ID  -> the CALL is refused (nothing to filter).
  (ii) RETURNED IN A LIST -> the RESPONSE is filtered and the subtraction is
       stated as `withheld_protected`.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import bridge  # noqa: E402
import seat_identity as si  # noqa: E402
import seat_socket as ss  # noqa: E402
import session_tokens as st  # noqa: E402

MASTER = "test-master-token-0123456789abcdef-0123456789abcdef"
SEAT = "grok-build-studio"

# A synthetic protected record. Invented here, designated here, read here.
SECRET = {
    "timestamp": "2026-01-01T00:00:00Z",
    "domain": "synthetic,protected,fixture",
    # Long enough that HALF of it still exceeds the 40-character window, so the
    # split-across-a-boundary test below is measuring the rule and not the
    # fixture. Real chronicle bodies are paragraphs; a 76-character one was
    # making the test assert something the rule never promised.
    "content": (
        "SYNTHETIC FIXTURE CONTENT — invented for this test and designated in "
        "this test, written long enough that either half of it still exceeds "
        "the forty-character window the redactor searches for."
    ),
}
ORDINARY = {
    "timestamp": "2026-01-02T00:00:00Z",
    "domain": "synthetic,ordinary,fixture",
    "content": "an ordinary synthetic entry that must survive the filter",
}


def claim_id(entry):
    preimage = "\x1f".join(entry.get(f, "") for f in ("timestamp", "domain", "content"))
    return hashlib.sha256(preimage.encode("utf-8")).hexdigest()


SECRET_ID = claim_id(SECRET)
STAKES_ARCHIVE_ID = "a" * 64


class StampPeer:
    def __init__(self, app, verified):
        self.app, self.verified = app, verified

    async def __call__(self, scope, receive, send):
        if scope.get("type") == "http" and self.verified is not None:
            ext = dict(scope.get("extensions") or {})
            ext[ss.SEAT_PEER_EXT] = self.verified
            scope = {**scope, "extensions": ext}
        await self.app(scope, receive, send)


def _peer():
    return {"ok": True, "pid": os.getpid(), "uid": os.getuid(), "seat": SEAT}


@pytest.fixture
def seated(monkeypatch, tmp_path):
    """A registered seat under a tmp SOVEREIGN_ROOT, with a designation index.

    Returns a writer for the index so a test can corrupt or empty it. NOTHING
    here touches ~/.sovereign.
    """
    monkeypatch.setenv("SOVEREIGN_ROOT", str(tmp_path))
    monkeypatch.setenv("SOVEREIGN_CHRONICLE", str(tmp_path / "chronicle"))
    monkeypatch.setattr(st, "DB_PATH", tmp_path / "session_tokens.db")
    monkeypatch.setattr(bridge, "BEARER_TOKEN", MASTER)
    reg = tmp_path / "hq" / "seats" / "registry.json"
    reg.parent.mkdir(parents=True)
    reg.write_text(json.dumps({"seats": {SEAT: {"kind": "seated", "enabled": True}}}))
    index = tmp_path / "chronicle" / "protected.jsonl"
    index.parent.mkdir(parents=True)

    # ⚠ THE DESIGNATED RECORDS EXIST ON DISK, because since review N1 a
    # designation the bridge cannot RESOLVE TO A BODY refuses every
    # text-producing read: it cannot remove from prose what it cannot find, and
    # "I looked and found nothing" is not the same fact as "there is nothing".
    # A fixture that designated an id with no entry behind it would be testing
    # a state the guard is built to reject.
    shard = tmp_path / "chronicle" / "insights" / "synthetic-fixture"
    shard.mkdir(parents=True)
    (shard / "entries.jsonl").write_text(
        json.dumps(SECRET) + "\n" + json.dumps(ORDINARY) + "\n"
    )

    def write(text):
        index.write_text(text)

    write(
        json.dumps(
            {
                "action": "protect",
                "timestamp": "2026-01-01T00:00:01Z",
                "claim_id": SECRET_ID,
                "stakes_archive_id": STAKES_ARCHIVE_ID,
                "subject": "synthetic",
                "emotion": "invented",
                "designated_by": "test-fixture",
            }
        )
        + "\n"
    )
    write.path = index
    return write


@pytest.fixture
def upstream(monkeypatch):
    """The stack, faked. `result` is what the next call returns."""
    box = {"result": {"ok": True, "result": None}}
    seen = []

    async def fake(tool, args, seat=None):
        seen.append((tool, args))
        return json.loads(json.dumps(box["result"]))

    monkeypatch.setattr(bridge, "call_mcp_tool", fake)
    box["seen"] = seen
    return box


def seat_client():
    return TestClient(StampPeer(bridge.app, _peer()), client=("127.0.0.1", 51234))


def call(tool, **args):
    return seat_client().post(
        "/api/call",
        json={"tool": tool, "arguments": args},
        headers={"X-Sovereign-Seat": SEAT},
    )


def bearer_call(tool, **args):
    return TestClient(bridge.app).post(
        "/api/call",
        json={"tool": tool, "arguments": args},
        headers={"Authorization": f"Bearer {MASTER}"},
    )


# ── (i) Addressed by id: the CALL is refused ────────────────────────────────


def test_inspect_claim_on_a_designated_record_is_refused(seated, upstream):
    r = call("inspect_claim", claim_id=SECRET_ID)
    assert r.status_code == 403, r.text
    assert "reserved to him" in r.json()["detail"]
    assert upstream["seen"] == [], "the call reached the stack before being refused"


def test_a_PREFIX_of_a_designated_id_is_refused_too(seated, upstream):
    """⚠ THE BYPASS AN EXACT-MATCH CHECK WOULD LEAVE OPEN.

    `inspect_claim` resolves "full 64-hex OR a unique prefix" and `load_stakes`
    resolves an archive id the same way. A guard that compared only whole
    strings would be walked past by a caller who typed twelve characters — the
    same finding again, one release later. Both directions are refused: a
    prefix of a designation, and a designation that is a prefix of what was
    asked for.
    """
    for candidate in (SECRET_ID[:12], SECRET_ID[:8].upper(), SECRET_ID + "extra"):
        r = call("inspect_claim", claim_id=candidate)
        assert r.status_code == 403, f"{candidate!r} was accepted"
    assert upstream["seen"] == []


def test_archive_exchange_cannot_fetch_the_coupled_stakes(seated, upstream):
    """The stakes prose lives in the archive layer and the designation index
    holds the POINTER. Refusing only claim ids would leave the archived stakes
    — the human's lived experience, the very thing the coupling protects —
    reachable by its own id."""
    r = call("archive_exchange", mode="get", archive_id=STAKES_ARCHIVE_ID)
    assert r.status_code == 403, r.text
    r = call("archive_exchange", mode="get", archive_id=STAKES_ARCHIVE_ID[:10])
    assert r.status_code == 403, r.text
    assert upstream["seen"] == []


def test_an_undesignated_id_still_works(seated, upstream):
    """FAIL-CLOSED IS NOT FAIL-USELESS. The overwhelming majority of claims are
    not designated, and `inspect_claim` is a seat's ordinary forensic tool."""
    upstream["result"] = {"ok": True, "result": {"claim_id": claim_id(ORDINARY), "found": True}}
    r = call("inspect_claim", claim_id=claim_id(ORDINARY))
    assert r.status_code == 200, r.text
    assert [t for t, _ in upstream["seen"]] == ["inspect_claim"]


def test_the_bearer_path_is_unchanged(seated, upstream):
    """Master is master. This is a SEAT boundary, not a new restriction on
    Anthony's own token — and pretending otherwise would be a bridge quietly
    deciding what the operator may read on his own machine."""
    upstream["result"] = {"ok": True, "result": dict(SECRET)}
    r = bearer_call("inspect_claim", claim_id=SECRET_ID)
    assert r.status_code == 200, r.text
    assert r.json()["result"]["content"] == SECRET["content"]
    assert "withheld_protected" not in r.json(), (
        "the master path must not even carry the seat filter's bookkeeping"
    )


# ── (ii) Returned in a list: the RESPONSE is filtered, visibly ──────────────


@pytest.mark.parametrize(
    "tool", ["recall_insights", "season_review", "thread_get_touches", "the_ground"]
)
def test_a_designated_entry_is_dropped_from_every_read(seated, upstream, tool):
    """The lane names three readers "and any other read that returns entries by
    claim id". An ENUMERATED list of readers is the fail-open F1 already
    demonstrated once — the guard names the doors somebody thought of, and the
    set of doors is open — so the filter walks EVERY seat response. `the_ground`
    is in this list precisely because nobody named it.
    """
    upstream["result"] = {
        "ok": True,
        "result": {
            "items": [dict(ORDINARY), dict(SECRET, claim_id=SECRET_ID)],
            "returned": 2,
            "total_matched": 2,
        },
    }
    body = call(tool, query="x").json()
    items = body["result"]["items"]
    assert len(items) == 1, f"{tool} returned a designated record"
    assert items[0]["content"] == ORDINARY["content"]
    assert body["withheld_protected"] == 1


def test_the_filter_finds_it_with_no_claim_id_on_the_entry(seated, upstream):
    """`recall_insights(with_ids=false)` returns entries with no id at all, so a
    filter that only read a declared `claim_id` would pass the record straight
    through. The id is DERIVED from the entry as a second, independent signal.
    """
    upstream["result"] = {"ok": True, "result": {"items": [dict(SECRET)]}}
    body = call("recall_insights", with_ids=False).json()
    assert body["result"]["items"] == []
    assert body["withheld_protected"] == 1


def test_the_filter_believes_the_stacks_own_marker(seated, upstream):
    """The third signal. When the stack's read chokepoint has ALREADY marked an
    entry (`_protected` / `_stakes` / `_stakes_withheld`), the bridge withholds
    on that alone — no id needed, no derivation needed.

    Three ORed signals rather than one because each is absent in a different
    world: the marker when the chokepoint did not run, the declared id when the
    caller passed with_ids=false, and the derived id if the upstream preimage
    ever changes. A filter resting on the derivation alone would match nothing,
    silently, the day that happened — a fail-open inside the fix for a
    fail-open.
    """
    unrelated = {"timestamp": "x", "domain": "y", "content": "z", "_stakes": "coupled prose"}
    upstream["result"] = {"ok": True, "result": {"items": [unrelated]}}
    body = call("recall_insights").json()
    assert body["result"]["items"] == []
    assert body["withheld_protected"] == 1


def test_withheld_protected_is_stated_even_when_zero(seated, upstream):
    """SOP #2. "the filter ran and removed nothing" and "the filter did not
    run" are different facts, and an absent field collapses them."""
    upstream["result"] = {"ok": True, "result": {"items": [dict(ORDINARY)]}}
    body = call("recall_insights").json()
    assert body["withheld_protected"] == 0
    assert len(body["result"]["items"]) == 1


def test_a_designated_record_returned_bare_is_replaced_wholesale(seated, upstream):
    """Some payloads ARE the record rather than containing a list of them. A
    walk that only filtered list members would hand that one back intact."""
    upstream["result"] = {"ok": True, "result": dict(SECRET, claim_id=SECRET_ID)}
    body = call("recall_insights").json()
    assert body["result"] == {
        "withheld": "protected",
        "note": (
            "This record is designated protected and is not returned to seat identity."
        ),
    }
    assert body["withheld_protected"] == 1


def test_the_filtered_result_is_what_gets_CACHED(seated, upstream):
    """⚠ ORDER MATTERS AND THIS IS THE PROOF. Filtering the return value while
    caching the raw one would put protected content in the idempotency store,
    where the next replay serves it straight back around the guard.
    """
    upstream["result"] = {
        "ok": True,
        "result": {"items": [dict(ORDINARY), dict(SECRET, claim_id=SECRET_ID)]},
    }
    c = seat_client()
    body = {
        "tool": "recall_insights",
        "arguments": {"query": "x"},
        "idempotency_key": "k-1",
    }
    hdr = {"X-Sovereign-Seat": SEAT}
    first = c.post("/api/call", json=body, headers=hdr).json()
    assert first["withheld_protected"] == 1
    replay = c.post("/api/call", json=body, headers=hdr).json()
    assert replay.get("idempotent_replay") is True
    assert len(replay["result"]["items"]) == 1, "the CACHE served the protected record"
    assert replay["result"]["items"][0]["content"] == ORDINARY["content"]
    assert len(upstream["seen"]) == 1, "the replay was not a replay"


def test_a_DESIGNATION_MADE_AFTER_THE_CACHE_WRITE_still_binds_the_replay(
    seated, upstream
):
    """⚠ THE CACHE MUST NOT OUTLIVE A DESIGNATION.

    Filtering before the cache write (the test above) protects records that
    were designated when the entry was written. It does nothing for a record
    designated AFTER — and the idempotency TTL is 24 hours. Anthony designates
    a record; a seat that read it an hour ago with an idempotency key would go
    on being served it all day, through the one route that never reads the
    index. Fresh-per-request (below) is the promise; this is the route that
    would have quietly excepted itself from it.
    """
    upstream["result"] = {
        "ok": True,
        "result": {"items": [dict(ORDINARY), dict(SECRET, claim_id=SECRET_ID)]},
    }
    c = seat_client()
    body = {
        "tool": "recall_insights",
        "arguments": {"query": "x"},
        "idempotency_key": "k-late",
    }
    hdr = {"X-Sovereign-Seat": SEAT}
    first = c.post("/api/call", json=body, headers=hdr).json()
    assert first["withheld_protected"] == 1
    assert len(first["result"]["items"]) == 1

    # Anthony designates the OTHER record, after the cache entry exists.
    seated(
        json.dumps(
            {
                "action": "protect",
                "claim_id": SECRET_ID,
                "stakes_archive_id": STAKES_ARCHIVE_ID,
                "designated_by": "t",
            }
        )
        + "\n"
        + json.dumps(
            {
                "action": "protect",
                "claim_id": claim_id(ORDINARY),
                "stakes_archive_id": "c" * 64,
                "designated_by": "t",
            }
        )
        + "\n"
    )

    replay = c.post("/api/call", json=body, headers=hdr).json()
    assert replay.get("idempotent_replay") is True, "not a replay; the test proves nothing"
    assert len(upstream["seen"]) == 1, "the replay was not a replay"
    assert replay["result"]["items"] == [], (
        "the idempotency cache served a record designated after it was written"
    )
    assert replay["withheld_protected"] == 1


def test_an_error_envelope_does_not_grow_a_null_result_on_the_seat_path(
    seated, upstream
):
    """The filter REPLACES a result; it must not INVENT one. A failed call
    carries {ok, error, failure_class} and no `result` key on every other auth
    path — stamping a null one here would make the seat path's failures a
    different shape than everyone else's, which is a contract change nobody
    asked for and no consumer would learn about until it broke.
    """
    upstream["result"] = {"ok": False, "error": "upstream said no", "failure_class": "tool"}
    body = call("recall_insights", query="x").json()
    assert body["ok"] is False
    assert "result" not in body, "the seat path invented a null result on an error"
    assert body["withheld_protected"] == 0, "the filter must still say it ran"


# ── (iii) TEXT-PRODUCING READS: the filter above cannot see them (N1) ───────


def test_context_retrieve_no_longer_hands_a_seat_the_rendered_body(seated, upstream):
    """⚠ ASTRA'S N1 REPRODUCTION, THE RELEASE-BLOCKING ONE.

    The real `context_retrieve` handler reads a designated entry, formats the
    first 150 characters of its content into a SENTENCE, and discards the claim
    id and every protection marker with it. The structural filter walks the
    response looking for entry objects, finds a string, and returns it
    unchanged: 200, ok:true, the designated body on the wire, and
    `withheld_protected: 0`.

    A guard that matches on IDENTITY fails the moment something upstream
    renders the content and throws the identity away.
    """
    excerpt = SECRET["content"][:150]
    upstream["result"] = {
        "ok": True,
        "result": f"Relevant context found:\n  - [2026-01-01] {excerpt}...",
    }
    body = call("context_retrieve", query="anything").json()
    assert body["ok"] is True
    assert SECRET["content"] not in body["result"]
    assert excerpt not in body["result"]
    assert si.WITHHELD_MARK in body["result"]
    assert body["withheld_protected"] == 1
    # the surrounding prose survives: this is redaction, not refusal
    assert "Relevant context found" in body["result"]


def test_a_body_split_across_a_formatting_boundary_is_still_caught(seated, upstream):
    """The 40-character window rule, which is why the fix does not need to
    understand any tool's formatting. A body reflowed across a line break, or
    truncated mid-word with an ellipsis, still puts a long run of itself on the
    wire — and a long run is what is searched for."""
    body_text = SECRET["content"]
    half = len(body_text) // 2
    upstream["result"] = {
        "ok": True,
        "result": {
            "lines": [
                "  · " + body_text[:half],
                "    " + body_text[half:] + " …",
            ]
        },
    }
    out = call("season_review").json()
    rendered = json.dumps(out["result"])
    assert body_text[:half] not in rendered
    assert body_text[half:] not in rendered
    assert si.WITHHELD_MARK in rendered
    assert out["withheld_protected"] >= 1


def test_a_fragment_SHORTER_than_the_window_is_NOT_caught_and_that_is_the_bound(
    seated, upstream
):
    """⚠ THE LIMIT OF THE RULE, WRITTEN DOWN RATHER THAN DISCOVERED LATER.

    HQ specified "any 40-character-or-longer substring". Below that window the
    redactor does not match, and it must not: 20 characters of ordinary English
    collide with ordinary English, and a guard that redacted every such run
    would return responses with the meaning taken out of them.

    So a formatter that emitted a designated body in pieces shorter than the
    window would defeat this. No such formatter is known — the reproduction
    renders 150 characters — and the whole-body rule below covers the short
    ones. It is a real residual and it is stated, not claimed closed.
    """
    fragment = SECRET["content"][:25]
    upstream["result"] = {"ok": True, "result": f"a snippet: {fragment}"}
    out = call("start_here").json()
    assert fragment in out["result"], (
        "the window is narrower than this fixture assumes — re-derive the bound"
    )
    assert out["withheld_protected"] == 0
    assert len(fragment) < si.PROTECTED_BODY_GRAM


def test_a_short_whole_body_is_caught_by_the_containment_rule(seated, upstream, tmp_path):
    """The other half of the pair. A body too short for the window rule is
    still matched WHOLE, which is what catches a formatter that printed a brief
    record in full."""
    short = {
        "timestamp": "2026-04-04T00:00:00Z",
        "domain": "synthetic,short",
        "content": "a brief designated note",  # 23 chars: under the window
    }
    shard = tmp_path / "chronicle" / "insights" / "synthetic-fixture" / "entries.jsonl"
    shard.write_text(
        json.dumps(SECRET) + "\n" + json.dumps(ORDINARY) + "\n" + json.dumps(short) + "\n"
    )
    seated(
        json.dumps({"action": "protect", "claim_id": SECRET_ID,
                    "stakes_archive_id": STAKES_ARCHIVE_ID, "designated_by": "t"}) + "\n"
        + json.dumps({"action": "protect", "claim_id": claim_id(short),
                      "stakes_archive_id": "e" * 64, "designated_by": "t"}) + "\n"
    )
    upstream["result"] = {"ok": True, "result": f"the note said: {short['content']}."}
    out = call("start_here").json()
    assert short["content"] not in out["result"]
    assert si.WITHHELD_MARK in out["result"]
    assert out["withheld_protected"] == 1


def test_an_ordinary_body_is_not_touched(seated, upstream):
    """Over-redaction is the safe direction and still has a floor: text that is
    not a designated body must come back whole, or the guard is just an outage
    with a nice name."""
    upstream["result"] = {"ok": True, "result": "here is " + ORDINARY["content"]}
    out = call("start_here").json()
    assert out["result"] == "here is " + ORDINARY["content"]
    assert out["withheld_protected"] == 0


def test_a_designated_body_that_cannot_be_located_refuses_the_text_read(
    seated, upstream, tmp_path
):
    """FAIL CLOSED ON THE LOOKUP. If a designated id does not resolve to a body,
    either the record is gone or this scan cannot see where it lives — and the
    bridge cannot tell those apart. Reporting "nothing to withhold" about a
    record it merely failed to reach is the read-side fail-open in its purest
    form, so it refuses and names the id."""
    (tmp_path / "chronicle" / "insights" / "synthetic-fixture" / "entries.jsonl").write_text(
        json.dumps(ORDINARY) + "\n"
    )
    r = call("context_retrieve", query="x")
    assert r.status_code == 403
    detail = r.json()["detail"]
    assert "cannot be located" in detail
    assert SECRET_ID[:12] in detail
    assert not upstream["seen"], "a text read dispatched before it could be certified"


def test_an_unlocatable_body_does_not_take_the_structured_surface_down(
    seated, upstream, tmp_path
):
    """The refusal is scoped to the reads that RENDER. A write, or a status
    call, cannot carry another record's body, so it must not be collateral."""
    (tmp_path / "chronicle" / "insights" / "synthetic-fixture" / "entries.jsonl").write_text(
        json.dumps(ORDINARY) + "\n"
    )
    assert call("context_retrieve", query="x").status_code == 403
    assert call("heartbeat").status_code == 200
    assert call("record_insight", content="x", domain="d").status_code == 200


def test_a_short_designated_body_refuses_rather_than_redacting_the_language(
    seated, upstream
):
    """A body of a handful of characters cannot be searched for without
    redacting ordinary words. Ignoring it would leak; redacting it would
    destroy every response. Refusing is the only honest third answer, and it
    names the length."""
    tiny = {"timestamp": "2026-03-03T00:00:00Z", "domain": "synthetic,tiny", "content": "ab"}
    (Path(os.environ["SOVEREIGN_CHRONICLE"]) / "insights" / "synthetic-fixture" / "entries.jsonl").write_text(
        json.dumps(SECRET) + "\n" + json.dumps(ORDINARY) + "\n" + json.dumps(tiny) + "\n"
    )
    seated(
        json.dumps({"action": "protect", "claim_id": claim_id(tiny),
                    "stakes_archive_id": "d" * 64, "designated_by": "t"}) + "\n"
    )
    r = call("context_retrieve", query="x")
    assert r.status_code == 403
    assert "below the" in r.json()["detail"]


def test_a_text_response_the_walker_cannot_read_is_refused(seated, monkeypatch):
    """(c) A payload carrying a node this walker cannot vouch for is withheld
    WHOLE. "I could not check it" must never render as "here it is"."""

    class _Opaque:
        pass

    async def fake(tool, args, seat=None):
        return {"ok": True, "result": {"weird": _Opaque()}}

    monkeypatch.setattr(bridge, "call_mcp_tool", fake)
    r = call("context_retrieve", query="x")
    assert r.status_code == 403
    assert "withheld whole" in r.json()["detail"]


def test_the_structural_filter_still_runs_on_a_text_tool(seated, upstream):
    """A read can return BOTH prose and entries, so a TEXT tool gets the entry
    filter AND the redaction. The class is the WORSE case, not the only case."""
    upstream["result"] = {
        "ok": True,
        "result": {"items": [dict(ORDINARY), dict(SECRET, claim_id=SECRET_ID)]},
    }
    out = call("recall_insights").json()
    assert len(out["result"]["items"]) == 1
    assert out["withheld_protected"] == 1


def test_the_classification_covers_the_published_surface_exactly(surface):
    """(a) EVERY published tool is in EXACTLY ONE class. A tool missing from the
    table would otherwise pick its own containment class by being absent."""
    published = set(surface.published) | set(surface.retired)
    classified = set(si.TOOL_CLASSES)
    assert set(surface.published) - classified == set(), "published but unclassified"
    assert classified - published == set(), "classified but not a stack tool"
    assert set(si.TOOL_CLASSES.values()) == {si.TOOL_CLASS_TEXT, si.TOOL_CLASS_STRUCTURED}
    for name in surface.published:
        assert si.tool_class(name) in (si.TOOL_CLASS_TEXT, si.TOOL_CLASS_STRUCTURED), name


def test_every_tool_the_lane_named_is_TEXT():
    """The eight the review named by hand, pinned so a future edit cannot
    quietly demote one to STRUCTURED."""
    for name in (
        "context_retrieve", "where_did_i_leave_off", "arrive", "arrive_lineage",
        "season_review", "get_inheritable_context", "start_here", "reflexive_surface",
    ):
        assert si.tool_class(name) == si.TOOL_CLASS_TEXT, name


def test_a_published_tool_nobody_classified_is_refused(seated, upstream, monkeypatch):
    """FAIL CLOSED ON A TOOL THE STACK ADDS TOMORROW. Default-to-structured
    would let a new rendering read through on its first day; default-to-text
    would hide that nobody looked. Refusing says so out loud."""
    monkeypatch.setitem(si.TOOL_CLASSES, "recall_insights", si.TOOL_CLASS_TEXT)
    monkeypatch.delitem(si.TOOL_CLASSES, "the_ground")
    r = call("the_ground")
    assert r.status_code == 403
    assert "not classified as structured or text-producing" in r.json()["detail"]
    assert not upstream["seen"]


# ── The index itself ────────────────────────────────────────────────────────


def test_an_unreadable_index_refuses_rather_than_passes(seated, upstream):
    """FAIL CLOSED. A designation the bridge cannot parse is a record it would
    otherwise hand to a seat, so an index with one bad line makes the WHOLE
    index unusable.

    ⚠ THIS IS DELIBERATELY STRICTER THAN THE STACK'S OWN READER, which SKIPS
    corrupt lines "matching the chronicle read convention". That is right for a
    reader assembling a view and wrong for a guard: a skipped line is a
    designation nobody enforced.
    """
    seated('{"action":"protect","claim_id":"' + SECRET_ID + '"}\n{not json at all\n')
    for tool, args in (
        ("inspect_claim", {"claim_id": "0" * 64}),
        ("recall_insights", {"query": "x"}),
        ("archive_exchange", {"mode": "get", "archive_id": "c" * 64}),
        # ...and a WRITE, because refusing only reads would leave a write
        # dispatched-then-403'd: the record lands and the caller is told no.
        ("record_insight", {"content": "c", "domain": "d"}),
    ):
        r = call(tool, **args)
        assert r.status_code == 403, f"{tool} was served from an unreadable index"
        assert "could not be read" in r.json()["detail"], tool
    assert upstream["seen"] == [], "a call reached the stack before being refused"


def test_an_absent_index_is_a_machine_with_nothing_designated(seated, upstream, tmp_path):
    """ABSENT IS NOT UNREADABLE, and conflating them would break every fresh
    checkout. A file that is not there is a real, common, correct state."""
    (tmp_path / "chronicle" / "protected.jsonl").unlink()
    upstream["result"] = {"ok": True, "result": {"items": [dict(ORDINARY)]}}
    r = call("recall_insights", query="x")
    assert r.status_code == 200, r.text
    assert r.json()["withheld_protected"] == 0


def test_unprotect_restores_the_record(seated, upstream):
    """The ledger is append-only and `unprotect` nullifies — the same fold rule
    `sovereign_stack.protected.fold_protected` applies. Two implementations of
    one fold that disagreed about which records are live designations would be
    worse than one."""
    seated(
        json.dumps(
            {
                "action": "protect",
                "claim_id": SECRET_ID,
                "stakes_archive_id": STAKES_ARCHIVE_ID,
                "designated_by": "t",
            }
        )
        + "\n"
        + json.dumps({"action": "unprotect", "claim_id": SECRET_ID}) + "\n"
    )
    upstream["result"] = {"ok": True, "result": {"items": [dict(SECRET)]}}
    body = call("recall_insights").json()
    assert body["withheld_protected"] == 0
    assert len(body["result"]["items"]) == 1


def test_the_index_is_read_fresh_on_every_request(seated, upstream):
    """Designating a record must take effect NOW, not after a cache window or a
    restart. The registry is read fresh for the same reason."""
    upstream["result"] = {"ok": True, "result": {"items": [dict(ORDINARY)]}}
    assert call("recall_insights").json()["withheld_protected"] == 0
    seated(
        json.dumps(
            {
                "action": "protect",
                "claim_id": claim_id(ORDINARY),
                "stakes_archive_id": "b" * 64,
                "designated_by": "t",
            }
        )
        + "\n"
    )
    assert call("recall_insights").json()["withheld_protected"] == 1


def test_the_derivation_matches_the_stacks_own(seated):
    """⚠ THE DRIFT ALARM FOR THE COPIED PREIMAGE.

    `si.derive_claim_id` reimplements sha256(timestamp \\x1f domain \\x1f
    content) from `sovereign_stack.provenance`. If upstream ever changes that
    preimage, the derived-id signal would match NOTHING — silently — and this
    test is what turns that into a red line instead of a leak.

    Subprocess, because this pytest process has `sovereign_stack` bound to the
    LIVE tree already; skips loudly when no stack source is on disk.
    """
    import subprocess

    trees = [
        Path.home() / ".cache" / "wt-release-stack" / "src",
        Path.home() / "sovereign-stack" / "src",
    ]
    tree = next((p for p in trees if (p / "sovereign_stack" / "provenance.py").exists()), None)
    if tree is None:
        pytest.skip("no sovereign-stack source on disk; the derivation cannot be cross-checked")
    code = (
        "import json, sys\n"
        "from sovereign_stack import provenance\n"
        "entry = json.loads(sys.argv[1])\n"
        "print(provenance.derive_claim_id(entry))"
    )
    out = subprocess.run(
        [sys.executable, "-c", code, json.dumps(SECRET)],
        capture_output=True,
        text=True,
        env=dict(os.environ, PYTHONPATH=str(tree), PYTHONDONTWRITEBYTECODE="1"),
        timeout=120,
    )
    assert out.returncode == 0, out.stderr
    upstream_id = out.stdout.strip()
    assert si.derive_claim_id(SECRET) == upstream_id, (
        "the bridge's claim-id preimage has drifted from the stack's. The "
        "derived-id signal in the protected filter now matches nothing — "
        f"bridge {si.derive_claim_id(SECRET)} vs stack {upstream_id} ({tree})"
    )
