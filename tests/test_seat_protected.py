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
    "content": "SYNTHETIC FIXTURE CONTENT — invented for this test, designated in this test.",
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

    async def fake(tool, args):
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
