"""How the seat surface is RESOLVED — HQ decision D2, review question (b).

Everything in `tests/test_seat_identity.py` decides against the pinned surface;
this file tests the machinery that produces one. It is the only place
`si.published_surface` is not stubbed, so every test here resets the cache
first and drives the two routes deliberately.

WHAT D2 REPLACED. The first release carried two hand-copied constants: a
100-name `SEAT_TOOL_SURFACE` transcribed from the stack's `list_tools`, and a
48-name `SEAT_RETIRED_TOOLS` derived from a 30-day usage census because the
stack had no retirement of its own. The reviewer measured the bridge's derived
retired set against the stack's and found the symmetric difference EMPTY — the
moment to delete the copy rather than keep it. The stack now owns retirement
(`RETIRED_TOOLS`, release/2026-09-06) and `list_tools` already filters by it,
so the published list IS the answer.

THE THREE PROPERTIES THIS FILE EXISTS FOR:
  1. The local import is preferred; the fetch is the fallback.
  2. Neither answering is a 503, never allow-all and never a deny-all dressed
     up as policy.
  3. The import is RETRIED each cache window, so deploying the stack without
     restarting the bridge is visible — the SOP #12 shape this house keeps
     rebuilding by resolving an import once at module scope.
"""

from __future__ import annotations

import asyncio
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


class _Tool:
    """The shape `_list_tools_raw` returns: an object with `.name`."""

    def __init__(self, name):
        self.name = name


# ⚠ CAPTURED AT MODULE IMPORT, BEFORE ANY FIXTURE RUNS, AND THAT IS THE WHOLE
# TRICK. The root conftest's autouse `surface` fixture replaces
# `si.published_surface` with a pinned stub, and conftest autouse fixtures run
# BEFORE a test module's own. So a fixture here that read
# `si.published_surface` to "restore the real one" would faithfully restore the
# stub and every test below would pass while exercising nothing — a suite green
# for the wrong reason, which is worse than red.
_REAL_PUBLISHED_SURFACE = si.published_surface


@pytest.fixture(autouse=True)
def _unpinned(monkeypatch):
    """⚠ THIS FILE OPTS OUT OF THE SUITE-WIDE PIN, DELIBERATELY.

    The root conftest replaces `si.published_surface` for every test so that no
    gate test depends on which stack tree the machine has. That is right there
    and fatal here: this file's whole subject IS the resolution. So the real
    function goes back, and every test starts from a cold cache.
    """
    monkeypatch.setattr(si, "published_surface", _REAL_PUBLISHED_SURFACE)
    si.reset_published_cache()
    yield
    si.reset_published_cache()


def _resolve(fetch=None):
    return asyncio.run(_REAL_PUBLISHED_SURFACE(fetch=fetch))


def _no_import(monkeypatch):
    """The stack registry is not importable — the state of a bridge whose
    companion tree is absent, or older than the retirement release."""
    monkeypatch.setattr(
        si, "_published_from_import", lambda: (_ for _ in ()).throw(ImportError("no stack"))
    )


# ── Route preference ────────────────────────────────────────────────────────


def test_the_local_import_is_preferred_over_the_fetch(monkeypatch):
    """A network round-trip inside an auth path is a cost and a dependency. The
    in-process registry answers when it can, and the fetch is not called."""
    monkeypatch.setattr(
        si,
        "_published_from_import",
        lambda: si.Surface(frozenset({"a", "b"}), frozenset({"c"}), "import"),
    )
    fetched = []

    async def fetch():
        fetched.append(1)
        return [_Tool("z")]

    surface = _resolve(fetch)
    assert surface.published == {"a", "b"}
    assert surface.retired == {"c"}
    assert fetched == [], "the fetch ran while the import was available"


def test_the_fetch_answers_when_the_import_cannot(monkeypatch):
    _no_import(monkeypatch)

    async def fetch():
        return [_Tool("recall_insights"), _Tool("record_insight")]

    surface = _resolve(fetch)
    assert surface.published == {"recall_insights", "record_insight"}
    assert "bridge credential" in surface.source


def test_the_fetch_route_reports_no_retirement_rather_than_guessing(monkeypatch):
    """The fetch can see what IS published and never what was removed, so its
    `retired` set is EMPTY and a denial there reads `unpublished`, not
    `retired`. Reporting a retirement it did not measure would be a reason
    invented to sound more informative than the measurement was."""
    _no_import(monkeypatch)

    async def fetch():
        return [_Tool("recall_insights")]

    surface = _resolve(fetch)
    assert surface.retired == frozenset()
    assert si.seat_tool_allowed("synthesize_now", surface) == (False, "unpublished")


# ── Fail closed ─────────────────────────────────────────────────────────────


def test_neither_route_answering_raises_rather_than_returning_empty(monkeypatch):
    """⚠ THE WHOLE REASON THIS IS A FUNCTION AND NOT A CONSTANT.

    An authorization decision needs the published set. Without it the two
    available defaults are "allow everything" and "deny everything", and the
    first is not an authorization decision at all. The second is not either: it
    would deny every tool with the word `unpublished`, a false statement about
    the world dressed as policy. So it raises, and the caller returns 503 —
    the door is BROKEN, which is a different sentence from "you are refused".
    """
    _no_import(monkeypatch)

    async def fetch():
        raise RuntimeError("SSE is down")

    with pytest.raises(si.SeatSurfaceUnavailable) as exc:
        _resolve(fetch)
    assert "ImportError" in str(exc.value), "the import failure was not named"
    assert "SSE is down" in str(exc.value), "the fetch failure was not named"


def test_a_fetch_that_returns_nothing_is_a_failure_not_an_empty_surface(monkeypatch):
    """An empty catalog and a failed fetch are indistinguishable from the wire,
    so the safe reading is the one that refuses. `get_tool_inventory` already
    fails closed to count -1 for the same reason."""
    _no_import(monkeypatch)

    async def fetch():
        return []

    with pytest.raises(si.SeatSurfaceUnavailable):
        _resolve(fetch)


def test_no_fetch_supplied_is_still_a_named_failure(monkeypatch):
    _no_import(monkeypatch)
    with pytest.raises(si.SeatSurfaceUnavailable) as exc:
        _resolve(None)
    assert "no tool-listing fallback" in str(exc.value)


def test_the_seat_path_returns_503_when_the_surface_is_unresolvable(monkeypatch, tmp_path):
    """End to end: an unresolvable surface is a SERVICE fault (503), not a
    scope refusal (403). The status code is the difference between "come back
    later" and "you may not have this", and a caller acts on it."""
    monkeypatch.setenv("SOVEREIGN_ROOT", str(tmp_path))
    monkeypatch.setenv("SOVEREIGN_CHRONICLE", str(tmp_path / "chronicle"))
    monkeypatch.setattr(st, "DB_PATH", tmp_path / "session_tokens.db")
    monkeypatch.setattr(bridge, "BEARER_TOKEN", MASTER)
    reg = tmp_path / "hq" / "seats" / "registry.json"
    reg.parent.mkdir(parents=True)
    reg.write_text(json.dumps({"seats": {SEAT: {"kind": "seated", "enabled": True}}}))
    _no_import(monkeypatch)

    async def broken():
        raise RuntimeError("SSE is down")

    monkeypatch.setattr(bridge, "_list_tools_raw", broken)

    class StampPeer:
        def __init__(self, app):
            self.app = app

        async def __call__(self, scope, receive, send):
            if scope.get("type") == "http":
                ext = dict(scope.get("extensions") or {})
                ext[ss.SEAT_PEER_EXT] = {
                    "ok": True, "pid": os.getpid(), "uid": os.getuid(), "seat": SEAT,
                }
                scope = {**scope, "extensions": ext}
            await self.app(scope, receive, send)

    r = TestClient(StampPeer(bridge.app), client=("127.0.0.1", 1)).post(
        "/api/call",
        json={"tool": "recall_insights", "arguments": {}},
        headers={"X-Sovereign-Seat": SEAT},
    )
    assert r.status_code == 503, r.text
    assert "bridge fault, not a caller error" in r.json()["detail"]


# ── The cache, and the retry that keeps it honest ───────────────────────────


def test_one_resolution_serves_the_cache_window(monkeypatch):
    calls = []

    def once():
        calls.append(1)
        return si.Surface(frozenset({"a"}), frozenset(), "import")

    monkeypatch.setattr(si, "_published_from_import", once)
    _resolve()
    _resolve()
    _resolve()
    assert calls == [1], "the surface was re-resolved inside its own cache window"


def test_the_import_is_retried_each_window_not_once_per_process(monkeypatch):
    """⚠ THE SOP #12 SHAPE, CLOSED BY CONSTRUCTION.

    Resolve the import once at module scope and a bridge that started before
    the stack deployed is pinned to the fetch route — or to a stale answer —
    for the life of the process, while the registry that knows the answer sits
    in the same interpreter. The attempt is INSIDE the cached function, so a
    stack that becomes importable is picked up at the next window with no
    restart. A failed import is not cached in sys.modules, so the retry costs a
    failed lookup.
    """
    state = {"importable": False}

    def flaky():
        if not state["importable"]:
            raise ImportError("not yet")
        return si.Surface(frozenset({"after_deploy"}), frozenset(), "import")

    monkeypatch.setattr(si, "_published_from_import", flaky)

    async def fetch():
        return [_Tool("before_deploy")]

    assert _resolve(fetch).published == {"before_deploy"}
    state["importable"] = True
    # Still inside the window: the cached answer stands, which is the point of
    # a window.
    assert _resolve(fetch).published == {"before_deploy"}
    si.reset_published_cache()  # the window turns over
    assert _resolve(fetch).published == {"after_deploy"}


def test_the_cache_window_expires(monkeypatch):
    """Measured against the module's own clock rather than by sleeping: a test
    that waits sixty seconds is a test that gets deleted."""
    monkeypatch.setattr(si, "PUBLISHED_CACHE_SECONDS", 0.0)
    calls = []

    def counted():
        calls.append(1)
        return si.Surface(frozenset({"a"}), frozenset(), "import")

    monkeypatch.setattr(si, "_published_from_import", counted)
    _resolve()
    _resolve()
    assert len(calls) == 2, "a zero-length window still served a cached answer"


# ── The listing adapter ─────────────────────────────────────────────────────


def test_the_listing_adapter_takes_tool_objects_or_bare_names():
    """The seam is fakeable without importing the MCP types, which is why the
    tests above can drive it at all."""
    a = si._published_from_listing([_Tool("x"), _Tool("y")])
    b = si._published_from_listing(["x", "y"])
    assert a.published == b.published == {"x", "y"}


def test_the_listing_adapter_ignores_unusable_entries():
    surface = si._published_from_listing([_Tool("x"), None, 7, _Tool(""), {"name": "y"}])
    assert surface.published == {"x"}
