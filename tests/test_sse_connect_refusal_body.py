"""The stack's refusal DETAIL must survive the connect, not just its status.

⚠ WHAT WAS ACTUALLY BROKEN, AND WHY THE EXISTING N4 TESTS DID NOT SEE IT.

`tests/test_seat_identity.py` already proves `_connect_refusal` prefers the
stack's own words over httpx's paraphrase — and it proves it against a hand-made
`_Resp` whose `.json()` simply works. In production nothing works: the MCP SSE
transport opens the door with `httpx_sse.aconnect_sse`, a STREAMING request, and
raises `raise_for_status()` inside that context manager, so at the moment of the
raise the body is unread and by the moment `call_mcp_tool` catches the exception
the context manager has closed the response. Measured on httpx 0.28.1:

    response.json()  -> httpx.ResponseNotRead
    response.text    -> httpx.ResponseNotRead
    response.read()  -> httpx.StreamClosed   (and .aread() likewise)

So `detail` fell back to `str(leaf)` — "Client error '400 Bad Request' for url
…" — which contains no seat name, so `named_seat` was False and every
seat-name refusal was reported as `stack_refused_session` with a message
naming nothing. The round-4 review saw the symptom and read the cause as "the
SDK's HTTPStatusError does not carry the body". It carries the RESPONSE; the
body is what is gone, and it is gone irrecoverably, so the fix cannot live in
the handler. It has to read the body AT the response — an httpx event hook —
which is `bridge._read_error_body`, installed by `bridge._mcp_client_factory`.

⚠ EVERY TEST BELOW BUILDS ITS 400 WITH `stream=httpx.ByteStream(...)`, NEVER
`content=`. That is the difference between reproducing the bug and testing a
world where it cannot happen: with `content=` httpx has the body eagerly and
these tests pass on the unfixed code. Verified both ways before this file was
written.

No socket is opened. `httpx.MockTransport` answers in-process, so the suite's
AF_INET block and the isolation audit both stay clean.
"""

import asyncio
import json
import sys
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
import mcp.client.sse as mcp_sse
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import bridge  # noqa: E402

SEAT_DETAIL = (
    "X-Sovereign-Seat 'anthony' is a reserved ledger label and cannot be used "
    "as a seat name"
)
PLAIN_DETAIL = "credential rejected"


def _run(coro):
    return asyncio.run(coro)


def _streamed(status: int, payload, content_type="application/json"):
    """A 400 in the shape the real transport produces: body present on the
    wire, NOT yet read into the response object."""
    body = json.dumps(payload).encode() if not isinstance(payload, bytes) else payload
    return httpx.Response(
        status,
        stream=httpx.ByteStream(body),
        headers={"content-type": content_type, "content-length": str(len(body))},
    )


@pytest.fixture
def refusing_stack(monkeypatch):
    """Pin the TRANSPORT identically on both sides of the fix, and nothing else.

    ⚠ THE OBVIOUS SEAM IS A NO-OP, AND IT COSTS A REAL SOCKET IF YOU BELIEVE IT.
    `mcp.client.sse.sse_client` takes `httpx_client_factory: ... =
    create_mcp_http_client` as a DEFAULT ARGUMENT, bound when the function was
    defined. `monkeypatch.setattr(mcp_sse, "create_mcp_http_client", ...)`
    therefore changes nothing the default path reads — measured 2026-09-06, a
    run patched that way went out to the live `127.0.0.1:3434/sse` and came
    back 401. Inside the suite the conftest AF_INET block catches it, and the
    result LOOKS like a red test: `failure_class` "stack", which is neither the
    unfixed answer nor the fixed one. That is a false red, and a false red on a
    baseline is how a fix gets declared over a bug it never reproduced.

    So the transport is bound by wrapping `sse_client` itself:

      * the bridge passed a factory (FIXED)   -> forward it untouched. It calls
        `bridge.create_mcp_http_client`, patched below to build the
        mock-transport client, and installs its own real hook on it.
      * the bridge passed none (UNFIXED)      -> substitute a factory that
        builds the SAME mock-transport client with NO hook.

    Identical bytes on the wire, identical response object, one difference: the
    hook. Which is the thing under test.
    """

    def install(status=400, payload=None, seat_detail=True):
        detail = SEAT_DETAIL if seat_detail else PLAIN_DETAIL
        body = {"detail": detail} if payload is None else payload

        def handler(request):
            if body == b"":
                return httpx.Response(status, stream=httpx.ByteStream(b""))
            return _streamed(status, body)

        def make(headers=None, timeout=None, auth=None):
            return httpx.AsyncClient(
                transport=httpx.MockTransport(handler),
                headers=headers or {},
                follow_redirects=True,
            )

        # What `bridge._mcp_client_factory` delegates to (the fixed path).
        monkeypatch.setattr(bridge, "create_mcp_http_client", make, raising=False)

        @asynccontextmanager
        async def pinned_sse(url, headers=None, httpx_client_factory=None, **kw):
            async with mcp_sse.sse_client(
                url,
                headers=headers,
                httpx_client_factory=httpx_client_factory or make,
                **kw,
            ) as pair:
                yield pair

        # conftest blocks the real transport for every test; this file is one
        # of the "installs its own transport" cases that block documents.
        monkeypatch.setattr(bridge, "sse_client", pinned_sse)
        return make

    return install


# ── THE FIX ─────────────────────────────────────────────────────────────────


def test_a_seat_name_refusal_survives_the_streamed_close(refusing_stack):
    """RED ON 49f270d. The whole point of the file.

    Real `sse_client`, real `aconnect_sse`, real streaming close — only the
    socket is mocked. Unfixed, this returns `stack_refused_session` and an
    error carrying httpx's "Client error '400 Bad Request'". Fixed, the hook
    has already read the body, so the stack's sentence is in hand and the seat
    marker is found in it.
    """
    refusing_stack()
    out = _run(bridge.call_mcp_tool("recall_insights", {}, seat="anthony"))

    assert out["ok"] is False
    assert out["failure_class"] == "stack_refused_seat_name"
    assert out["upstream_status"] == 400
    assert SEAT_DETAIL in out["error"]
    assert "renamed in the registry" in out["error"]
    # The three ways the unfixed path described this failure, all absent now.
    assert "Client error" not in out["error"]
    assert "TaskGroup" not in out["error"]


def test_a_non_seat_refusal_carries_the_stacks_words_and_keeps_its_class(refusing_stack):
    """Precision both ways. A 401 that says nothing about a seat must still
    reach the operator with the stack's sentence — the body-reading fix is not
    only for seat names — and must NOT be reclassified as a seat problem."""
    refusing_stack(status=401, seat_detail=False)
    out = _run(bridge.call_mcp_tool("recall_insights", {}))

    assert out["failure_class"] == "stack_refused_session"
    assert out["upstream_status"] == 401
    assert PLAIN_DETAIL in out["error"]


def test_a_refusal_with_no_body_still_names_the_refusal(refusing_stack):
    """THE "ONE WITHOUT" CASE. An empty body is not a failure of the fix; the
    bridge falls back to the SDK's message and still reports a refusal at
    connect with its status, rather than an egress fault. Green on both sides
    of the fix, deliberately: it guards the fallback the hook must not eat."""
    refusing_stack(status=400, payload=b"")
    out = _run(bridge.call_mcp_tool("recall_insights", {}, seat="anthony"))

    assert out["ok"] is False
    assert out["failure_class"] == "stack_refused_session"
    assert out["upstream_status"] == 400
    assert out["error"]


def test_a_non_json_body_is_carried_verbatim(refusing_stack):
    """The stack is not the only thing that can answer /sse. A proxy's
    text/plain refusal must reach the operator as its own words."""
    refusing_stack(payload=b"upstream said no: seat header rejected")
    out = _run(bridge.call_mcp_tool("recall_insights", {}, seat="anthony"))

    assert out["upstream_status"] == 400
    assert "upstream said no: seat header rejected" in out["error"]


# ── THE FALSIFIER: it is the HOOK that does this ────────────────────────────


def test_without_the_hook_the_same_transport_loses_the_detail(refusing_stack):
    """⚠ THE CONTROL, AND IT ENCODES THE UNFIXED BEHAVIOUR ON PURPOSE.

    Identical transport, identical 400, identical body — but the bridge is made
    to open the session with a factory that installs NO hook, which is exactly
    what 49f270d did by passing no factory at all. The detail is then
    unreachable and the class falls back to `stack_refused_session`.

    Without this, the tests above could be passing because `MockTransport` is
    friendlier than a socket rather than because the hook works, and the file
    would prove nothing. It also pins the OLD behaviour, so a future change
    that made the hook unnecessary would have to say so here.
    """
    unhooked = refusing_stack()
    monkeypatch_target = bridge._mcp_client_factory
    try:
        bridge._mcp_client_factory = unhooked
        out = _run(bridge.call_mcp_tool("recall_insights", {}, seat="anthony"))
    finally:
        bridge._mcp_client_factory = monkeypatch_target

    assert out["failure_class"] == "stack_refused_session"
    assert SEAT_DETAIL not in out["error"]
    assert "Client error" in out["error"]


def test_the_hook_leaves_a_success_response_unread():
    """⚠ THE ONE WAY THIS FIX COULD BREAK PRODUCTION. Reading a 2xx here would
    consume the SSE stream the transport is about to iterate and hang the
    connection instead of serving it. The hook must be a no-op below 400."""

    class _Probe:
        status_code = 200
        read_calls = 0

        async def aread(self):
            type(self).read_calls += 1

    _run(bridge._read_error_body(_Probe()))
    assert _Probe.read_calls == 0


def test_the_hook_never_raises_on_an_unreadable_body():
    """Fail-QUIET, and that is not the fail-open this house hunts: the hook
    decides nothing. If it raised, a precise upstream error would be replaced
    by an error about the diagnostic."""

    class _Broken:
        status_code = 400

        async def aread(self):
            raise httpx.StreamClosed()

    _run(bridge._read_error_body(_Broken()))  # must not raise


# ── The factory contract ────────────────────────────────────────────────────


def test_every_sse_session_is_opened_with_the_hooked_factory():
    """The fix is worth nothing on the one call path that forgets it, and
    `_list_tools_raw` (the heartbeat's inventory fetch) is exactly the path a
    reader would forget. Read from the source rather than by calling each one,
    because two of the three need a live session to reach their transport."""
    src = Path(bridge.__file__).read_text()
    opens = src.count("async with sse_client(")
    hooked = src.count("httpx_client_factory=_mcp_client_factory")
    assert opens == 3, f"the number of SSE call sites changed: {opens}"
    assert hooked == opens, (
        f"{opens} SSE sessions are opened and only {hooked} install the "
        "error-body hook; the ones that do not will report a refusal with no "
        "detail."
    )


def test_the_factory_matches_the_sdks_expected_signature():
    """`sse_client` calls the factory BY KEYWORD (headers=, timeout=, auth=).
    A factory that renamed one of those would fail at connect — as a TypeError
    inside a TaskGroup, i.e. the exact class of unreadable failure this whole
    lane is about."""
    import inspect

    params = inspect.signature(bridge._mcp_client_factory).parameters
    assert list(params) == ["headers", "timeout", "auth"]
    assert all(p.default is None for p in params.values())


def test_the_factory_installs_the_hook_and_keeps_the_sdk_defaults():
    client = bridge._mcp_client_factory(headers={"x-test": "1"})
    try:
        assert bridge._read_error_body in client.event_hooks["response"]
        # Delegated to the SDK constructor, so MCP's own defaults survive.
        assert client.follow_redirects is True
        assert client.headers["x-test"] == "1"
    finally:
        _run(client.aclose())
