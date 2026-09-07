"""The bridge never answers 3xx. A trailing slash is a 404, not a redirect.

FROM THE MCP SHIM'S FIELD-LEVEL CONTRACT (web seat, chronicle domain
`temple-harness,stack-readiness,mcp-shim-contract,hq-lane,substrate-carries,2026-09-06`):
the bridge must never redirect. HQ measured `POST /api/call/` returning
**HTTP 307** on the live bridge on 2026-09-06 — Starlette's `redirect_slashes`,
on by default, sending a path that misses by one character to the one that
matches.

⚠ THIS IS A CONTRACT FIX, NOT A BEHAVIOUR CHANGE FOR ANY KNOWN CLIENT. The
shim refuses every 3xx and never follows one, so it already failed closed
against the 307; nothing that works today stops working. What changes is what
the bridge says about itself.

WHY IT MATTERS ANYWAY. A 307 preserves method and body, so a client that DOES
follow re-sends its `Authorization` header and the entire call to whatever
`Location` names — which turns a redirect from an authenticated tool endpoint
into a credential-forwarding instruction. The callers here hold scoped session
grants. A client that follows is one Location header from handing a token to an
unaudited address; a client that does not follow gets a 3xx it cannot
interpret. 404 is the only answer that serves either.

⚠ EVERY REQUEST BELOW PASSES `follow_redirects=False`. TestClient follows
redirects by DEFAULT, which would turn a 307-then-404 into a bare 404 and make
this whole file pass against the unfixed app. Each test asserts the status is
404 AND that it is not in the 3xx range, so a future redirect that happened to
land on a 404 still fails here.
"""

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import bridge  # noqa: E402

MASTER = "test-master-token-0123456789abcdef-0123456789abcdef"

# The two the contract names, plus the rest of the public door. Both an
# unauthenticated route and an authenticated one, because the redirect fires in
# the router BEFORE any dependency runs — a 3xx here would leak the existence
# of a route to a caller holding nothing.
SLASH_PATHS = (
    ("POST", "/api/call/"),
    ("GET", "/api/heartbeat/"),
    ("GET", "/api/tools/"),
    ("GET", "/api/discover/"),
    ("POST", "/api/batch/"),
    ("POST", "/api/arrival/request/"),
    ("POST", "/api/admin/tokens/mint/"),
)


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(bridge, "BEARER_TOKEN", MASTER)
    return TestClient(bridge.app)


@pytest.mark.parametrize("method,path", SLASH_PATHS)
def test_the_trailing_slash_form_is_404_and_never_a_redirect(client, method, path):
    r = client.request(
        method,
        path,
        json={} if method == "POST" else None,
        headers={"Authorization": f"Bearer {MASTER}"},
        follow_redirects=False,
    )
    assert not (300 <= r.status_code < 400), (
        f"{method} {path} answered {r.status_code} with "
        f"Location={r.headers.get('location')!r}; the contract says this door "
        "never redirects"
    )
    assert r.status_code == 404, f"{method} {path} answered {r.status_code}"
    assert "location" not in {k.lower() for k in r.headers}


@pytest.mark.parametrize("method,path", SLASH_PATHS)
def test_the_unauthenticated_trailing_slash_form_is_also_404(client, method, path):
    """The router decides slash redirection BEFORE any auth dependency runs, so
    the anonymous case is a different code path and gets its own assertion."""
    r = client.request(
        method,
        path,
        json={} if method == "POST" else None,
        follow_redirects=False,
    )
    assert not (300 <= r.status_code < 400), f"{method} {path} -> {r.status_code}"
    assert r.status_code == 404


def test_the_slash_form_is_indistinguishable_from_any_other_unknown_path(client):
    """The slash form must not become its own special 404 dialect.

    ⚠ AND IT DOES NOT CARRY `failure_class`, WHICH IS DELIBERATE AND WORTH
    STATING. The router's own 404 raises `starlette.exceptions.HTTPException`;
    the house handler at `bridge._http_exc_handler` is registered for
    `fastapi.HTTPException`, a SUBCLASS, so it never sees a routing 404 and
    every unknown path on this bridge already answers a bare
    `{"detail": "Not Found"}`. Making the slash form the one 404 that carries a
    failure class would be a broader change to every unknown path, and this
    lane is a contract fix. Asserted against a genuinely unknown path rather
    than against a literal, so if that ever changes both move together.
    """
    slash = client.post(
        "/api/call/",
        json={"tool": "recall_insights", "arguments": {}},
        headers={"Authorization": f"Bearer {MASTER}"},
        follow_redirects=False,
    )
    unknown = client.post(
        "/api/definitely-not-a-route",
        json={"tool": "recall_insights", "arguments": {}},
        headers={"Authorization": f"Bearer {MASTER}"},
        follow_redirects=False,
    )
    assert slash.status_code == unknown.status_code == 404
    assert slash.json() == unknown.json()


def test_the_canonical_forms_are_untouched(client):
    """THE FALSIFIER. Without it, `redirect_slashes=False` could have been
    achieved by breaking routing altogether and every assertion above would
    still be green."""
    assert client.get("/api/heartbeat", follow_redirects=False).status_code == 200
    # /api/call without a credential is 401 — reached the route, refused by
    # auth, which is what proves the route still resolves.
    r = client.post("/api/call", json={"tool": "x", "arguments": {}}, follow_redirects=False)
    assert r.status_code in (401, 403), r.status_code
    # The root, which is the ONE route in this file DEFINED with a slash.
    assert client.get("/", follow_redirects=False).status_code == 200


def test_the_app_declares_no_slash_redirection():
    """State the setting itself, so a future `FastAPI(...)` edit that drops the
    argument fails here by name rather than through seven status codes."""
    assert bridge.app.router.redirect_slashes is False


def test_no_route_in_this_file_is_defined_with_a_trailing_slash():
    """⚠ THE RISK THE FLAG CARRIES, ASSERTED. `redirect_slashes=False` is
    app-wide: a route DEFINED as `/api/thing/` would, from this commit on, stop
    answering its `/api/thing` form. Today only `/` is, and the root path is
    unaffected. This test is what makes adding such a route a deliberate act.
    """
    offenders = sorted(
        r.path
        for r in bridge.app.router.routes
        if getattr(r, "path", "") not in ("/",) and getattr(r, "path", "").endswith("/")
    )
    assert offenders == [], (
        f"routes defined with a trailing slash: {offenders}. With "
        "redirect_slashes=False their non-slash form now 404s."
    )
