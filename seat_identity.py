"""Seat identity — the third auth path on POST /api/call.

WHY THIS EXISTS (Anthony, 2026-09-05): *"Inside my network, meaning seats I've
put on the Studio, no tokens. They have the filesystem, I seated them, they work
together. The tap-to-arrive flow is for everything outside my network... The
master key stays on the Studio... Every Studio terminal gets its seat identity
in its environment so every write signs itself."*

Before this module a seated seat with no bearer could not call the bridge AT
ALL, so it could not write the record. That is the gap this closes.

THE THREE PATHS, in decision order, with no fallback between them:

  1. master bearer      — BRIDGE_TOKEN, full reach, unchanged.
  2. scoped session tok — svs_ prefix, The Door That Asks, unchanged.
  3. seat identity      — THIS MODULE. No bearer. A Unix-socket peer whose OWN
                          process environment names a registered, enabled seat.

A request carrying an Authorization header of ANY kind is decided by the bearer
path, whether it succeeds or fails. Adding X-Sovereign-Seat to a bad-bearer
request must never buy reach the bearer did not have — that would be privilege
escalation by header, so the seat path is only ever consulted when NO
Authorization header is present at all.

──────────────────────────────────────────────────────────────────────────────
LOOPBACK IS NOT AN IDENTITY. IT WAS TREATED AS ONE, AND THAT WAS THE BUG.

Until 2026-09-06 this module admitted a request on two facts: the ASGI peer was
127.0.0.1, and no proxy-forwarding header was present. Neither says ANYTHING
about which process is calling. The Codex review proved it in one command: with
SOVEREIGN_SEAT=codex-astra-studio in its own environment, a caller sent
`X-Sovereign-Seat: hq-claude-studio`, got a 200, and wrote as HQ. Seat ids are
not secrets; the header was an unverified claim.

Loopback is doubly worthless here because `cloudflared` runs ON this machine
and connects to 127.0.0.1:8100 — a request from the open internet arrives with
`scope["client"] == ("127.0.0.1", ...)`. bridge.py's own code says this twice:
the rate limiter keys on CF-Connecting-IP because it "is present iff the
request arrived through the Cloudflare tunnel", and the connector route notes
"request.client.host is ALWAYS 127.0.0.1 here".

THE FIX IS A DIFFERENT TRANSPORT, NOT A BETTER HEADER. A seat calls over a Unix
domain socket, where the kernel will name the peer's pid and uid; the bridge
reads that pid's SOVEREIGN_SEAT out of band and requires it to equal the
declared header. See seat_socket.py for the mechanism and its limits. TCP —
loopback or not, with or without forwarding headers — is no longer a seat path
at all: it is a 401 that says "use the socket". Anthony's rule is kept exactly,
because nothing in this exchange is a token: the seat proves who it is by BEING
the process the operator seated.

THE FEATURE IS INERT UNTIL THE REGISTRY FILE EXISTS. There is deliberately no
enable flag: an env var pointing at behaviour is the "config that assumes a
merge" shape this house has been bitten by. Absent registry -> every seat
request is 401. Anthony creating ~/.sovereign/hq/seats/registry.json IS the
deploy switch, and deleting it is the kill switch.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

import session_tokens as st

# ── Audit ───────────────────────────────────────────────────────────────────
# Every seat-identity request emits ONE line: seat, tool, outcome, reason.
#
# Given its OWN handler at INFO with propagate=False, deliberately. bridge.py
# configures no logging at all, so an un-configured logger falls through to
# logging.lastResort, which emits WARNING and above ONLY — every 'allowed' line
# would vanish while every denial was loud, and an audit trail that records
# refusals but not grants is the wrong half. That is a fail-open on the audit
# surface, so it is closed here rather than left to whatever configures the
# root logger. stderr, because that is where launchd already collects the
# bridge's output.
audit_log = logging.getLogger("seat-auth")
if not audit_log.handlers:
    _h = logging.StreamHandler(sys.stderr)
    _h.setFormatter(logging.Formatter("%(asctime)s seat-auth %(message)s"))
    audit_log.addHandler(_h)
    audit_log.setLevel(logging.INFO)
    audit_log.propagate = False


# Every audited field is caller-controlled — the seat id and the tool name both
# arrive off the wire — so every one is bounded and escaped. Codex review
# 2026-09-06 (P2 AUDIT): a tool name containing a newline produced TWO physical
# log lines, which is forged audit text. A reader parsing one line per request
# would have read the injected half as a genuine record of a second request.
_AUDIT_FIELD_MAX = 120


def _audit_field(value: Any) -> str:
    """One log field: escaped, quoted, bounded. Never more than one line.

    repr() is doing the real work — it renders \\n, \\r and every other control
    character as an escape rather than emitting it — and the slice bounds a
    caller who sends a megabyte of seat id. Truncation is MARKED, because a
    silently shortened audit field is a small fail-open of its own.
    """
    text = repr("-" if value is None or value == "" else str(value))
    if len(text) > _AUDIT_FIELD_MAX:
        text = text[:_AUDIT_FIELD_MAX] + "...TRUNCATED"
    return text


def audit(seat_id: str | None, tool: str | None, outcome: str, reason: str) -> None:
    """One line per seat-identity request, always exactly one. Seat ids and tool
    names only — no bearer, no token, no argument bodies, nothing secret."""
    audit_log.info(
        "seat=%s tool=%s outcome=%s reason=%s",
        _audit_field(seat_id),
        _audit_field(tool),
        _audit_field(outcome),
        _audit_field(reason),
    )

# The header a seated terminal sets from its environment.
SEAT_HEADER = "x-sovereign-seat"

# ⚠ AN ALLOWLIST, NOT A DENYLIST — AND THAT INVERSION IS THE FIX.
#
# This was a six-name denylist (cf-connecting-ip, x-forwarded-for, x-real-ip,
# forwarded, x-forwarded-host, cf-ray). Codex review 2026-09-06 (P2 FORWARDING)
# enumerated what it MISSED: X-Forwarded-Proto, X-Forwarded-Port,
# CF-Connecting-IPv6 and True-Client-IP each admitted a request when supplied
# alone. A denylist of relay headers can only ever name the relays somebody
# thought of; the set of headers a proxy might add is open, and ours was not.
#
# So: a seat request may carry the handful of headers an HTTP client needs to
# make the request at all, plus its own declaration. Anything else — known
# forwarding header, unknown forwarding header, or a header nobody has invented
# yet — is a 401 naming the header. New relay software cannot widen this.
SEAT_ALLOWED_HEADERS = frozenset(
    {
        # What curl / httpx must send for the request to be a request.
        "host",
        "user-agent",
        "accept",
        "accept-encoding",
        "accept-language",
        "connection",
        "content-type",
        "content-length",
        "transfer-encoding",
        "expect",  # curl switches to 100-continue above a ~1 KiB body
        # The seat's own declaration, checked against the peer's environment.
        SEAT_HEADER,
    }
)

# Kept as a name because the audit reason and the prose both refer to it, and
# because a reader grepping for the old constant deserves to find it rather
# than conclude the relay defence was dropped. It is now documentation of the
# common cases, not the mechanism — SEAT_ALLOWED_HEADERS is the mechanism.
PROXY_HEADERS = (
    "cf-connecting-ip",
    "cf-connecting-ipv6",
    "cf-ray",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-forwarded-port",
    "x-real-ip",
    "true-client-ip",
    "forwarded",
    "via",
)

# The loopback literal is GONE, and its absence is the point. It used to be the
# admission test; a peer address is not an identity, and the ::1-or-not question
# it left open (see the previous delivery report's NOTES) is moot now that the
# transport is a filesystem path rather than an address.

# ── The seat tool surface ────────────────────────────────────────────────────
#
# "The same tool surface a read+write session grant gets today" — so the source
# of truth is st.TOOL_SCOPES, reused EXACTLY. Nothing is widened here. Two
# narrowings apply on top, and both are narrowings:
SEAT_SCOPES = ("read", "write")

# 1. Governance-shaped, denied on this path regardless of what TOOL_SCOPES ever
#    says. st.NEVER_TOOLS already hard-denies these to session tokens; repeating
#    them here means a governance tool later mapped into read/write by mistake
#    still cannot reach a seat. Default-deny already covers every one of them
#    today (none is in TOOL_SCOPES) — this is the belt to that suspenders.
SEAT_NEVER_TOOLS = frozenset(st.NEVER_TOOLS) | frozenset(
    {
        # policies
        "set_policy",
        "govern",
        # protected records
        "designate_protected",
        "list_protected_thresholds",
        "open_protected_record",
        "decline_protected_record",
        # deletes / retirement / state rewriting
        "retire",
        "resolve_thread",
        "resolve_thread_by_id",
        "triage_threads",
        # tokens / grants — bridge ADMIN ROUTES, not stack tools; unreachable
        #   from this path anyway (the seat path exists only on /api/call), but
        #   named so the denial is legible rather than incidental.
        "mint_token",
        "revoke_token",
        # audit
        "audit_decoupling",
    }
)

# 2. Unsignable writes. Anthony's requirement is that EVERY write signs itself.
#    A write tool whose stack schema has no field that can carry the seat id
#    cannot sign, and the stack's _reject_unknown_params turns an injected
#    unknown key into a hard ValueError rather than a silent drop — so
#    injecting anyway is not an option either. Fail closed: deny the write
#    rather than let an unsigned one through. This set shrinks as the stack
#    grows the field; it is a to-do list, not a policy.
SEAT_UNSIGNABLE_WRITES = frozenset(
    {
        "archive_exchange",
        "reflection_ack",
        "spiral_reflect",
    }
)

# Tools whose stack inputSchema declares source_instance, so the bridge can
# stamp the seat id onto them. Explicit, never inferred: injecting into a tool
# that does not declare the field is a hard error upstream.
#
# ⚠ DEPLOY ORDER: THE STACK GOES FIRST. record_open_thread's source_instance
# lands on sovereign-stack branch feat/seat-identity-stamp (server.py schema +
# dispatch, memory.py storage). Until that is merged and the SSE process is
# running it, this bridge injects a field the stack does not declare — and
# _reject_unknown_params is NOT applied to record_open_thread (it is invoked
# for record_insight and recall_insights only, server.py:2964/3088), so the key
# would be SILENTLY DROPPED rather than refused. The bridge would believe it
# signed; the thread would land unattributed. That is exactly the fail-open
# record_insight lived under until 2026-08-28. Deploying this bridge branch
# without the stack branch is therefore not a partial win, it is the bug.
SEAT_SIGNABLE_TOOLS = frozenset(
    {
        "record_insight",
        "record_open_thread",
        "handoff",
        "arrive_lineage",
    }
)


class SeatDenied(Exception):
    """Seat path refused. `reason` is safe to return to the caller and to log —
    it names a condition, never a secret."""

    def __init__(self, reason: str, detail: str):
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


def sovereign_root() -> Path:
    """Resolved FRESH on every call so SOVEREIGN_ROOT overrides are honored.

    Every other ~/.sovereign path in this repo is a module-level constant
    (session_tokens.py DB_PATH, bridge.py COMMS_DIR / LEGACY_LEDGER_FILE /
    _IDEM_PATH), which makes monkeypatch.setenv a no-op because bridge is
    imported at collection time. sovereign-stack learned this the hard way and
    documents it at src/sovereign_stack/handoff.py:88-110; dashboard_readers.py:98
    is the pattern copied here.
    """
    return Path(os.environ.get("SOVEREIGN_ROOT", str(Path.home() / ".sovereign")))


def registry_path() -> Path:
    return sovereign_root() / "hq" / "seats" / "registry.json"


# The registry is a hand-written file listing a handful of terminals. 64 KiB is
# already absurdly generous; anything larger is not a registry.
REGISTRY_MAX_BYTES = 64 * 1024
# Deep enough for {"seats": {"id": {...}}} several times over, shallow enough
# that the parser never approaches the interpreter's recursion limit.
REGISTRY_MAX_DEPTH = 12


class _DuplicateKey(ValueError):
    """A registry object declared the same key twice."""


def _no_duplicate_keys(pairs):
    """json object hook — Codex review 2026-09-06 (P2 REGISTRY).

    `{"enabled": false, "enabled": true}` parsed to `{"enabled": True}` and let
    a disabled seat in: json.loads is last-wins, and the DISABLING half was the
    half that got dropped. There is no honest way to pick a winner, so the file
    is refused. Anthony's revocation lever must not be defeatable by appending.
    """
    seen = set()
    for key, _ in pairs:
        if key in seen:
            raise _DuplicateKey(f"duplicate key {key!r} in the seat registry")
        seen.add(key)
    return dict(pairs)


def _depth_ok(value: Any, budget: int) -> bool:
    """Iterative depth check. Recursion here would be the very bug being fixed."""
    stack = [(value, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > budget:
            return False
        if isinstance(node, dict):
            stack.extend((v, depth + 1) for v in node.values())
        elif isinstance(node, list):
            stack.extend((v, depth + 1) for v in node)
    return True


def load_registry() -> dict[str, Any] | None:
    """The seat registry, or None if it is absent/unreadable/malformed.

    None is the fail-closed answer and the caller MUST treat it as "deny every
    seat", never as "no restrictions". Absence is the off switch.

    EVERY failure returns None. Codex review 2026-09-06 (P2 REGISTRY): a
    10,000-level nested array raised RecursionError, which is NOT a ValueError,
    so it escaped this except clause and surfaced as a 500. A 500 on the auth
    path is a fail-open in the only sense that matters — it tells the caller
    the door is broken rather than shut, and it takes the audit line with it.
    The size cap is the real fix; the RecursionError catch is the belt.
    """
    path = registry_path()
    try:
        if path.stat().st_size > REGISTRY_MAX_BYTES:
            return None
        raw = json.loads(path.read_text(), object_pairs_hook=_no_duplicate_keys)
    except (OSError, ValueError, RecursionError):
        return None
    if not isinstance(raw, dict):
        return None
    if not _depth_ok(raw, REGISTRY_MAX_DEPTH):
        return None
    seats = raw.get("seats")
    if not isinstance(seats, dict):
        return None
    return raw


def resolve_seat(peer: Any, seat_id: str | None, headers: Any) -> dict[str, Any]:
    """Decide the seat path. Returns an auth context on success, raises
    SeatDenied on every failure. There is no partial success and no fallback to
    another auth path.

    `peer` is the VERIFIED peer identity the Unix-socket listener stamped into
    the ASGI scope (seat_socket.SEAT_PEER_EXT), or None for a request that did
    not arrive on that socket. It is never read from a header, and a header
    cannot create it — uvicorn builds the http scope with no `extensions` key
    at all, so only seat_socket can put one there.

    Order matters: the header allowlist runs FIRST, then the process binding,
    and only then anything the caller declared about itself.
    """
    # 1. Only the headers a request needs to be a request. Anything else — a
    #    relay header known or unknown — means something between the caller and
    #    here, and a relay is not a seated terminal.
    unexpected = _unexpected_headers(headers)
    if unexpected:
        first = unexpected[0]
        relay = " It is a known proxy-forwarding header." if first in PROXY_HEADERS else ""
        raise SeatDenied(
            "relayed",
            (
                f"Seat identity refuses a request carrying {first!r}.{relay} This "
                "path accepts only the headers a client needs to make the request "
                "(host, accept, content-type, content-length, user-agent and "
                "friends) plus X-Sovereign-Seat. Everything else means the request "
                "was relayed. Use the arrival flow: POST /api/arrival/request."
            ),
        )

    # 2. THE BINDING. A seat is a PROCESS, not a string somebody typed.
    #
    #    Before 2026-09-06 this was a loopback-peer check, and a loopback peer
    #    is not an identity: cloudflared runs on this machine, so the whole
    #    internet arrives at 127.0.0.1, and every local process could name any
    #    seat it liked. The kernel is the only witness that cannot be talked
    #    into lying, and it will only testify over a Unix socket.
    if not isinstance(peer, dict):
        raise SeatDenied(
            "not_socket",
            (
                "Seat identity is not available on this connection. A seat must "
                "call over the seat socket (curl --unix-socket "
                "<sovereign-root>/hq/seats/bridge.sock), not over 127.0.0.1:8100 "
                "— a TCP connection carries no process identity, and the tunnel "
                "makes every outside request look local. Everything else uses "
                "the arrival flow: POST /api/arrival/request."
            ),
        )
    if not peer.get("ok"):
        raise SeatDenied(
            str(peer.get("reason") or "no_peer_creds"),
            str(peer.get("detail") or "The calling process could not be identified."),
        )

    # 3. A seat id was actually declared.
    seat_id = (seat_id or "").strip()
    if not seat_id:
        raise SeatDenied(
            "no_seat_header",
            (
                f"No seat identity presented. Expected header "
                f"'X-Sovereign-Seat: <seat-id>' (and no Authorization header). "
                "A seated terminal exports this in its environment."
            ),
        )

    # 4. THE DECLARATION MUST MATCH THE PROCESS. This is the line the whole
    #    module exists for. The header stays — a request that says who it is
    #    and is checked audits far better than one whose identity is only ever
    #    inferred — but it is a declaration, never a credential.
    if seat_id != peer.get("seat"):
        raise SeatDenied(
            "seat_mismatch",
            (
                f"This process is not seated as {seat_id!r}. Its {'SOVEREIGN_SEAT'} "
                "environment names a different seat, and the environment wins: the "
                "header is a declaration the bridge checks, not a credential the "
                "bridge accepts. A seat cannot call as another seat."
            ),
        )

    # 5. The registry exists and is readable. Absence denies — it is the switch.
    registry = load_registry()
    if registry is None:
        raise SeatDenied(
            "no_registry",
            (
                "No readable seat registry on this machine, so no seat can be "
                f"recognized. Expected {registry_path()}. Seat identity is inert "
                "until that file exists — this is not a caller error."
            ),
        )

    # 6. The seat is registered.
    seat = registry["seats"].get(seat_id)
    if not isinstance(seat, dict):
        raise SeatDenied(
            "unknown_seat",
            (
                f"Seat {seat_id!r} is not in the seat registry. Ask Anthony to "
                "seat you, or use the arrival flow: POST /api/arrival/request."
            ),
        )

    # 7. ...and enabled. Explicit true only: a missing/likewise-shaped `enabled`
    #    is NOT consent.
    if seat.get("enabled") is not True:
        raise SeatDenied(
            "seat_disabled",
            (
                f"Seat {seat_id!r} is registered but not enabled. Its registry "
                "entry must carry \"enabled\": true."
            ),
        )

    return {
        "status": "ok",
        "kind": "seat",
        "seat_id": seat_id,
        "substrate": seat.get("substrate"),
        "seat_kind": seat.get("kind"),
        # The kernel-attested pid this identity was bound to. Carried so the
        # audit line can name the actual process, not just the string it sent.
        "peer_pid": peer.get("pid"),
        # The scope a seat gets, reused verbatim from the session-token model.
        "scope": list(SEAT_SCOPES),
    }


def _header_present(headers: Any, name: str) -> bool:
    """True if `name` is present. Works for Starlette Headers (case-insensitive
    mapping) and for a plain dict, so tests can pass either."""
    if headers is None:
        return False
    try:
        if name in headers:
            return True
    except TypeError:
        pass
    try:
        return any(str(k).lower() == name for k in headers.keys())
    except AttributeError:
        return False


def _unexpected_headers(headers: Any) -> list[str]:
    """Every present header that is NOT on the allowlist, lowercased and sorted.

    Sorted so the denial names the same header every time for the same request
    — a message that varies run to run is a message nobody can write a test
    against. Returns a list rather than a bool so the 401 can say WHICH one.
    """
    if headers is None:
        return []
    try:
        names = {str(k).lower() for k in headers.keys()}
    except AttributeError:
        return []
    return sorted(names - SEAT_ALLOWED_HEADERS)


def seat_tool_allowed(tool: str) -> tuple[bool, str]:
    """Default-deny tool check for the seat path. Returns (allowed, reason).

    `reason` is 'ok' or the audit-line word for WHY it was refused. Every branch
    below is a denial; there is no path that returns True by falling through.
    """
    if tool in SEAT_NEVER_TOOLS:
        return False, "governance"
    required = st.TOOL_SCOPES.get(tool)
    if required is None:
        return False, "unmapped"  # master-only by default-deny
    if required not in SEAT_SCOPES:
        return False, "out_of_scope"  # e.g. the 'session' scope
    if required == "write" and tool not in SEAT_SIGNABLE_TOOLS:
        # Includes SEAT_UNSIGNABLE_WRITES and anything write-shaped added later
        # without a signing field — new write tools are denied until they can
        # sign, which is the correct direction to fail.
        return False, "unsignable"
    return True, "ok"


_DENY_DETAIL = {
    "governance": (
        "is governance-shaped (policies, protected records, thread resolution, "
        "tokens/grants, audit) and is denied to seat identity regardless of "
        "scope. Governance stays behind the master key on the Studio."
    ),
    "unmapped": (
        "is not in the session-token scope map, so it is master-only by "
        "default-deny. Seat identity reuses that map exactly and never widens it."
    ),
    "out_of_scope": (
        "needs a scope outside read+write (it mutates global spiral state). "
        "Seat identity carries read+write only."
    ),
    "unsignable": (
        "is a write whose stack schema has no field that can carry a seat id, "
        "so a seat could not sign it. Every write on this path must sign itself, "
        "so it is refused rather than written unsigned. This is a gap in the "
        "stack's tool schema, not a judgement about the seat."
    ),
}


def deny_detail(tool: str, reason: str) -> str:
    return f"Tool {tool!r} {_DENY_DETAIL.get(reason, 'is denied to seat identity.')}"


def seat_allowed_tools() -> list[str]:
    """The seat surface, derived from st.TOOL_SCOPES — never hand-listed."""
    return sorted(t for t in st.TOOL_SCOPES if seat_tool_allowed(t)[0])


def seat_denied_tools() -> list[tuple[str, str]]:
    """(tool, reason) for every mapped tool the seat path refuses."""
    return sorted(
        (t, seat_tool_allowed(t)[1]) for t in st.TOOL_SCOPES if not seat_tool_allowed(t)[0]
    )


def sign_arguments(tool: str, arguments: dict[str, Any], seat_id: str) -> dict[str, Any]:
    """Stamp the seat id onto a call so the write signs itself.

    OVERRIDE, not setdefault: a seat cannot claim another identity. If the body
    says source_instance='HQ' and the header says 'grok-build-studio', the
    header wins, because the header is the thing the bridge actually verified.
    """
    if tool in SEAT_SIGNABLE_TOOLS and isinstance(arguments, dict):
        arguments["source_instance"] = seat_id
    return arguments
