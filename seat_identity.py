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
  3. seat identity      — THIS MODULE. No bearer. Loopback peer + a registered,
                          enabled seat id in a header.

A request carrying an Authorization header of ANY kind is decided by the bearer
path, whether it succeeds or fails. Adding X-Sovereign-Seat to a bad-bearer
request must never buy reach the bearer did not have — that would be privilege
escalation by header, so the seat path is only ever consulted when NO
Authorization header is present at all.

──────────────────────────────────────────────────────────────────────────────
LOOPBACK IS NOT "INSIDE MY NETWORK", AND THIS IS THE TRAP THIS MODULE IS BUILT
AROUND.

The bridge is published through a Cloudflare tunnel. `cloudflared` runs ON this
machine and connects to 127.0.0.1:8100, so a request from the open internet
arrives at the ASGI layer with `scope["client"] == ("127.0.0.1", ...)`. The peer
check ALONE would therefore hand the whole read+write surface to anyone on the
internet who guesses a seat id — and seat ids are not secrets. bridge.py's own
code already says this twice: the rate limiter keys on CF-Connecting-IP because
"CF-Connecting-IP is present iff the request arrived through the Cloudflare
tunnel", and the connector route notes "request.client.host is ALWAYS 127.0.0.1
here".

So the seat path denies whenever ANY proxy-forwarding header is present, and it
denies before it looks at anything else. A genuinely seated Studio terminal
talking straight to 127.0.0.1:8100 sends none of them.

That is defence in depth, not belt-and-braces: either check alone is
insufficient, and both together are still only as strong as "nothing on this
box forwards to the bridge without a forwarding header".

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


def audit(seat_id: str | None, tool: str | None, outcome: str, reason: str) -> None:
    """One line per seat-identity request. Seat ids and tool names only —
    no bearer, no token, no argument bodies, nothing secret."""
    audit_log.info(
        "seat=%s tool=%s outcome=%s reason=%s",
        seat_id or "-",
        tool or "-",
        outcome,
        reason,
    )

# The header a seated terminal sets from its environment.
SEAT_HEADER = "x-sovereign-seat"

# Any of these means the request was relayed by something. A relayed request is
# not a seated terminal, whatever the TCP peer says. Lowercase: header lookup on
# Starlette's Headers is case-insensitive, but we also scan raw dict copies.
PROXY_HEADERS = (
    "cf-connecting-ip",
    "x-forwarded-for",
    "x-real-ip",
    "forwarded",
    "x-forwarded-host",
    "cf-ray",
)

# Literal, deliberately. Not a subnet, not a hostname, not ::1 — see NOTES in
# the delivery report: whether to admit ::1 depends on the launchd bind address
# and is Anthony's call, not this module's.
LOOPBACK = "127.0.0.1"

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


def load_registry() -> dict[str, Any] | None:
    """The seat registry, or None if it is absent/unreadable/malformed.

    None is the fail-closed answer and the caller MUST treat it as "deny every
    seat", never as "no restrictions". Absence is the off switch.
    """
    path = registry_path()
    try:
        raw = json.loads(path.read_text())
    except (OSError, ValueError):
        return None
    if not isinstance(raw, dict):
        return None
    seats = raw.get("seats")
    if not isinstance(seats, dict):
        return None
    return raw


def resolve_seat(peer_host: str | None, seat_id: str | None, headers: Any) -> dict[str, Any]:
    """Decide the seat path. Returns an auth context on success, raises
    SeatDenied on every failure. There is no partial success and no fallback to
    another auth path.

    Order matters: the relay check runs FIRST, because a tunneled request has a
    loopback peer and would otherwise pass the peer check.
    """
    # 1. Relayed? Then it is not a seated terminal, whatever the peer says.
    for h in PROXY_HEADERS:
        if _header_present(headers, h):
            raise SeatDenied(
                "relayed",
                (
                    f"Seat identity is refused on relayed requests (saw {h!r}). "
                    "This path is for terminals seated on this machine talking "
                    "directly to 127.0.0.1. A request through the tunnel or any "
                    "reverse proxy arrives with a loopback peer, so the peer "
                    "address alone cannot tell the two apart. Use the arrival "
                    "flow: POST /api/arrival/request."
                ),
            )

    # 2. Loopback peer, from the ASGI scope client — never from a header.
    if peer_host != LOOPBACK:
        raise SeatDenied(
            "not_loopback",
            (
                f"Seat identity requires a loopback peer address; this request "
                f"came from {peer_host!r}. Seats are terminals on this machine. "
                "Everything outside uses the arrival flow: POST /api/arrival/request."
            ),
        )

    # 3. A seat id was actually presented.
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

    # 4. The registry exists and is readable. Absence denies — it is the switch.
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

    # 5. The seat is registered.
    seat = registry["seats"].get(seat_id)
    if not isinstance(seat, dict):
        raise SeatDenied(
            "unknown_seat",
            (
                f"Seat {seat_id!r} is not in the seat registry. Ask Anthony to "
                "seat you, or use the arrival flow: POST /api/arrival/request."
            ),
        )

    # 6. ...and enabled. Explicit true only: a missing/likewise-shaped `enabled`
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
