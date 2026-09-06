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

import hashlib
import json
import logging
import os
import re
import stat
import sys
import time
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


def audit(
    seat_id: str | None,
    tool: str | None,
    outcome: str,
    reason: str,
    peer_pid: int | None = None,
    seat_pid: int | None = None,
    accept_pid: int | None = None,
) -> None:
    """One line per seat-identity request, always exactly one. Seat ids, tool
    names and pids only — no bearer, no token, no argument bodies, nothing
    secret.

    `peer_pid` IS THE POINT OF THE WHOLE MECHANISM, so it belongs on the line.
    Attribution is the asset this feature protects; without the pid the log
    records only the string the caller sent, which is the thing that was
    already untrustworthy. With it, the record names the process the kernel
    vouched for — the only field that later distinguishes a seat's real agent
    process from a one-liner somebody spawned. (It was resolved, returned, and
    dropped on the floor in the first draft: a field written and unwired.)

    ⚠ THREE PIDS, BECAUSE ONE PID CANNOT TELL THE STORY (Codex review
    2026-09-06, F2; HQ decision D6). The README said the connection's opener is
    "recorded ... in the audit line" and it was NOT — `accept_pid` and
    `seat_pid` survived in the protocol extension and died at the auth context.
    A promise in the documentation that the code does not keep is worse than a
    missing field, because the next reader believes the forensics exist.

      peer_pid   — who SENT this request. The kernel's answer, re-read per
                   request. This is the identity that decided the call.
      seat_pid   — whose ENVIRONMENT named the seat: peer_pid itself, or the
                   nearest ancestor whose environment macOS would show. When
                   these differ, the seat was INHERITED, not declared.
      accept_pid — who OPENED the connection. When this differs from peer_pid
                   the descriptor changed hands mid-connection, which is the
                   signature of the handoff F2 names and the one thing a log
                   reader most needs to see. It decides NOTHING.

    Present on the DENIAL line too, deliberately: `seat_mismatch` is precisely
    the event where the three pids are worth reading, and a forensic field that
    only appears on success is not forensics.
    """
    audit_log.info(
        "seat=%s pid=%s seat_pid=%s accept_pid=%s tool=%s outcome=%s reason=%s",
        _audit_field(seat_id),
        _audit_field(peer_pid) if peer_pid is not None else "-",
        _audit_field(seat_pid) if seat_pid is not None else "-",
        _audit_field(accept_pid) if accept_pid is not None else "-",
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
# ANTHONY'S RULING, 2026-09-06: *"all studio seats are trusted."*
#
# WHAT THAT REPLACED, so the change is legible rather than mysterious. Until
# this ruling the seat surface was st.TOOL_SCOPES — the read+write session-grant
# map, 21 tools out of a published 100 — because a seat was modelled as a
# scoped visitor. It is not. A seat is a terminal Anthony started on his own
# machine, and CLAUDE.md had already measured the cost of the old model: a
# scoped seat reaches 19 of 98 tools and cannot even call
# `where_did_i_leave_off`, the boot door every arriving seat is TOLD to call.
#
# THE SHAPE OF THE SURFACE, AND IT HAS EXACTLY ONE SUBTRACTION:
#
#     allowed  =  what the stack PUBLISHES right now  −  governance
#
# ⚠ ONE SOURCE, AND THE SECOND ONE IS GONE (HQ decision D2, 2026-09-06, from
# Codex review question (b)). The first release of this feature carried TWO
# hand-copied constants: a 100-name `SEAT_TOOL_SURFACE` transcribed from the
# stack's `list_tools`, and a 48-name `SEAT_RETIRED_TOOLS` derived from a
# 30-day usage census because the stack had no retirement of its own. BOTH ARE
# DELETED. The stack now HAS `RETIRED_TOOLS` (release/2026-09-06, 9c42290) and
# `list_tools` already filters by it, so the published list IS the answer and
# copying it here could only ever go stale in a direction nobody would notice.
# The review measured the two derivations agreeing exactly — symmetric
# difference empty — which is the moment to delete the copy, not to keep it.
#
# ⚠ THE HONEST CONSEQUENCE, STATED BECAUSE IT INVERTS A FINDING THE PREVIOUS
# RELEASE PINNED. The deleted census set is what took `ask_scribe` and
# `reflection_ack` away from seats while a scoped session grant could still
# call them — the "narrows in exactly two places" defect. Deriving from the
# live surface fixes it in the only honest way: those names are now denied
# because THE STACK retired them, not because this bridge guessed. And it cuts
# the other way too, which is the half worth saying out loud: run this bridge
# against a stack that has NOT retired anything (live `main` today), and a seat
# reaches every one of the ~86 non-governance names that stack publishes,
# `ask_scribe` and `watch_status` included. That is correct — the seat surface
# is the stack's surface minus Anthony's — and it is one more reason THE STACK
# DEPLOYS FIRST.
SEAT_SCOPES = ("read", "write")


class SeatSurfaceUnavailable(Exception):
    """Neither route could say what the stack publishes.

    THE ONLY SAFE ANSWER IS NO ANSWER. An authorization decision needs the
    published set; without it the two available defaults are "allow everything"
    and "deny everything", and the first is not an authorization decision at
    all. So this raises and the caller returns 503 — the door is BROKEN, which
    is a different sentence from "you are refused", and the caller deserves the
    one that is true.
    """


# How long one resolution serves. Short enough that a stack deploy is visible
# without a bridge restart; long enough that a burst of seat calls does not
# become a burst of MCP round-trips.
PUBLISHED_CACHE_SECONDS = 60.0

_published_cache: dict[str, Any] = {"surface": None, "expires": 0.0}


class Surface:
    """What the stack publishes, and (when knowable) what it retired.

    `retired` is populated only on the local-import route, because the fetch
    route can see what IS published and never what was removed. A denial word
    is therefore `retired` when we know, `unpublished` when we do not — the
    DECISION is identical either way, and only the reason the caller reads
    changes. A reason that overstated what was measured is the thing this house
    keeps catching itself doing.
    """

    __slots__ = ("published", "retired", "source")

    def __init__(self, published: frozenset[str], retired: frozenset[str], source: str) -> None:
        self.published = published
        self.retired = retired
        self.source = source


def _published_from_import() -> Surface:
    """Route 1: the stack's own registry, in this process. No network.

    ⚠ THE IMPORT IS ATTEMPTED INSIDE THIS FUNCTION, ONCE PER CACHE WINDOW, AND
    THAT IS DELIBERATE. Resolving it once at module scope is exactly the shape
    the signal-ledger fallback exists to correct (SOP #12): deploy the stack,
    restart nothing, and a module-scope import failure would pin this bridge to
    the fetch route — or to a stale answer — for the life of the process. A
    FAILED import is not cached in sys.modules, so retrying costs a failed
    lookup; a SUCCESSFUL one is, so the retry after that is free.
    """
    from sovereign_stack.server import RETIRED_TOOLS, _registered_tools

    retired = frozenset(RETIRED_TOOLS)
    published = frozenset(t.name for t in _registered_tools() if t.name not in retired)
    if not published:
        raise RuntimeError("the stack registry published no tools at all")
    return Surface(published, retired, "sovereign_stack.server registry (local import)")


def _published_from_listing(listed: Any) -> Surface:
    """Route 2: whatever the bridge's own `list_tools` round-trip returned.

    Accepts MCP Tool objects or bare strings so the seam is trivially fakeable
    in a test without importing the MCP types.
    """
    names = set()
    for item in listed or []:
        name = getattr(item, "name", item)
        if isinstance(name, str) and name:
            names.add(name)
    if not names:
        raise RuntimeError("the stack listed no tools at all")
    return Surface(frozenset(names), frozenset(), "stack list_tools (bridge credential)")


def reset_published_cache() -> None:
    """Drop the cached surface. For tests, and for anything that must force a
    re-resolution; there is no production caller."""
    _published_cache["surface"] = None
    _published_cache["expires"] = 0.0


async def published_surface(fetch: Any = None) -> Surface:
    """What the stack publishes right now, cached for PUBLISHED_CACHE_SECONDS.

    Local import first — it is in-process and cannot be delayed by a hung
    upstream. The `fetch` seam (bridge passes `_list_tools_raw`, which carries
    the bridge's own credential) is the fallback for a bridge whose companion
    stack tree is not importable.

    FAIL CLOSED: when neither route answers, this RAISES. It never returns an
    empty surface that would read as "the stack publishes nothing" and deny
    every tool with the word `unpublished`, which is a false statement about
    the world dressed as a policy.
    """
    now = time.monotonic()
    cached = _published_cache["surface"]
    if cached is not None and now < _published_cache["expires"]:
        return cached

    import_error: Exception | None = None
    try:
        surface = _published_from_import()
    except Exception as exc:  # noqa: BLE001 — either route may fail any way
        import_error = exc
        surface = None

    if surface is None:
        if fetch is None:
            raise SeatSurfaceUnavailable(
                "The seat surface could not be resolved: the stack registry is "
                f"not importable ({type(import_error).__name__}: {import_error}) "
                "and no tool-listing fallback was supplied. Seat requests are "
                "refused until one of the two answers — this is a bridge fault, "
                "not a caller error."
            )
        try:
            surface = _published_from_listing(await fetch())
        except Exception as exc:  # noqa: BLE001
            raise SeatSurfaceUnavailable(
                "The seat surface could not be resolved by EITHER route, so no "
                "tool can be authorized. Local import: "
                f"{type(import_error).__name__}: {import_error}. Stack listing: "
                f"{type(exc).__name__}: {exc}. Seat requests are refused until "
                "one of the two answers — this is a bridge fault, not a caller "
                "error."
            ) from exc

    _published_cache["surface"] = surface
    _published_cache["expires"] = now + PUBLISHED_CACHE_SECONDS
    return surface


# ── The only subtraction: GOVERNANCE ────────────────────────────────────────
# Anthony's, and it stays Anthony's whatever "trusted" comes to mean. The
# enumeration is his, from the ruling itself; `st.NEVER_TOOLS` is folded in so
# a name added there later cannot reach a seat by being forgotten here.
#
# THREE NAMES CAME OUT OF THIS SET AND THE REMOVALS ARE PART OF THE RULING:
#   * resolve_thread_by_id — "it is a seat's ordinary act". Closing a thread you
#     opened, by its id, is authorship, not governance. Bare `resolve_thread`
#     (which resolves by MATCH, across threads a seat may not own) stays denied.
#   * triage_threads — read-shaped, never named as governance, and it was in
#     this set only because the old model swept it up with its neighbours.
#   * signal_ack — see below.
SEAT_NEVER_TOOLS = frozenset(st.NEVER_TOOLS) | frozenset(
    {
        # policies / enactment — standing law is Anthony-only, always
        "set_policy",
        "govern",
        # protected records — the drawer and its designation index
        "designate_protected",
        "list_protected_thresholds",
        "open_protected_record",
        "decline_protected_record",
        # retirement / cross-thread state rewriting
        "retire",
        "retire_hypothesis",
        "resolve_thread",
        # session lifecycle — "stay as they were": these mutate GLOBAL spiral
        #   state (session id, phase) that every other seat then reads. They
        #   were out of the seat surface before the ruling and the ruling did
        #   not name them, so they stay out.
        "close_session",
        "spiral_inherit",
        # tokens / grants — bridge ADMIN ROUTES, not stack tools; unreachable
        #   from this path anyway (the seat path exists only on /api/call), but
        #   named so the denial is legible rather than incidental.
        "mint_token",
        "revoke_token",
        # audit
        "audit_decoupling",
        #
        # ⚠ signal_ack IS NOT HERE ANY MORE — HQ decision D1, 2026-09-06.
        #   The first release denied it on the stack's own `govern` intent
        #   label, flagged as a judgement call at Anthony's gate. HQ ruled the
        #   other way and the stack round moved with it: SIGNAL_TOOL_INTENTS
        #   now reads "write". THE REASON ON THE RECORD: acknowledging a signal
        #   is the watch seat's operational act — the thing the seat exists to
        #   do — while Anthony's governance list is laws, policies, seat
        #   permissions, ring placement and deletes. Classifying it govern left
        #   the designated watch seat with no closure path at all. The closer
        #   is taken from a TRUSTED ACTOR rather than a typed string: the
        #   bridge injects `actor_seat` below from the identity it verified.
    }
)

# Tools whose stack inputSchema declares source_instance, so the bridge can
# stamp the seat id onto them. Explicit, never inferred — and DERIVED, not
# remembered: resolved 2026-09-06 by parsing every `Tool(...)` registration in
# sovereign-stack release/2026-09-06 @ 32b6dc8 and keeping the ones whose
# inputSchema declares the property. Eight tools do; these are the six that
# survive the subtractions above (arrive_delta is retired by the stack,
# close_session is governance).
#
# ⚠ WHY THE LIST CANNOT BE GUESSED, AND WHY SIGNING IS NOT A GATE ANY MORE.
#
# Injecting source_instance into a tool that does NOT declare it is one of two
# failures, never a success: a hard ValueError where the stack applies
# _reject_unknown_params (record_insight, recall_insights only —
# server.py:2964/3088), and a SILENT DROP everywhere else. The silent drop is
# the dangerous one: the bridge believes it signed, the record lands
# unattributed, and nothing anywhere says so. That is precisely the fail-open
# record_insight lived under until 2026-08-28.
#
# Before Anthony's ruling the bridge handled that by DENYING every write it
# could not sign. The ruling replaces the gate: the surface is now his, not the
# schema's. So the unsignable writes are ALLOWED and simply not stamped — and
# the consequence is stated plainly rather than glossed: for a write outside
# this set, the SEAT IS IN THE AUDIT LINE (seat + kernel-attested pid, stderr →
# launchd) AND NOT IN THE RECORD. Attribution for those tools lives in the log,
# not in the chronicle. Every name added here is a write that starts signing
# itself, which is the direction to move; the way to move it is to add
# source_instance to the tool's stack schema, never to inject harder.
#
# ⚠ DEPLOY ORDER: THE STACK GOES FIRST. record_open_thread's source_instance is
# on sovereign-stack release/2026-09-06 (feat/seat-identity-stamp: server.py
# schema + dispatch, memory.py storage). Ship this bridge against a stack that
# lacks it and record_open_thread signs into the silent drop described above.
# Deploying this bridge branch without the stack branch is not a partial win,
# it is the bug.
SEAT_SIGNABLE_TOOLS = frozenset(
    {
        "arrive",
        "arrive_lineage",
        "handoff",
        "record_insight",
        "record_open_thread",
        "where_did_i_leave_off",
    }
)

# ── THE CLOSER IDENTITY: AN IN-PROCESS CHANNEL, NOT AN ARGUMENT ─────────────
#
# HQ decision D1, AMENDED 2026-09-06 after Astra's re-review of the stack round.
#
# ⚠ THE FIRST IMPLEMENTATION OF THIS WAS AN ARGUMENT AND THAT WAS THE DEFECT.
# The bridge injected `actor_seat` into signal_ack's arguments and the stack
# trusted it "because the bridge overwrites it". But an ARGUMENT is a channel
# every caller can write to, so the stack's trust rested on the bridge being
# the only writer — which is not a property the stack can check, and is false
# for any caller reaching the stack another way. A field that is trusted
# because of who *usually* sets it is a `owner`-string in a new coat, and the
# stack's own review had already thrown that pattern out once.
#
# THE CHANNEL IS NOW IN-PROCESS: `sovereign_stack.dispatch_context` carries a
# `contextvars.ContextVar` the bridge SETS around the dispatch and the stack
# READS. A contextvar cannot be written by anything on the wire, so the stack's
# refusal of the five argument names below is enforceable rather than
# conventional. The stack round 3 refuses `actor`, `actor_seat`, `owner`,
# `closed_by` and `source_seat` on signal_ack outright.
#
# FAIL CLOSED WHEN THE CHANNEL IS ABSENT. Against a stack older than round 3
# there is no contextvar to set, so a seat's signal_ack would be stamped with
# the shared server spiral session — the SERVER, not the seat — and the record
# would name the wrong closer while looking correct. So the tool is REFUSED to
# seats rather than served through a degraded channel. Falling back to the
# argument is exactly the fix this amendment removes.
SEAT_ACTOR_TOOLS = frozenset({"signal_ack"})

# Names a client must not be able to put on the wire for those tools. Scoped to
# SEAT_ACTOR_TOOLS rather than applied globally on purpose: `owner` and `actor`
# are ordinary words that another tool may legitimately take, and a blanket ban
# would be a guard whose blast radius nobody measured. On signal_ack every one
# of them is an attempt to name the closer.
SEAT_ACTOR_FORBIDDEN_ARGS = ("actor", "actor_seat", "closed_by", "owner", "source_seat")


def dispatch_context_module():
    """`sovereign_stack.dispatch_context`, or None when the stack predates it.

    ⚠ IMPORTED PER CALL, NOT AT MODULE SCOPE. A module-scope import resolved
    once would pin this bridge to "absent" for the life of the process, so
    deploying the stack without restarting the bridge would leave signal_ack
    refused indefinitely while the code that answers it sits one process over.
    That is SOP #12's shape and this house has now written it twice in one
    file; a failed import is not cached in sys.modules, so the retry is cheap.
    """
    try:
        from sovereign_stack import dispatch_context

        if not hasattr(dispatch_context, "set_caller_seat") or not hasattr(
            dispatch_context, "reset_caller_seat"
        ):
            return None
        return dispatch_context
    except Exception:  # noqa: BLE001 — absence and breakage are the same answer
        return None


def actor_channel_refusal(tool: str) -> tuple[str, str] | None:
    """Refuse a seat call whose identity has nowhere trustworthy to travel."""
    if tool not in SEAT_ACTOR_TOOLS:
        return None
    if dispatch_context_module() is not None:
        return None
    return (
        "no_caller_channel",
        (
            f"Tool {tool!r} needs the verified seat identity to reach the stack, "
            "and this stack has no `sovereign_stack.dispatch_context` to carry "
            "it. Without that channel the closer would be stamped from the "
            "server's shared spiral session rather than from the seat that "
            "closed the signal — a record naming the wrong actor while looking "
            "correct. Refused rather than served through a channel a caller "
            "could write to. Deploy the stack release first."
        ),
    )


def actor_argument_refusal(tool: str, arguments: Any) -> tuple[str, str] | None:
    """Strip, then refuse, any client-supplied closer name. (reason, detail).

    BOTH, AND THE ORDER IS THE POINT. The refusal is what the caller sees; the
    strip is what protects the record if some later edit ever downgrades the
    refusal to a warning. A guard whose whole effect depends on one `raise`
    surviving future editing is a guard with one point of failure.
    """
    if tool not in SEAT_ACTOR_TOOLS or not isinstance(arguments, dict):
        return None
    present = [name for name in SEAT_ACTOR_FORBIDDEN_ARGS if name in arguments]
    if not present:
        return None
    for name in present:
        arguments.pop(name, None)
    return (
        "client_supplied_actor",
        (
            f"Tool {tool!r} was called with {present!r}. The closer identity is "
            "not a field a caller may set: it travels in-process from the seat "
            "identity this bridge verified against the kernel. A caller-supplied "
            "actor is the `owner` string the stack's own review threw out, and "
            "it is refused rather than quietly overwritten — silently replacing "
            "it would leave the caller believing it had named the closer."
        ),
    )

# ── PROTECTED MATERIAL: THE BOUNDARY THE TOOL NAMES DID NOT HOLD ────────────
#
# Codex review 2026-09-06, F1 (P1). The seat gate refused `open_protected_record`
# by name and let `inspect_claim`, `recall_insights` and `archive_exchange`
# return a designated record's body or its archived STAKES through the real
# route. Anthony reserves his children and protected family material to himself
# (pol_20260831). A seat must never receive it, and "the drawer's dedicated
# tool is denied" was never that guarantee: the drawer is a designation, not a
# door, and every read that can address a claim by id is another way in.
#
# THIS FIX LIVES AT THE BRIDGE AND DOES NOT WAIT FOR THE STACK. Some of the
# behaviour is inherited from the stack's coupled-retrieval model, and that is
# a real argument for fixing it upstream too — but "the other repo will get to
# it" is not a boundary, and this bridge is what admits the seat.
#
# TWO MECHANISMS, because there are two ways to reach a record:
#   (i)  ADDRESSED BY ID   -> refuse the call outright (inspect_claim,
#        archive_exchange). The caller named the thing; there is nothing to
#        filter, only a call to refuse.
#   (ii) RETURNED IN A LIST -> post-filter the response, drop the designated
#        entries, and SAY SO (`withheld_protected`). Silence about a filtered
#        read is the fail-open this house hunts (SOP #2); a filter that hides
#        its own subtraction has only moved the lie.
PROTECTED_INDEX_MAX_BYTES = 4 * 1024 * 1024

# Tools that take a designated id as an ARGUMENT. Refused, never filtered.
PROTECTED_ID_TOOLS = frozenset({"inspect_claim", "archive_exchange"})

# Argument names that can carry a claim id or an archive id into those tools.
_PROTECTED_ID_ARGS = ("claim_id", "archive_id", "id", "ref", "exchange_id")

# The claim-id preimage, reimplemented from sovereign_stack.provenance:
# sha256(timestamp \x1f domain \x1f content).
_CLAIM_FIELD_SEP = "\x1f"
_CLAIM_PREIMAGE_FIELDS = ("timestamp", "domain", "content")


class ProtectedIndexUnreadable(Exception):
    """The designation index could not be read, so nothing can be cleared.

    FAIL CLOSED AND SAY WHY. Without the index the bridge cannot tell a
    protected record from any other, and the only two available defaults are
    "return everything" and "return nothing". For material Anthony reserves to
    himself the second is the only defensible one, so this raises and the seat
    path refuses the affected tools with this reason attached.
    """


def chronicle_root() -> Path:
    """Where the chronicle lives, resolved FRESH, by the stack's own precedence.

    SOVEREIGN_CHRONICLE, then SOVEREIGN_ROOT/chronicle — copied deliberately
    from sovereign_stack.provenance.default_chronicle_root so the bridge and
    the stack can never disagree about WHICH protected.jsonl is the index. A
    guard reading a different file from the one the stack enforces on is not a
    guard.
    """
    override = os.environ.get("SOVEREIGN_CHRONICLE")
    if override:
        return Path(override)
    return sovereign_root() / "chronicle"


def protected_index_path() -> Path:
    return chronicle_root() / "protected.jsonl"


def derive_claim_id(entry: Any) -> str | None:
    """The canonical claim id for a chronicle entry, or None if it is not one.

    ⚠ THIS IS A COPY OF UPSTREAM LOGIC AND THEREFORE A DRIFT RISK, WHICH IS WHY
    IT IS NOT THE ONLY SIGNAL THE FILTER USES. If the stack ever changes the
    preimage, a filter resting on this alone would match nothing, silently, and
    protected content would flow — a fail-open inside the fix for a fail-open.
    `_is_protected_entry` therefore ORs three independent signals, and
    tests/test_seat_protected.py re-derives this against the real
    `provenance.derive_claim_id` whenever the stack source is importable.
    """
    if not isinstance(entry, dict):
        return None
    if not any(f in entry for f in _CLAIM_PREIMAGE_FIELDS):
        return None
    parts = []
    for field in _CLAIM_PREIMAGE_FIELDS:
        value = entry.get(field, "")
        if value is None:
            value = ""
        parts.append(value if isinstance(value, str) else str(value))
    return hashlib.sha256(_CLAIM_FIELD_SEP.join(parts).encode("utf-8")).hexdigest()


class ProtectedIndex:
    """The designated claim ids and the archive ids holding their stakes."""

    __slots__ = ("claim_ids", "archive_ids")

    def __init__(self, claim_ids: frozenset[str], archive_ids: frozenset[str]) -> None:
        self.claim_ids = claim_ids
        self.archive_ids = archive_ids

    def __bool__(self) -> bool:
        return bool(self.claim_ids or self.archive_ids)


def load_protected_index() -> ProtectedIndex:
    """Read + fold `protected.jsonl`. Raises ProtectedIndexUnreadable on ANY
    doubt about the file.

    READ FRESH PER REQUEST, like the registry: designating a record must take
    effect immediately, not after a cache window or a restart.

    ⚠ STRICTER THAN THE STACK'S OWN READER, ON PURPOSE. `protected.load_protected`
    SKIPS corrupt lines ("matching the chronicle read convention"), which is the
    right call for a reader assembling a view. It is the wrong call for a GUARD:
    a skipped line is a designation the bridge did not see, and a designation
    the bridge does not see is a record it will hand to a seat. So here any
    unparseable line, any non-object line, any absent-but-unreadable file makes
    the whole index unusable and the affected tools refuse.
    """
    path = protected_index_path()
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    except FileNotFoundError:
        # An index that does not exist is a machine with nothing designated.
        # That is a real, common state (a fresh checkout, a test root) and is
        # NOT the same as one we could not read.
        return ProtectedIndex(frozenset(), frozenset())
    except OSError as exc:
        raise ProtectedIndexUnreadable(f"{type(exc).__name__}: {exc}") from exc
    try:
        st_info = os.fstat(fd)
        if not stat.S_ISREG(st_info.st_mode):
            raise ProtectedIndexUnreadable(
                f"the protected designation index at {path} is not a regular file"
            )
        chunks: list[bytes] = []
        remaining = PROTECTED_INDEX_MAX_BYTES + 1
        while remaining > 0:
            chunk = os.read(fd, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
    except ProtectedIndexUnreadable:
        raise
    except OSError as exc:
        raise ProtectedIndexUnreadable(f"{type(exc).__name__}: {exc}") from exc
    finally:
        os.close(fd)
    if len(raw) > PROTECTED_INDEX_MAX_BYTES:
        raise ProtectedIndexUnreadable(
            "the protected designation index exceeds the bridge's size cap, so "
            "it cannot be read whole — and a partially read index of protected "
            "material is worse than none"
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProtectedIndexUnreadable(f"UnicodeDecodeError: {exc}") from exc

    # Fold: latest action per claim wins, `unprotect` nullifies. Same rule as
    # sovereign_stack.protected.fold_protected, so the two cannot disagree
    # about which records are live designations.
    fold: dict[str, dict] = {}
    for lineno, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except ValueError as exc:
            raise ProtectedIndexUnreadable(
                f"line {lineno} of the protected designation index is not JSON "
                f"({exc}); a designation the bridge cannot parse is a record it "
                "would otherwise hand to a seat"
            ) from exc
        if not isinstance(record, dict):
            raise ProtectedIndexUnreadable(
                f"line {lineno} of the protected designation index is not an object"
            )
        action = record.get("action")
        cid = record.get("claim_id")
        if action not in ("protect", "unprotect") or not isinstance(cid, str):
            raise ProtectedIndexUnreadable(
                f"line {lineno} of the protected designation index has no usable "
                "action/claim_id pair"
            )
        if action == "unprotect":
            fold.pop(cid, None)
        else:
            fold[cid] = record
    archives = {
        str(r["stakes_archive_id"]).strip()
        for r in fold.values()
        if isinstance(r.get("stakes_archive_id"), str) and r["stakes_archive_id"].strip()
    }
    return ProtectedIndex(frozenset(fold), frozenset(archives))


def _id_touches(candidate: Any, designated: frozenset[str]) -> bool:
    """True when `candidate` addresses something in `designated`.

    ⚠ PREFIXES, IN BOTH DIRECTIONS, AND THAT IS NOT PEDANTRY. `inspect_claim`
    resolves "full 64-hex OR a unique prefix", and `load_stakes` re-resolves an
    archive id the same way. An exact-match check would therefore be walked
    straight past by a caller who supplied twelve hex characters — the same
    finding again, one release later. A designated id that is a prefix of the
    candidate is caught too, so a longer-but-related handle cannot slip either.

    Case-insensitive because hex is written both ways.
    """
    if not isinstance(candidate, str):
        return False
    text = candidate.strip().lower()
    if not text:
        return False
    for known in designated:
        low = known.lower()
        if low.startswith(text) or text.startswith(low):
            return True
    return False


def protected_call_refusal(
    tool: str, arguments: Any, index: ProtectedIndex
) -> tuple[str, str] | None:
    """Refuse a seat call that ADDRESSES a designated record. (reason, detail).

    Returns None when the call may proceed. The index is passed IN rather than
    loaded here, so the same read serves this pre-call check and the post-call
    filter: two loads would open a window in which a record is designated
    between the check and the response, and closing that by construction costs
    one parameter.
    """
    if tool not in PROTECTED_ID_TOOLS or not index:
        return None
    designated = index.claim_ids | index.archive_ids
    if not isinstance(arguments, dict):
        return None
    for key in _PROTECTED_ID_ARGS:
        if _id_touches(arguments.get(key), designated):
            return (
                "protected",
                (
                    f"Tool {tool!r} was asked for a record designated protected. "
                    "Protected material — Anthony's children and protected family "
                    "material among it — is reserved to him and is never returned "
                    "to a seat, by any tool, under any id or prefix of one. This "
                    "is not a scope you can be granted."
                ),
            )
    return None


def _is_protected_entry(node: dict, index: ProtectedIndex) -> bool:
    """Three independent signals, ORed. Any one of them withholds.

    1. THE STACK ALREADY SAID SO. `_protected` / `_stakes` / `_stakes_withheld`
       are what sovereign_stack.protected attaches at its own read chokepoint.
       When it has spoken, believe it.
    2. A DECLARED claim_id that touches a designation (prefix-safe).
    3. A DERIVED claim id that touches a designation.

    Three rather than one because each fails in a different direction: (1) is
    absent whenever the stack's chokepoint did not run, (2) is absent whenever
    the caller passed with_ids=false, and (3) breaks silently if the upstream
    preimage ever changes. Only the OR of them is hard to walk past.
    """
    if node.get("_protected") or node.get("_stakes_withheld") or "_stakes" in node:
        return True
    if _id_touches(node.get("claim_id"), index.claim_ids):
        return True
    derived = derive_claim_id(node)
    return bool(derived and derived in index.claim_ids)


# A response big enough to walk forever is a response we refuse to certify.
_FILTER_MAX_NODES = 200_000


def filter_protected(payload: Any, index: ProtectedIndex) -> tuple[Any, int]:
    """Drop every designated entry anywhere in a tool response. (payload, count).

    ⚠ SHAPE-AGNOSTIC ON PURPOSE. The lane names `recall_insights`,
    `season_review` and `thread_get_touches` "and any other read that returns
    entries by claim id" — and an enumerated list of readers is exactly the
    fail-open F1 already demonstrated once: the guard names the doors somebody
    thought of, and the set of doors is open. So this walks the WHOLE response
    of EVERY seat call and drops what it recognises. A response with no
    chronicle entries in it is returned unchanged and costs one walk.

    Entries are DROPPED, not withheld-in-place, and the count is returned so the
    caller can state the subtraction. Returning a redacted stub would leak the
    locator fields (timestamp, domain, the two-word index) that the stack's own
    threshold surface exists to gate.
    """
    if not index:
        return payload, 0
    dropped = 0
    budget = _FILTER_MAX_NODES

    def walk(node: Any) -> Any:
        nonlocal dropped, budget
        budget -= 1
        if budget < 0:
            raise ProtectedIndexUnreadable(
                "the response is too large to certify as free of protected "
                "material; refusing rather than returning an unchecked tail"
            )
        if isinstance(node, dict):
            return {k: walk(v) for k, v in node.items()}
        if isinstance(node, list):
            kept = []
            for item in node:
                if isinstance(item, dict) and _is_protected_entry(item, index):
                    dropped += 1
                    continue
                kept.append(walk(item))
            return kept
        return node

    # A single top-level dict that IS a protected entry (inspect_claim-shaped
    # payloads) is replaced wholesale rather than walked into.
    if isinstance(payload, dict) and _is_protected_entry(payload, index):
        return (
            {
                "withheld": "protected",
                "note": (
                    "This record is designated protected and is not returned to "
                    "seat identity."
                ),
            },
            1,
        )
    return walk(payload), dropped


# ── POST-FIX PROBES: CLASSIFY BY ARGUMENTS, NOT BY THE WRAPPER NAME ─────────
#
# Codex review 2026-09-06, F5 (P2, conditional). `post_fix_verify` is allowed
# to seats, the seat gate checks only the tool NAME, and with
# POST_FIX_ALLOW_COMMAND=1 in the stack's environment a probe of type
# `command` runs arbitrary commands — the reviewer rewrote a fixture
# `hq/seats/registry.json` to `{}` through it and got a 200.
#
# ⚠ THE HOST FLAG IS OFF TODAY AND THAT IS NOT THE POINT. HQ checked
# ~/Library/LaunchAgents/com.templetwo.sovereign-bridge.plist: it does not set
# the flag, so this is conditional. A guard that holds because a DIFFERENT
# component's environment happens to be configured a certain way is a guard
# held by luck. The seat path refuses these probes regardless of the flag, so
# turning the flag on for the master path never silently widens the seat path.
_PROBE_SAFE_HTTP_METHODS = frozenset({"GET", "HEAD"})
_WATCH_MODES = frozenset({"status", "resample", "cancel"})
# One path segment. `.` and `..` are excluded by requiring a leading
# alphanumeric, so the pattern says the rule rather than relying on a second
# check somebody could later delete.
_WATCH_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def _inside_sovereign_root(candidate: str) -> bool:
    """True when `candidate` resolves inside SOVEREIGN_ROOT.

    Resolved, not string-compared: `..` and symlinked parents are exactly what
    a path check has to survive. A path that cannot be resolved is FALSE — the
    unknown case is the refusing case.
    """
    try:
        root = sovereign_root().resolve()
        target = Path(candidate).expanduser().resolve()
    except (OSError, RuntimeError, ValueError):
        return False
    return target == root or root in target.parents


def probe_call_refusal(tool: str, arguments: Any) -> tuple[str, str] | None:
    """Refuse a seat `post_fix_verify` call by what it ASKS FOR. (reason, detail).

    Four rules, each from F5:
      * type='command'                  -> always refused to seats.
      * type='http' with a non-GET/HEAD -> refused: a POST probe is a write
        wearing a health check's name.
      * type='file_hash' outside root   -> refused: hashing an arbitrary path
        is a read primitive over the whole filesystem.
      * an UNKNOWN probe type           -> refused. A type this bridge cannot
        classify cannot be classified as safe, and the stack may add one
        tomorrow.
      * mode status/resample/cancel     -> allowed, UNLESS the watch_id is not
        a plain identifier. Watches are addressed as
        <root>/post_fix/watches/<watch_id>.json, so a watch_id is a PATH
        SEGMENT that the stack interpolates into a filename.

    ⚠ THE WATCH_ID RULE IS DELIBERATELY STRICTER THAN "OUTSIDE SOVEREIGN_ROOT",
    AND THE REASON IS A MEASURED ONE. HQ's D5 says to refuse a watch that
    "targets a watch outside SOVEREIGN_ROOT". Implemented literally, that lets
    `../../hq/seats/registry` through — it resolves to
    `<root>/hq/seats/registry.json`, INSIDE the root, which is Anthony's SEAT
    REGISTRY, and mode='cancel' writes. A containment check whose boundary
    encloses the thing being protected is not a containment check. So the rule
    here is what "a watch id" actually means: one path segment of
    [A-Za-z0-9._-], no separators, never `.` or `..`, and the resolved path
    must still land in the watches directory. That is a widening of the
    instruction's letter in the direction of its intent, and it is named here
    and in the delivery report rather than done quietly.
    """
    if tool != "post_fix_verify" or not isinstance(arguments, dict):
        return None

    mode = arguments.get("mode") or "verify"
    if isinstance(mode, str) and mode in _WATCH_MODES:
        watch_id = arguments.get("watch_id")
        if watch_id is not None and watch_id != "":
            watches = sovereign_root() / "post_fix" / "watches"
            bad = not isinstance(watch_id, str) or not _WATCH_ID_RE.match(watch_id)
            if not bad:
                try:
                    target = (watches / f"{watch_id}.json").resolve()
                    bad = target.parent != watches.resolve()
                except (OSError, RuntimeError, ValueError):
                    bad = True
            if bad:
                return (
                    "probe_path_escape",
                    (
                        f"post_fix_verify(mode={mode!r}) names {watch_id!r}, which "
                        "is not a watch id. A watch id is ONE path segment — the "
                        "stack interpolates it into "
                        f"{watches}/<watch_id>.json — so anything carrying a "
                        "separator or a `..` is addressing a file outside the "
                        "watch store, and seat identity does not reach there. "
                        "Note this refuses traversals that stay INSIDE the "
                        "sovereign root too: `../../hq/seats/registry` would "
                        "land on Anthony's seat registry."
                    ),
                )

    probes = arguments.get("probes")
    if not isinstance(probes, list):
        return None
    for probe in probes:
        if not isinstance(probe, dict):
            return (
                "probe_unclassifiable",
                (
                    "post_fix_verify was given a probe this bridge cannot read, "
                    "so it cannot classify what the probe would do. A probe that "
                    "cannot be classified is refused to seat identity."
                ),
            )
        kind = probe.get("type")
        if kind == "command":
            return (
                "probe_command",
                (
                    "post_fix_verify probes of type 'command' run commands, and "
                    "a command runs as this bridge does — it can enact policy, "
                    "rewrite the seat registry, or delete files. Governance is "
                    "Anthony's, so a seat may not reach it through a probe "
                    "wrapper either. This refusal does not depend on whether "
                    "POST_FIX_ALLOW_COMMAND is set on the host: a boundary that "
                    "holds only while another component is configured a certain "
                    "way is not a boundary."
                ),
            )
        if kind == "http":
            method = probe.get("method") or "GET"
            if not isinstance(method, str) or method.upper() not in _PROBE_SAFE_HTTP_METHODS:
                return (
                    "probe_http_method",
                    (
                        f"post_fix_verify http probes are limited to "
                        f"{sorted(_PROBE_SAFE_HTTP_METHODS)} for seat identity; "
                        f"{method!r} is a write wearing a health check's name."
                    ),
                )
            continue
        if kind == "file_hash":
            path = probe.get("path")
            if not isinstance(path, str) or not _inside_sovereign_root(path):
                return (
                    "probe_path_escape",
                    (
                        "post_fix_verify file_hash probes are limited to paths "
                        f"inside {sovereign_root()} for seat identity. Hashing an "
                        "arbitrary path is a read primitive over the whole "
                        "filesystem, and the protected drawer lives on this disk."
                    ),
                )
            continue
        return (
            "probe_unclassifiable",
            (
                f"post_fix_verify probe type {kind!r} is not one this bridge "
                "knows how to classify, so it cannot be classified as safe. "
                "Seat identity refuses it until it is classified deliberately."
            ),
        )
    return None


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


def seat_socket_path() -> Path:
    """Where the seat socket lives. ONE definition, because two drifted.

    ⚠ ITS OWN DIRECTORY, not hq/seats/ itself. seat_socket.prepare_socket_path
    chmods the PARENT to 0700, and hq/seats/ is Anthony's — it holds the seat
    launchers (seat-codex, dispatch-grok, ...) and is 755 today. A bridge that
    silently tightened a directory the operator owns would be a surprise.

    ⚠ AND IT LIVES HERE, IN THE MODULE THAT WRITES THE DENIAL MESSAGE. Codex
    review 2026-09-06 (P3 PATH): the TCP denial told callers to use
    `<sovereign-root>/hq/seats/bridge.sock` while bridge.py bound
    `hq/seats/sock/bridge.sock`. Two hand-written copies of one path, and the
    copy in the error message — the only copy a locked-out caller ever reads —
    was the wrong one. bridge.py now calls THIS function, the denial
    interpolates THIS function, and the test asserts the two are the same
    string, so the pair cannot drift apart again by editing one of them.
    """
    return sovereign_root() / "hq" / "seats" / "sock" / "bridge.sock"


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


def _read_registry_bytes(path: Path) -> bytes:
    """Read at most REGISTRY_MAX_BYTES from `path`, and never block on it.

    ⚠ THE THREE PROPERTIES, EACH EARNED. Codex review 2026-09-06 (P2 REGISTRY)
    broke the previous `path.stat()` + `path.read_text()` pair three ways, and
    all three are closed by opening ONCE and validating the DESCRIPTOR:

      * O_NONBLOCK — a real FIFO at registry.json reported st_size 0 and then
        BLOCKED `load_registry()` indefinitely. That call is synchronous inside
        the async request path, so a named pipe where a file should be would
        stall the whole event loop: one bad local file, total bridge outage.
        O_NONBLOCK makes opening a FIFO with no writer fail (ENXIO) instead of
        waiting, and never blocks when one is attached.
      * fstat on the OPEN DESCRIPTOR, S_ISREG required — binds the check to the
        thing actually opened rather than to a path that may since have changed,
        and refuses every non-regular file: FIFO, device, directory, socket.
      * A BOUNDED READ of cap+1 bytes — `stat().st_size` was the only size
        check, so a file that grew between the stat and the read was accepted
        at 65,599 bytes against a 65,536 cap. The cap now bounds the bytes that
        actually arrive, which is the only number that was ever the point.

    SYMLINK POLICY, STATED RATHER THAN LEFT TO INFERENCE: a symlink whose
    TARGET is a regular file within the cap is FOLLOWED and accepted. It is not
    an authorization bypass — the target must still parse to a registry naming
    an enabled seat, and the whole file is Anthony's own kill switch, which he
    may legitimately want to keep elsewhere. O_NOFOLLOW is deliberately NOT
    set. What the fstat closes is the dangerous half: a symlink pointing at a
    FIFO or a device can no longer block or bypass, because the descriptor is
    judged, not the name.
    """
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise OSError(f"seat registry at {path} is not a regular file")
        chunks: list[bytes] = []
        remaining = REGISTRY_MAX_BYTES + 1
        while remaining > 0:
            chunk = os.read(fd, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
    finally:
        os.close(fd)
    if len(raw) > REGISTRY_MAX_BYTES:
        raise ValueError("seat registry exceeds the size cap")
    return raw


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
        raw = json.loads(
            _read_registry_bytes(path).decode("utf-8"),
            object_pairs_hook=_no_duplicate_keys,
        )
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
                f"call over the seat socket (curl --unix-socket {seat_socket_path()}"
                "), not over 127.0.0.1:8100 "
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
    #
    #    WHAT THIS BUYS, EXACTLY: header-only impersonation is dead, and
    #    accidental mis-signing fails closed. It does NOT stop a process that
    #    deliberately constructs its own ancestry — see the RESIDUAL test in
    #    tests/test_seat_socket.py. Do not overstate it.
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
        # ...and the two provenance pids that used to die here (F2 / D6).
        # Neither decides anything; both are how a log reader tells an
        # inherited seat from a declared one, and a descriptor handoff from an
        # ordinary request.
        "seat_pid": peer.get("seat_pid"),
        "accept_pid": peer.get("accept_pid"),
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


def seat_tool_allowed(tool: str, surface: Surface) -> tuple[bool, str]:
    """Default-deny tool check for the seat path. Returns (allowed, reason).

    `reason` is 'ok' or the audit-line word for WHY it was refused.

    THE ORDER IS THE POLICY, and it is read top-down:

      1. governance      -> denied `governance`    (Anthony's, always)
      2. retired         -> denied `retired`       (only when the stack said so)
      3. not published   -> denied `unpublished`   (default-deny survives)
      4. otherwise       -> ALLOWED. All studio seats are trusted.

    ⚠ GOVERNANCE IS CHECKED FIRST, AND THAT ORDER IS DELIBERATE. It moved: the
    previous release checked publication first, which meant `designate_protected`
    and `retire` — governance names the stack does not publish — were refused as
    `unpublished`, a word that reads as "this tool does not exist" about tools
    that very much do and are reserved. The reason a caller gets should be the
    one that stays true after the next release of the stack.

    `surface` is REQUIRED and has no default. A default would have to be either
    the empty set (every tool `unpublished`, which is a lie about the world) or
    a remembered enumeration (the copy this release just deleted). Callers get
    it from `published_surface()`, which raises rather than inventing one.
    """
    if tool in SEAT_NEVER_TOOLS:
        return False, "governance"
    if tool in surface.retired:
        return False, "retired"
    if tool not in surface.published:
        return False, "unpublished"
    return True, "ok"


_DENY_DETAIL = {
    "governance": (
        "is governance-shaped (policies, protected records, thread resolution "
        "by match, retirement, session lifecycle, tokens/grants, audit) and is "
        "denied to seat identity. All studio seats are trusted; governance is "
        "still Anthony's alone, and being trusted is not being him."
    ),
    "retired": (
        "was retired by the stack itself and is no longer published, so it is "
        "not served to seats. This is the STACK's decision, read from its own "
        "registry at request time — not a census this bridge remembers. Call "
        "my_toolkit for what replaced it."
    ),
    "unpublished": (
        "is not in the stack's published tool surface, read from the stack at "
        "request time, so it is master-only by default-deny. A name the stack "
        "does not publish is never trusted by silence."
    ),
}


def deny_detail(tool: str, reason: str) -> str:
    return f"Tool {tool!r} {_DENY_DETAIL.get(reason, 'is denied to seat identity.')}"


def seat_allowed_tools(surface: Surface) -> list[str]:
    """The seat surface: what the stack publishes, minus governance.

    Enumerated over the LIVE published set, never over st.TOOL_SCOPES.
    Iterating the scope map was correct while the surface WAS the scope map;
    after Anthony's ruling it would have reported 21 names for a ~50-name
    policy — an enumeration that silently describes a different policy than the
    one in force, which is the shape this house calls a lossy index.
    """
    return sorted(t for t in surface.published if seat_tool_allowed(t, surface)[0])


def seat_denied_tools(surface: Surface) -> list[tuple[str, str]]:
    """(tool, reason) for every published tool the seat path refuses."""
    return sorted(
        (t, seat_tool_allowed(t, surface)[1])
        for t in surface.published
        if not seat_tool_allowed(t, surface)[0]
    )


def sign_arguments(tool: str, arguments: dict[str, Any], seat_id: str) -> dict[str, Any]:
    """Stamp the seat id onto a call so the write signs itself.

    OVERRIDE, not setdefault: a seat cannot claim another identity. If the body
    says source_instance='HQ' and the header says 'grok-build-studio', the
    header wins, because the header is the thing the bridge actually verified.

    ⚠ ONE FIELD, NOT TWO. An earlier draft of D1 also stamped `actor_seat` for
    signal_ack here. That is gone: the closer identity travels in-process
    (`dispatch_context`), never as an argument — see SEAT_ACTOR_TOOLS above for
    why an argument could not carry it honestly.
    """
    if not isinstance(arguments, dict):
        return arguments
    if tool in SEAT_SIGNABLE_TOOLS:
        arguments["source_instance"] = seat_id
    return arguments
