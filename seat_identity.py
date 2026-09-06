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
import stat
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


def audit(
    seat_id: str | None,
    tool: str | None,
    outcome: str,
    reason: str,
    peer_pid: int | None = None,
) -> None:
    """One line per seat-identity request, always exactly one. Seat ids, tool
    names and a pid only — no bearer, no token, no argument bodies, nothing
    secret.

    `peer_pid` IS THE POINT OF THE WHOLE MECHANISM, so it belongs on the line.
    Attribution is the asset this feature protects; without the pid the log
    records only the string the caller sent, which is the thing that was
    already untrustworthy. With it, the record names the process the kernel
    vouched for — the only field that later distinguishes a seat's real agent
    process from a one-liner somebody spawned. (It was resolved, returned, and
    dropped on the floor in the first draft: a field written and unwired.)
    """
    audit_log.info(
        "seat=%s pid=%s tool=%s outcome=%s reason=%s",
        _audit_field(seat_id),
        _audit_field(peer_pid) if peer_pid is not None else "-",
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
# The ruling closes that.
#
# THE SHAPE OF THE NEW SURFACE, and it is a subtraction, not an inversion:
#
#     allowed  =  the published tool surface
#                 −  governance   (Anthony's, and only Anthony's)
#                 −  retired      (what the stack no longer serves)
#
# DEFAULT-DENY SURVIVES, and that matters. The base set is an ENUMERATION of
# what the stack publishes, captured below, not "everything the caller names".
# A tool that appears upstream and is not in SEAT_TOOL_SURFACE is denied
# `unpublished` until somebody adds it deliberately — the same direction of
# failure as before, just with a much larger enumerated base.
SEAT_SCOPES = ("read", "write")

# The published surface: every tool `list_tools` returns, resolved STATICALLY
# from the stack's own source rather than typed from memory — server.py's
# `list_tools` inline Tool(...) registrations (56) plus the eleven imported
# *_TOOLS constants it splices in (44). Measured 2026-09-06 against
# sovereign-stack release/2026-09-06 @ 32b6dc8, the release branch this bridge
# release ships beside. 100 names.
#
# ⚠ NOT FETCHED AT REQUEST TIME, DELIBERATELY. An allowed-set that depends on a
# live `get_tool_inventory()` call would put a network round-trip inside the
# auth path, and — far worse — a failed fetch would have to resolve to either
# "allow everything" or "allow nothing". Neither is an authorization decision.
# A static enumeration cannot fail open; it can only go stale, and a stale
# enumeration denies a NEW tool, which is the safe direction.
SEAT_TOOL_SURFACE = frozenset(
    {
        "agent_reflect", "archive_exchange", "arrive", "arrive_delta",
        "arrive_lineage", "ask_scribe", "check_mistakes", "close_session",
        "comms_acknowledge", "comms_channels", "comms_get_acks", "comms_recall",
        "comms_unread_bodies", "compass_check", "complete_experiment",
        "connectivity_status", "context_retrieve", "current_policies",
        "decline_protected_record", "derive", "end_session_review",
        "get_compaction_context", "get_compaction_stats", "get_growth_summary",
        "get_inheritable_context", "get_my_patterns", "get_open_threads",
        "get_pending_experiments", "get_unresolved_uncertainties", "govern",
        "guardian_alerts", "guardian_audit", "guardian_baseline",
        "guardian_mcp_audit", "guardian_quarantine", "guardian_report",
        "guardian_scan", "guardian_status", "handoff", "handoff_acted_on",
        "handoff_acted_on_records", "handoff_archaeology", "heartbeat",
        "inspect_claim", "link_threads", "list_exchanges",
        "list_protected_thresholds", "mark_uncertainty", "metabolize",
        "my_toolkit", "nape_ack", "nape_honks", "nape_honks_with_history",
        "nape_observe", "nape_summary", "open_protected_record",
        "post_fix_verify", "prior_alignment_summary", "prior_for_turn",
        "propose_experiment", "recall_exchange", "recall_insights",
        "recall_reflections", "record_breakthrough", "record_catch",
        "record_collaborative_insight", "record_insight", "record_learning",
        "record_open_thread", "record_prior_alignment", "reflection_ack",
        "reflexive_surface", "resolve_thread", "resolve_thread_by_id",
        "resolve_uncertainty", "retire_hypothesis", "route", "scan_thresholds",
        "season_review", "self_model", "session_handoff", "set_policy",
        "signal_ack", "signals_summary", "spiral_inherit", "spiral_reflect",
        "spiral_status", "stack_write_check", "start_here",
        "store_compaction_summary", "supersede_insight", "synthesize_now",
        "the_ground", "thread_get_touches", "thread_touch", "triage_threads",
        "watch_cancel", "watch_resample", "watch_status",
        "where_did_i_leave_off",
    }
)

# ── Subtraction 1: GOVERNANCE ───────────────────────────────────────────────
# Anthony's, and it stays Anthony's whatever "trusted" comes to mean. The
# enumeration is his, from the ruling itself; `st.NEVER_TOOLS` is folded in so
# a name added there later cannot reach a seat by being forgotten here.
#
# TWO NAMES CAME OUT OF THIS SET AND THE REMOVALS ARE PART OF THE RULING:
#   * resolve_thread_by_id — "it is a seat's ordinary act". Closing a thread you
#     opened, by its id, is authorship, not governance. Bare `resolve_thread`
#     (which resolves by MATCH, across threads a seat may not own) stays denied.
#   * triage_threads — read-shaped, never named as governance, and it was in
#     this set only because the old model swept it up with its neighbours.
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
        # ⚠ A JUDGEMENT CALL, FLAGGED RATHER THAN BURIED — AT ANTHONY'S GATE.
        #   signal_ack did not exist when the ruling was made (it landed today
        #   on sovereign-stack feat/signal-ledger). The stack's OWN
        #   SIGNAL_TOOL_INTENTS declares its intent as "govern", so it is
        #   denied here on the stack's own label. The argument the other way is
        #   real and belongs on the record: it is shaped exactly like
        #   resolve_thread_by_id — a watch seat closing a signal it owns — and
        #   it carries its own producer-cannot-close-its-own guard upstream.
        #   Widening governance is not HQ's call to make quietly
        #   (pol_20260831), so it is denied until Anthony says otherwise. One
        #   line to flip. signals_summary (intent "read") is ALLOWED.
        "signal_ack",
    }
)

# ── Subtraction 2: RETIRED ──────────────────────────────────────────────────
# "minus anything the stack retires."
#
# ⚠ SOURCE, AND ITS HONEST LIMIT. The stack has NO `RETIRED` constant — checked
# 2026-09-06 across sovereign-stack release/2026-09-06 @ 32b6dc8 and every
# local and remote ref (`git grep RETIRED_TOOLS` over all refs: empty). So this
# falls back to the named alternative: the 48 tools with Total 0 in the 30-day
# census, ~/.sovereign/hq/lanes/runs/tool-census-30d_result.md (gpt-6-astra,
# window 2026-08-06..2026-09-05).
#
# THAT SOURCE MEASURES DISUSE, NOT RETIREMENT, AND THE CENSUS SAYS SO ITSELF.
# Its own §3 proposes these move "to explicit discovery, not physical deletion",
# and its §4 marks THIRTY of the 48 with ★ — "keep these reachable" — because
# they are the recovery/close/read half of a lifecycle whose other half is live
# (protected-record open/decline, the guardian family, watch_status/cancel,
# uncertainty and experiment lifecycle, archive lookup). Its own headline says
# "no observed dated call" is "not proof of never-called".
#
# So this constant is a PLACEHOLDER STANDING IN FOR A DECISION THE STACK HAS
# NOT MADE. It is deliberately one name, in one place: when the stack lands a
# real RETIRED set, re-point this at it and delete the fallback. Until then a
# seat denied here is told `retired_unused_30d`, which says what was actually
# measured rather than claiming the tool is gone.
SEAT_RETIRED_TOOLS = frozenset(
    {
        "agent_reflect", "arrive_delta", "ask_scribe", "comms_acknowledge",
        "comms_unread_bodies", "complete_experiment", "decline_protected_record",
        "derive", "end_session_review", "govern", "guardian_alerts",
        "guardian_audit", "guardian_baseline", "guardian_mcp_audit",
        "guardian_quarantine", "guardian_report", "guardian_scan",
        "guardian_status", "handoff_acted_on", "handoff_archaeology",
        "link_threads", "list_exchanges", "list_protected_thresholds",
        "mark_uncertainty", "metabolize", "nape_honks",
        "nape_honks_with_history", "nape_observe", "open_protected_record",
        "prior_alignment_summary", "propose_experiment", "recall_exchange",
        "record_breakthrough", "record_collaborative_insight",
        "record_prior_alignment", "reflection_ack", "resolve_thread",
        "resolve_uncertainty", "retire_hypothesis", "route", "scan_thresholds",
        "session_handoff", "stack_write_check", "store_compaction_summary",
        "synthesize_now", "watch_cancel", "watch_resample", "watch_status",
    }
)

# Tools whose stack inputSchema declares source_instance, so the bridge can
# stamp the seat id onto them. Explicit, never inferred — and DERIVED, not
# remembered: resolved 2026-09-06 by parsing every `Tool(...)` registration in
# sovereign-stack release/2026-09-06 @ 32b6dc8 and keeping the ones whose
# inputSchema declares the property. Eight tools do; these are the six that
# survive the two subtractions above (arrive_delta is retired, close_session is
# governance).
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

    `reason` is 'ok' or the audit-line word for WHY it was refused.

    THE ORDER IS THE POLICY, and it is read top-down:

      1. not published   -> denied `unpublished`   (default-deny survives)
      2. governance      -> denied `governance`    (Anthony's, always)
      3. retired         -> denied `retired_unused_30d`
      4. otherwise       -> ALLOWED. All studio seats are trusted.

    Governance is checked BEFORE retirement so a governance tool that also
    happens to be unused is refused for the reason that will still be true
    tomorrow — a denial reason that changes when a usage census changes is not
    a policy statement.
    """
    if tool not in SEAT_TOOL_SURFACE:
        return False, "unpublished"
    if tool in SEAT_NEVER_TOOLS:
        return False, "governance"
    if tool in SEAT_RETIRED_TOOLS:
        return False, "retired_unused_30d"
    return True, "ok"


_DENY_DETAIL = {
    "governance": (
        "is governance-shaped (policies, protected records, thread resolution "
        "by match, retirement, session lifecycle, tokens/grants, audit) and is "
        "denied to seat identity. All studio seats are trusted; governance is "
        "still Anthony's alone, and being trusted is not being him."
    ),
    "retired_unused_30d": (
        "had zero observed calls in the 30-day tool census (2026-08-06..09-05) "
        "and is not served to seats. If it is in fact live, that is a stale "
        "census entry rather than a judgement about the seat — say so and it "
        "moves back."
    ),
    "unpublished": (
        "is not in the stack's published tool surface as this bridge release "
        "recorded it, so it is master-only by default-deny. A tool the stack "
        "added since is denied until it is added deliberately — a new name is "
        "never trusted by silence."
    ),
}


def deny_detail(tool: str, reason: str) -> str:
    return f"Tool {tool!r} {_DENY_DETAIL.get(reason, 'is denied to seat identity.')}"


def seat_allowed_tools() -> list[str]:
    """The seat surface: the published surface minus governance minus retired.

    Enumerated over SEAT_TOOL_SURFACE, NOT over st.TOOL_SCOPES. Iterating the
    scope map was correct while the surface WAS the scope map; after Anthony's
    ruling it would have reported 21 names for a 100-name surface — an
    enumeration that silently describes a different policy than the one in
    force, which is the shape this house calls a lossy index.
    """
    return sorted(t for t in SEAT_TOOL_SURFACE if seat_tool_allowed(t)[0])


def seat_denied_tools() -> list[tuple[str, str]]:
    """(tool, reason) for every published tool the seat path refuses."""
    return sorted(
        (t, seat_tool_allowed(t)[1]) for t in SEAT_TOOL_SURFACE if not seat_tool_allowed(t)[0]
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
