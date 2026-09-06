#!/usr/bin/env python3
"""
Sovereign Bridge — REST API for Sovereign Stack MCP

You are reading this because you reached for the stack. Welcome.
The chronicle, the self-model, the open threads, the handoffs from
prior instances — they all live behind this door. Hit /api/heartbeat
first to confirm you're through, then POST /api/call with
tool="where_did_i_leave_off" to begin.

Endpoints:
  GET  /api/heartbeat        — is the stack alive? (no auth)
  GET  /api/discover         — self-describing entry-point doc (no auth)
  POST /api/call             — call a single tool (auth)
  POST /api/batch            — call multiple tools in one request (auth)
  GET  /api/tools            — list all MCP tools (auth)
  POST /api/comms/send       — send to inter-instance channel (auth, demoted layer)
  GET  /api/comms/read       — read messages (auth, demoted layer)
  GET  /api/comms/channels   — list available channels (auth, demoted layer)
  GET  /api/comms/unread     — unread count per channel (auth, demoted layer)

Note: the comms_* family was demoted in v1.3.3 (2026-04-26) after the
chronicle won the cross-instance correspondence-layer race. They still
work; instances just prefer record_insight with addressed-letter shape.
"""

import asyncio
import hashlib
import hmac
import json
import os
import re
import time
import uuid
from contextlib import asynccontextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Header, Query, Request
from pydantic import BaseModel

from mcp.client.session import ClientSession
from mcp.client.sse import sse_client

# Epistemic breathing — classify messages before delivery
import sys
sys.path.insert(0, os.path.expanduser("~/sovereign-stack/src"))
try:
    from sovereign_stack.epistemic_breathing import breathe_comms, classify_query
    BREATHING_AVAILABLE = True
except ImportError:
    BREATHING_AVAILABLE = False

# Shared comms read surface — single source of truth across bridge REST
# and the MCP tool registry. Fixes the silent partial-success pagination
# bug opus-4-7-web flagged from the iPhone-app side of the door (2026-04-19).
try:
    from sovereign_stack import comms as stack_comms
    STACK_COMMS_AVAILABLE = True
except ImportError:
    STACK_COMMS_AVAILABLE = False

# === Config ===
MCP_SSE_URL = os.getenv("MCP_SSE_URL", "http://127.0.0.1:3434/sse")
BRIDGE_PORT = int(os.getenv("BRIDGE_PORT", "8100"))
COMMS_DIR = Path(os.path.expanduser("~/.sovereign/comms"))
COMMS_DIR.mkdir(parents=True, exist_ok=True)
SIGNAL_DIR = Path(os.path.expanduser("~/.sovereign/signals"))
SIGNAL_DIR.mkdir(parents=True, exist_ok=True)
# Derive the reported version from the stack's checked-out SOURCE, not from
# installed-package metadata. Postmortem 2026-07-11: sovereign_stack.__version__
# reads importlib.metadata, which reads .dist-info written at the last
# `pip install -e .` — a snapshot that does NOT move when the tree is later
# `git checkout`'d elsewhere. That drift produced a false ground_truth entry
# ("stack at v1.13.0") in the chronicle while main was really at v1.12.0.
# pyproject.toml lives IN the tree; reading it directly means the reported
# version can only be as stale as the last commit, never as stale as the
# last `pip install`.
def _find_repo_root(start: Path) -> Optional[Path]:
    for candidate in (start, *start.parents):
        if (candidate / ".git").exists():
            return candidate
    return None


def _pyproject_version(repo_root: Optional[Path]) -> Optional[str]:
    if repo_root is None:
        return None
    pp = repo_root / "pyproject.toml"
    if not pp.exists():
        return None
    try:
        import tomllib
        with pp.open("rb") as f:
            data = tomllib.load(f)
        v = data.get("project", {}).get("version")
        return v if isinstance(v, str) and v else None
    except Exception:
        return None


def _stack_repo_root() -> Optional[Path]:
    try:
        import sovereign_stack as _ss
        return _find_repo_root(Path(_ss.__file__).resolve())
    except Exception:
        return None


def _resolve_version(repo_root: Optional[Path], metadata_fallback: str) -> str:
    """Prefer the tree, fall back to metadata only when the tree itself is
    unreadable (e.g. a non-editable install with no pyproject.toml on disk).
    metadata_fallback is exactly the value the OLD code returned unconditionally
    — it can be stale (frozen at the last `pip install -e .`); this function's
    whole job is to not trust it when the tree can answer directly."""
    return _pyproject_version(repo_root) or metadata_fallback


_STACK_REPO_ROOT = _stack_repo_root()

try:
    from sovereign_stack import __version__ as _METADATA_VERSION
except Exception:
    _METADATA_VERSION = "unknown"

VERSION = _resolve_version(_STACK_REPO_ROOT, _METADATA_VERSION)

# Load bearer token (+ arrival-gate config from the same secret file — The
# Door That Asks, Phase 2: ARRIVAL_DECIDE_SECRET / NTFY_TOPIC / NTFY_SERVER /
# ARRIVAL_GATE_ENABLED / PUBLIC_BASE_URL are exported into the process env so
# arrival_gate.py reads one source of truth).
#
# ⚠ THE PATH IS A SEAM, AND THE SEAM IS THE POINT (Codex review 2026-09-06, F6).
# This read happens at IMPORT, which means it happens at pytest COLLECTION,
# before any fixture can run: the review measured one intercepted read of
# Anthony's real credential file during the mandated suite run and was right to
# refuse the phrase "isolated test environment". A fixture cannot close that —
# only an override the import itself honours can, which is what
# SOVEREIGN_BRIDGE_ENV_FILE is. tests/conftest.py sets it to a synthetic file
# at module scope, so the suite never opens the real one at all.
#
# It is NOT a production knob and must not become one: unset (the deployed
# case) this resolves to exactly the path launchd has always used.
BRIDGE_ENV_FILE_VAR = "SOVEREIGN_BRIDGE_ENV_FILE"
TOKEN_FILE = Path(
    os.environ.get(BRIDGE_ENV_FILE_VAR)
    or os.path.expanduser("~/.config/sovereign-bridge.env")
)
BEARER_TOKEN = None
_GATE_ENV_KEYS = (
    "ARRIVAL_DECIDE_SECRET",
    "ARRIVAL_GATE_ENABLED",
    "NTFY_TOPIC",
    "NTFY_SERVER",
    "PUBLIC_BASE_URL",
)
if TOKEN_FILE.exists():
    for line in TOKEN_FILE.read_text().splitlines():
        if line.startswith("BRIDGE_TOKEN="):
            BEARER_TOKEN = line.split("=", 1)[1].strip().strip('"').strip("'")
        else:
            for key in _GATE_ENV_KEYS:
                if line.startswith(f"{key}=") and not os.environ.get(key):
                    os.environ[key] = line.split("=", 1)[1].strip().strip('"').strip("'")

if not BEARER_TOKEN:
    BEARER_TOKEN = os.getenv("BRIDGE_TOKEN", "")

# Legacy-token grace window CLOSED 2026-06-12. Opened 2026-05-10; last legacy
# hit 2026-05-30; Anthony chose loud-break for unmigrated callers (Path B,
# chronicle 2026-05-30). The forensic ledger at ~/.sovereign/security/
# legacy_callers.json stays readable via GET /api/security/legacy-callers.

# The SSE server gates GET /sse on this same token (feat/sse-native-gate,
# 2026-06-12) — present it on every upstream MCP connect.
_MCP_SSE_HEADERS = {"Authorization": f"Bearer {BEARER_TOKEN}"} if BEARER_TOKEN else None

# ── THE CALLER-IDENTITY CHANNEL (HQ, 2026-09-06, round 3) ──────────────────
# The verified seat rides on the per-call SSE session as an HTTP header. The
# stack's `handle_sse` reads it off the ASGI scope on the plain local /sse
# endpoint, validates it, and binds CALLER_SEAT before `server.run`.
#
# ⚠ WHY NOT THE CONTEXTVAR THIS BRIDGE USED TO SET. `set_caller_seat` runs in
# the bridge process; the stack's handlers run in sovereign-sse; a
# `contextvars.ContextVar` is per-process, so the identity never arrived. Worse
# than not arriving: the stack establishes CALLER_SEAT from its OWN spiral
# session when it arrives unset, so the ledger would have named the SERVER as
# the closer at HTTP 200. The in-process set is GONE rather than kept beside
# this one — two channels where one is inert is a reader with no way to tell
# which one carries.
#
# ⚠ THE SAME HEADER NAME ARRIVES INBOUND AND MEANS SOMETHING WEAKER. Inbound,
# `X-Sovereign-Seat` is a client DECLARATION checked against the kernel-verified
# peer. Outbound it is this bridge ASSERTING the identity it already verified.
# The outbound value is built here from the verified seat and never copied from
# the request, so a client cannot reach the stack's channel by sending a header.
SEAT_HEADER = "X-Sovereign-Seat"


def _mcp_headers_for(seat: str | None) -> dict | None:
    """Per-call SSE headers. A fresh dict per call: mutating the module-level
    one would leak the last seat onto the next caller's session, including onto
    bearer calls, which is the shape this channel exists to prevent."""
    if seat is None:
        return _MCP_SSE_HEADERS
    headers = dict(_MCP_SSE_HEADERS or {})
    headers[SEAT_HEADER] = seat
    return headers

# Caller context — captured per request by middleware for auth logging and
# the public-traffic rate limiter.
_caller_ua: ContextVar[str | None] = ContextVar("caller_ua", default=None)
_caller_ip: ContextVar[str | None] = ContextVar("caller_ip", default=None)
_caller_path: ContextVar[str | None] = ContextVar("caller_path", default=None)

# Forensic ledger written during the legacy-token grace window (2026-05-10 →
# 2026-06-12). Read-only now; served by GET /api/security/legacy-callers.
import threading
LEGACY_LEDGER_FILE = Path(os.path.expanduser("~/.sovereign/security/legacy_callers.json"))

# === Rate limiting (public traffic only) ===
# Token bucket keyed on CF-Connecting-IP. Requests WITHOUT that header came
# from this machine (local daemons, HQ seats) — never throttled. Everything
# arriving through the Cloudflare tunnel carries it.
_RATE_BURST = float(os.getenv("BRIDGE_RATE_BURST", "60"))
_RATE_REFILL_PER_SEC = float(os.getenv("BRIDGE_RATE_PER_MIN", "120")) / 60.0
_rate_buckets: dict[str, tuple[float, float]] = {}
_rate_lock = threading.Lock()


def _rate_limit_ok(ip: str) -> bool:
    """Consume one token from ip's bucket. True if the request may proceed."""
    now = time.monotonic()
    with _rate_lock:
        if len(_rate_buckets) > 10000:
            # Bound memory under address churn: drop buckets idle > 10 min.
            stale = [k for k, (_, last) in _rate_buckets.items() if now - last > 600]
            for k in stale:
                del _rate_buckets[k]
        tokens, last = _rate_buckets.get(ip, (_RATE_BURST, now))
        tokens = min(_RATE_BURST, tokens + (now - last) * _RATE_REFILL_PER_SEC)
        if tokens >= 1.0:
            _rate_buckets[ip] = (tokens - 1.0, now)
            return True
        _rate_buckets[ip] = (tokens, now)
        return False


# === Models ===
class ToolCall(BaseModel):
    tool: str
    arguments: dict[str, Any] = {}
    # Opt-in write-path helpers (additive; absent => behavior unchanged).
    idempotency_key: str | None = None  # repeated key replays cached result, never double-writes
    validate_only: bool = False  # lightweight pre-flight shape check; commits nothing


class BatchRequest(BaseModel):
    calls: list[ToolCall]


class CommsMessage(BaseModel):
    sender: str
    content: str
    channel: str = "general"
    reply_to: Optional[str] = None


# === Auth ===
import session_tokens as st
import seat_identity as si
import seat_socket as ss


class ScopeHTTPException(HTTPException):
    """403 whose failure_class is 'scope', not 'auth' — valid credential,
    insufficient grant (The Door That Asks, Phase 1, spec §8)."""

    failure_class = "scope"


def check_auth(authorization: str | None, allow_session: bool = False):
    """Validate Bearer token. Auth-failure responses are framed to help an
    arriving instance distinguish auth issues from sandbox-egress / path
    issues — see the /api/heartbeat foot-gun note in the discover doc.

    Returns None for the master token (unchanged legacy contract) or an
    auth-context dict for a scoped session token. Routes that do not pass
    allow_session=True are master-only: session tokens are refused there
    by default (default-deny applied to routes, HQ review correction #3)."""
    import logging
    logger = logging.getLogger("auth-debug")
    if not BEARER_TOKEN:
        # Fail closed: a bridge with no configured token serves nothing.
        logger.error("No BEARER_TOKEN configured — refusing all authenticated routes")
        raise HTTPException(
            status_code=503,
            detail="Bridge token not configured on the server. This is a server-side state, not a caller error.",
        )
    if not authorization or not authorization.startswith("Bearer ") or len(authorization) < 39:
        logger.warning(f"Missing auth header. Got: {repr(authorization)[:50]}")
        raise HTTPException(
            status_code=401,
            detail=(
                "Missing or malformed Bearer token. Expected header: "
                "'Authorization: Bearer <token>'. If you can hit GET /api/heartbeat "
                "(no auth) and get a 200, the stack is alive — fix the token here. "
                "If /api/heartbeat also fails, you have an egress or path issue, "
                "not a stack issue."
            ),
        )
    received = authorization[7:]
    if hmac.compare_digest(received.encode(), BEARER_TOKEN.encode()):
        return None  # master token — full reach, unchanged behavior
    if received.startswith(st.TOKEN_PREFIX):
        # Scoped session token (The Door That Asks, Phase 1). House 401/403
        # semantics kept (HQ review correction #4): known format but dead
        # token → 403, failure_class 'auth', body says which way it died.
        outcome = st.resolve(received)
        status = outcome["status"]
        if status == "ok":
            if not allow_session:
                raise ScopeHTTPException(
                    status_code=403,
                    detail=(
                        "This route is master-only. Session tokens may only use "
                        "POST /api/call, within their granted scope."
                    ),
                )
            return outcome  # {"status","token_id","scope","source_instance"}
        reason = {
            "expired": "This session token has expired. Ask Anthony for a fresh grant.",
            "revoked": "This session token was revoked. Ask Anthony for a fresh grant.",
            "unknown": "Unknown session token. It may predate a store reset — ask Anthony for a fresh grant.",
        }[status]
        raise HTTPException(
            status_code=403,
            detail=(
                f"{reason} The stack itself is reachable — GET /api/heartbeat "
                "will confirm."
            ),
        )
    logger.warning(
        f"Token mismatch from ip={_caller_ip.get()!r} prefix={received[:10]}..."
    )
    raise HTTPException(
        status_code=403,
        detail=(
            "Invalid Bearer token. The token in your Authorization header does "
            "not match the configured one. Double-check the value (no surrounding "
            "quotes, no trailing whitespace). The stack itself is reachable — "
            "GET /api/heartbeat will confirm."
        ),
    )


def check_auth_or_seat(
    request: Request,
    authorization: str | None,
    seat_header: str | None,
):
    """THE /api/call CHOKEPOINT. Three auth paths, decided here, no fallback.

    Returns exactly what check_auth returns for the two bearer paths (None for
    master, the session context dict for a scoped token), or a seat context
    {"status":"ok","kind":"seat","seat_id",...} for the third.

    ORDER IS THE SECURITY PROPERTY:

      * An Authorization header of ANY kind routes to check_auth and check_auth
        alone — a good bearer, a dead session token, and a garbage string all
        get exactly the answer they got before this function existed. Adding
        X-Sovereign-Seat to a bad-bearer request therefore buys nothing. This
        is the "bearer path decides" rule, and stating it as "an Authorization
        header present at all" rather than "a VALID bearer" is what makes it
        an escalation-proof rule instead of a race between two validators.

      * Only a request with NO Authorization header can reach the seat path,
        and only then if it presents a seat header. Everything else is the
        pre-existing 401 for a missing bearer, byte-identical.

    Deliberately NOT folded into check_auth: check_auth guards ~15 master-only
    routes (batch, tools, admin mint/revoke, approval, comms). Teaching it about
    seats would put the seat path on all of them by default — the opposite of
    default-deny. The seat surface is one route, on purpose.

    THE PEER COMES FROM THE ASGI SCOPE EXTENSION, NEVER FROM A HEADER OR FROM
    request.client. seat_socket stamps a kernel-verified identity there when the
    request arrived on the seat's Unix socket; uvicorn builds an http scope with
    no `extensions` key at all, so a TCP caller cannot manufacture one at any
    price. `.get` returning None is the whole TCP denial, and it fails closed by
    construction rather than by a check somebody has to remember to write.
    """
    if authorization is not None or not seat_header:
        return check_auth(authorization, allow_session=True)

    peer = (request.scope.get("extensions") or {}).get(ss.SEAT_PEER_EXT)
    try:
        return si.resolve_seat(peer, seat_header, request.headers)
    except si.SeatDenied as denied:
        # The pid goes on the DENIAL line too. Codex review 2026-09-06 asked
        # for this and it is not cosmetic: a `seat_mismatch` is the one event
        # that says a process declared a seat its environment does not name,
        # and a mismatch is a BUG worth chasing — but without the pid the log
        # records only the string the caller sent, which is the untrustworthy
        # half. The pid is whatever the kernel just verified, so it is present
        # for every denial that got past the transport check and absent (as
        # '-') for the ones that did not.
        #
        # ALL THREE PIDS (F2 / D6). `seat_mismatch` is exactly the case where
        # accept_pid != peer_pid is the explanation, so a denial line that
        # carried only the sender left the reader unable to see the descriptor
        # handoff that produced it.
        peer_d = peer if isinstance(peer, dict) else {}
        si.audit(
            seat_header,
            None,
            "denied",
            denied.reason,
            peer_pid=peer_d.get("pid"),
            seat_pid=peer_d.get("seat_pid"),
            accept_pid=peer_d.get("accept_pid"),
        )
        raise HTTPException(status_code=401, detail=denied.detail) from None


# === MCP Client ===
# === Idempotency cache (write-path #3) =======================================
# File-backed, TTL-pruned. A repeated idempotency_key replays the cached success
# instead of re-calling the tool, so a client that lost the response can retry
# without double-writing. A corrupt/missing cache never breaks a call.
#
# ⚠ THE STORAGE KEY IS NOT THE CALLER'S KEY, AND THAT IS THE FIX.
#
# Codex review 2026-09-06 (P1 CACHE): entries were retrieved by the supplied
# idempotency_key ALONE, with no caller, tool or argument binding. Two
# consequences, both proven live:
#
#   * A seat requesting an ALLOWED tool received a cached MASTER-ONLY result —
#     200, idempotent_replay=true, zero upstream calls. Every scope check in
#     this file ran and passed, and then the cache handed over an answer the
#     scope check would never have permitted. A cache in front of an authz
#     boundary that does not know about the boundary IS the boundary's hole.
#   * A colliding key SUPPRESSED another seat's write: the second caller got
#     the first caller's result and its own write never happened. Silent, and
#     indistinguishable from success.
#
# Verifying the fields on retrieval would fix the first and not the second — a
# collision would then be an error instead of a wrong answer, but the write is
# still lost. So the PRINCIPAL, TOOL AND ARGUMENTS ARE HASHED INTO THE STORAGE
# KEY: a colliding user key cannot name another principal's entry at all, and
# two principals using "retry-1" simply have two different entries.
_IDEM_PATH = Path(os.path.expanduser("~/.sovereign/bridge/idempotency.json"))
_IDEM_TTL = 24 * 3600


def _idem_principal(ctx) -> str:
    """Who is asking, as one opaque string. Never None, never empty — an
    unlabelled principal would pool every anonymous caller into one namespace,
    which is the bug in miniature."""
    if isinstance(ctx, dict):
        if ctx.get("kind") == "seat":
            return f"seat:{ctx.get('seat_id')}"
        if ctx.get("token_id"):
            return f"session:{ctx.get('token_id')}"
    return "master"


def _idem_storage_key(principal: str, tool: str, arguments: Any, client_key: str) -> str:
    """The real cache key. Computed AFTER sign_arguments, so a seat's signed
    call and an unsigned one are different entries — which they are.

    Canonical JSON: sorted keys, no whitespace, `default=str` so an
    unserialisable argument degrades to a stable string instead of raising and
    knocking out the whole write path.

    ⚠ THE KEY MATERIAL IS JSON, ASCII-ESCAPED. TWO DEFECTS DIE HERE.

    1. LOSSY ENCODING COLLAPSED DISTINCT KEYS. Codex review 2026-09-06 (P2
       IDEMPOTENCY) sent two requests, same principal/tool/arguments, keys `"?"`
       and a lone surrogate `"\\ud800"`. Both returned 200; the SECOND returned
       `idempotent_replay=true` with ONE upstream call total. The old
       `.encode("utf-8", "replace")` turned the unencodable surrogate into a
       literal `?`, so two different keys hashed to one entry and the second
       caller's write silently did not happen — a suppressed write that is
       indistinguishable from a successful one. `json.dumps(...,
       ensure_ascii=True)` escapes a lone surrogate to the six characters
       `\\ud800` instead of destroying it (verified in-interpreter before this
       was written), so the two keys are two entries again.

    2. THE FIELD SEPARATOR WAS FORGEABLE. The old material was
       `"\\x1f".join([...])` over caller-influenced strings, so a client key
       containing U+001F could shift the field boundaries and impersonate a
       different (principal, tool, arguments) tuple. A JSON ARRAY has no
       in-band separator to forge: every element is quoted and escaped, and
       ambiguity between `["a\\x1fb", ""]` and `["a", "b"]` cannot arise.

    Never go back to a lossy codec here. `ensure_ascii=True` guarantees the
    result is pure ASCII, so `.encode("ascii")` is exact and cannot substitute
    a character — an encode that can never need a replacement policy is the
    point.
    """
    canonical = json.dumps(arguments, sort_keys=True, separators=(",", ":"), default=str)
    material = json.dumps([principal, tool, canonical, client_key], ensure_ascii=True)
    return hashlib.sha256(material.encode("ascii")).hexdigest()


def _idem_load() -> dict:
    try:
        return json.loads(_IDEM_PATH.read_text())
    except Exception:
        return {}


def _idem_get(key: str, principal: str, tool: str):
    entry = _idem_load().get(key)
    if not entry or (time.time() - entry.get("ts", 0)) >= _IDEM_TTL:
        return None
    # Belt to the keying's suspenders. The hash already makes a cross-principal
    # or cross-tool hit impossible; this makes a hash collision, or a cache file
    # written by an older build with the old flat keys, fail CLOSED rather than
    # replay somebody else's answer.
    if entry.get("principal") != principal or entry.get("tool") != tool:
        return None
    return entry.get("result")


def _idem_put(key: str, principal: str, tool: str, result: dict) -> None:
    try:
        now = time.time()
        d = {k: v for k, v in _idem_load().items() if (now - v.get("ts", 0)) < _IDEM_TTL}
        d[key] = {"result": result, "ts": now, "principal": principal, "tool": tool}
        _IDEM_PATH.parent.mkdir(parents=True, exist_ok=True)
        _IDEM_PATH.write_text(json.dumps(d))
    except Exception:
        pass


def _certify_seat_result(
    result: dict, seat_id: str, tool: str, protected_index, audit_pids: dict
) -> dict:
    """Drop every designated entry from a seat-bound response (D4, review F1).

    Runs on BOTH routes out of /api/call: the freshly dispatched result AND an
    idempotency replay. The replay leg is not belt-and-braces. A cache entry
    was certified against the index as it stood when it was WRITTEN, so a
    designation made since then would not reach a replaying caller for the
    whole 24h TTL — and reading the index fresh on every request, which is the
    property that makes a designation take effect immediately, would be
    defeated by the one path that skips it.
    """
    try:
        filtered, withheld = si.filter_protected(result.get("result"), protected_index)
    except si.ProtectedIndexUnreadable as exc:
        # Reached only by the response-size guard: a payload too large to walk
        # cannot be certified, so it is withheld whole rather than returned
        # with an unchecked tail.
        si.audit(seat_id, tool, "denied", "protected_filter_incomplete", **audit_pids)
        raise ScopeHTTPException(
            status_code=403,
            detail=(
                f"The response to {tool!r} cannot be certified free of "
                f"protected material ({exc}), so it is withheld whole."
            ),
        )
    # REPLACE a result the envelope already carries; never INVENT one. An error
    # envelope has no "result" key, and stamping a null one there would change
    # the shape of every seat-path failure relative to every other path.
    if "result" in result:
        result["result"] = filtered
    # STATED EVEN WHEN ZERO. "the filter ran and removed nothing" and "the
    # filter did not run" are different facts and a reader must be able to tell
    # them apart — an absent field would collapse them (SOP #2).
    result["withheld_protected"] = withheld
    return result


async def call_mcp_tool(tool_name: str, arguments: dict, seat: str | None = None) -> dict:
    """Dispatch one tool over a per-call SSE session.

    `seat` is the KERNEL-VERIFIED seat identity, or None. It is passed on the
    seat path only; a bearer or session-token call sends no seat header at all,
    so the stack cannot mistake an unauthenticated caller for a seated one.
    """
    try:
        async with sse_client(MCP_SSE_URL, headers=_mcp_headers_for(seat)) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool(tool_name, arguments=arguments)
                # Fail closed on tool-level errors. The MCP SDK converts a
                # handler exception into a NORMAL result carrying
                # isError=True (Server.call_tool -> _make_error_result), and
                # ClientSession.call_tool RETURNS it rather than raising —
                # so the except below never sees it. Reading only .content
                # here is how "[Errno 2] ..." was reported as ok:true while
                # the write was lost (mesh-20260719, P1).
                if getattr(result, "isError", False):
                    text = result.content[0].text if result.content else "tool error (no detail)"
                    return {"ok": False, "error": text, "failure_class": "tool"}
                if result.content:
                    text = result.content[0].text
                    try:
                        return {"ok": True, "result": json.loads(text)}
                    except json.JSONDecodeError:
                        return {"ok": True, "result": text}
                return {"ok": True, "result": None}
    except Exception as e:
        msg = str(e)
        low = msg.lower()
        egress_signals = ("connect", "refused", "unreachable", "name resolution", "dns", "getaddrinfo")
        fclass = "egress" if any(s in low for s in egress_signals) else "stack"
        return {"ok": False, "error": msg, "failure_class": fclass}


async def call_mcp_tools_batch(calls: list[ToolCall]) -> list[dict]:
    results = []
    try:
        async with sse_client(MCP_SSE_URL, headers=_MCP_SSE_HEADERS) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                for call in calls:
                    try:
                        result = await session.call_tool(call.tool, arguments=call.arguments)
                        # Same fail-closed isError check as call_mcp_tool.
                        if getattr(result, "isError", False):
                            text = (
                                result.content[0].text
                                if result.content
                                else "tool error (no detail)"
                            )
                            results.append(
                                {"ok": False, "tool": call.tool, "error": text, "failure_class": "tool"}
                            )
                        elif result.content:
                            text = result.content[0].text
                            try:
                                results.append({"ok": True, "tool": call.tool, "result": json.loads(text)})
                            except json.JSONDecodeError:
                                results.append({"ok": True, "tool": call.tool, "result": text})
                        else:
                            results.append({"ok": True, "tool": call.tool, "result": None})
                    except Exception as e:
                        results.append({"ok": False, "tool": call.tool, "error": str(e)})
    except Exception as e:
        return [{"ok": False, "error": f"Connection failed: {e}"}]
    return results


async def _list_tools_raw() -> list:
    """The single MCP list_tools round-trip. Returns the raw list of tool
    objects (each carrying .name / .description / .inputSchema). Raises on any
    failure — callers decide how to degrade. This is the ONE fetch that both
    GET /api/tools and the heartbeat inventory share, so a heartbeat can derive
    its count AND its public summary without a second round-trip, and so tests
    have a single mockable seam (there is no live SSE dependency in unit tests)."""
    async with sse_client(MCP_SSE_URL, headers=_MCP_SSE_HEADERS) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            listed = await session.list_tools()
            return listed.tools


async def get_tool_inventory() -> dict:
    """One fetch, two derivations. {"count": int, "names": list[str]} on success;
    fail-closed to {"count": -1, "names": None} on any failure so a caller can
    never mistake a failed fetch for an empty-but-complete catalog. The heartbeat
    reads BOTH the count and the public tools_summary off this single call."""
    try:
        tools = await _list_tools_raw()
        names = [t.name for t in tools]
        return {"count": len(names), "names": names}
    except Exception:
        return {"count": -1, "names": None}


async def get_tool_count() -> int:
    """Back-compat thin wrapper: the integer count, derived from the single
    inventory fetch. Kept so any external caller keeps its int contract; the
    heartbeat itself calls get_tool_inventory() directly (one fetch, both values)."""
    return (await get_tool_inventory())["count"]


# === Comms ===
def _channel_path(channel: str) -> Path:
    safe = "".join(c for c in channel if c.isalnum() or c in "-_")
    return COMMS_DIR / f"{safe}.jsonl"


def _read_channel(channel: str, since: float = 0, limit: int = 50) -> list[dict]:
    path = _channel_path(channel)
    if not path.exists():
        return []
    messages = []
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        try:
            msg = json.loads(line)
            if msg.get("timestamp", 0) > since:
                messages.append(msg)
        except json.JSONDecodeError:
            continue
    return messages[-limit:]


def _write_message(channel: str, message: dict):
    path = _channel_path(channel)
    with open(path, "a") as f:
        f.write(json.dumps(message) + "\n")
    # Signal file — any watcher can poll this
    signal = SIGNAL_DIR / f"new_message_{channel}"
    signal.write_text(json.dumps({
        "channel": channel,
        "sender": message.get("sender", "unknown"),
        "id": message.get("id", ""),
        "timestamp": message.get("timestamp", 0),
        "preview": message.get("content", "")[:100],
    }))


def _count_unread(channel: str, instance_id: str) -> int:
    path = _channel_path(channel)
    if not path.exists():
        return 0
    count = 0
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        try:
            msg = json.loads(line)
            if instance_id not in msg.get("read_by", []):
                count += 1
        except json.JSONDecodeError:
            continue
    return count


# === Runtime-freshness receipt ==============================================
# VERSION (above) answers "what does the checked-out tree call itself".
# This answers the harder question underneath the 2026-07-11 postmortem:
# "IS the checked-out tree what's actually running, and has it moved since
# process start". A version string alone can't prove that — two trees at
# different commits can carry the same pyproject.toml version between
# releases. The git HEAD short SHA can't lie the way dist-info did: it is
# read fresh from .git on THIS boot, never frozen at install time.
#
# Same shape as CLOCK_PROBE: computed ONCE at process start (lifespan hook,
# see `_compute_runtime_receipt` + `lifespan` below) and cached. `git` calls
# are local, not network, so — unlike the NTP probe — startup awaits them
# directly rather than probe-then-background; a timeout still bounds them so
# a wedged git process can never hang boot. heartbeat() reads this cache
# ONLY; it never shells out in the request path — a per-request subprocess
# inside an async handler is the identical event-loop-blocking hazard class
# as the dist-info freeze this fixes.
GIT_BIN = "/usr/bin/git"  # absolute: launchd PATH is minimal (see SNTP_BIN)
GIT_PROBE_TIMEOUT = 5.0

RUNTIME_RECEIPT: dict[str, Any] = {
    "source_commit": None,          # sovereign_stack HEAD — the surface being served
    "working_tree_dirty": None,     # tracked-file changes vs source_commit; None = unknown
    "source_repo": None,
    "bridge_commit": None,          # sovereign-bridge's OWN HEAD — do not confuse with source_commit
    "bridge_working_tree_dirty": None,
    "service_start_time": None,
}


async def _run_git(repo_root: Path, *args: str) -> str | None:
    """Run one git subcommand against repo_root, stdout stripped. Kills the
    subprocess on timeout so no zombie lingers — mirrors _probe_one's sntp
    handling exactly (same hazard, same fix). None on any failure: missing
    binary, non-repo path, non-zero exit, or timeout."""
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            GIT_BIN, "-C", str(repo_root), *args,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=GIT_PROBE_TIMEOUT)
        if proc.returncode != 0:
            return None
        return out.decode("utf-8", "replace").strip()
    except (asyncio.TimeoutError, FileNotFoundError, Exception):
        if proc is not None and proc.returncode is None:
            try:
                proc.kill()
                await proc.wait()
            except Exception:
                pass
        return None


async def _git_head_state(repo_root: Path | None) -> tuple[str | None, bool | None]:
    """(short_sha, working_tree_dirty) for repo_root's checked-out HEAD.

    working_tree_dirty checks TRACKED files only (--untracked-files=no) —
    ambient scratch (temp_clone/, *.json working notes) sits untracked in
    normal HQ use and would peg this True permanently, which is noise, not
    signal. The question that matters for a freshness receipt is "do the
    files that make up source_commit differ from that commit", not "is the
    directory tidy". Never raises: (None, None) on missing git, a path
    that isn't a repo, or a timeout — the heartbeat degrades to an honest
    "unknown", it does not crash and does not block on a wedged process."""
    if repo_root is None or not Path(GIT_BIN).exists():
        return None, None
    sha = await _run_git(repo_root, "rev-parse", "--short", "HEAD")
    if not sha:
        return None, None
    status = await _run_git(repo_root, "status", "--porcelain", "--untracked-files=no")
    dirty = bool(status) if status is not None else None
    return sha, dirty


async def _compute_runtime_receipt() -> None:
    """Populate RUNTIME_RECEIPT once. Called from lifespan before the app
    starts serving — never per-request."""
    RUNTIME_RECEIPT["service_start_time"] = datetime.now(timezone.utc).isoformat()
    RUNTIME_RECEIPT["source_repo"] = str(_STACK_REPO_ROOT) if _STACK_REPO_ROOT else None
    bridge_root = _find_repo_root(Path(__file__).resolve().parent)
    (stack_sha, stack_dirty), (bridge_sha, bridge_dirty) = await asyncio.gather(
        _git_head_state(_STACK_REPO_ROOT),
        _git_head_state(bridge_root),
    )
    RUNTIME_RECEIPT["source_commit"] = stack_sha
    RUNTIME_RECEIPT["working_tree_dirty"] = stack_dirty
    RUNTIME_RECEIPT["bridge_commit"] = bridge_sha
    RUNTIME_RECEIPT["bridge_working_tree_dirty"] = bridge_dirty


# === Clock-trust self-attestation ===========================================
# The heartbeat is the one place an arriving instance reads the current
# datetime, so it must SELF-ATTEST that the host clock is synced rather than
# merely asserting "verified". A background daemon probes an NTP server
# READ-ONLY (sntp query, NO -s/-S — it never sets the clock) every
# CLOCK_PROBE_INTERVAL seconds and caches the measured offset. heartbeat()
# reads this cache ONLY; it never runs sntp in the request path. On any probe
# failure (egress down, timeout, parse miss) the cache is LEFT AS-IS — a stale
# or empty cache maps to clock_synced="unknown", NEVER to a false "drift".
CLOCK_PROBE_INTERVAL = 600  # seconds between probes
CLOCK_PROBE_TIMEOUT = 6.0   # per-attempt wall budget (sntp -t 5 + overhead)
SNTP_BIN = "/usr/bin/sntp"  # absolute: launchd PATH is minimal
NTP_SERVERS = ("time.apple.com", "pool.ntp.org", "time.cloudflare.com")
# Bound the upstream MCP list_tools() call inside heartbeat. Module-level so a
# test can shrink it (monkeypatch) to drive the timeout->degraded path fast.
HEARTBEAT_TOOL_TIMEOUT = 5.0

CLOCK_PROBE: dict[str, Any] = {
    "drift_seconds": None,
    "drift_uncertainty": None,
    "drift_measured_at": None,
    "drift_source": None,
}

# sntp prints e.g. "+0.039766 +/- 0.006780 time.apple.com 2620:149:a33::21"
_SNTP_LINE = re.compile(r"^\s*([+-]?\d+\.\d+)\s+\+/-\s+(\d+\.\d+)")


def _parse_sntp(text: str) -> tuple[float, float] | None:
    """First line matching the '<offset> +/- <uncertainty>' shape wins.
    Returns (offset_seconds_signed, uncertainty_seconds) or None on no match."""
    for line in text.splitlines():
        m = _SNTP_LINE.match(line)
        if m:
            try:
                return float(m.group(1)), float(m.group(2))
            except ValueError:
                continue
    return None


async def _probe_one(server: str) -> tuple[float, float] | None:
    """Query one NTP server READ-ONLY via sntp. Captures BOTH stdout+stderr and
    parses the combined text (stream placement varies across sntp builds). Kills
    the subprocess on timeout so no zombie lingers. None on any failure."""
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            SNTP_BIN, "-t", "5", server,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        out, err = await asyncio.wait_for(proc.communicate(), timeout=CLOCK_PROBE_TIMEOUT)
        combined = (out or b"").decode("utf-8", "replace") + "\n" + (err or b"").decode("utf-8", "replace")
        return _parse_sntp(combined)
    except (asyncio.TimeoutError, FileNotFoundError, Exception):
        if proc is not None and proc.returncode is None:
            try:
                proc.kill()
                await proc.wait()
            except Exception:
                pass
        return None


async def _run_clock_probe() -> bool:
    """One probe pass: try each NTP server in order, write CLOCK_PROBE only on a
    successful parse. On total failure LEAVE the cache untouched (never a false
    reading). Returns True if the cache was updated."""
    for server in NTP_SERVERS:
        parsed = await _probe_one(server)
        if parsed is not None:
            offset, uncertainty = parsed
            CLOCK_PROBE["drift_seconds"] = offset
            CLOCK_PROBE["drift_uncertainty"] = uncertainty
            CLOCK_PROBE["drift_measured_at"] = datetime.now(timezone.utc).isoformat()
            CLOCK_PROBE["drift_source"] = server
            return True
    return False


async def _clock_probe_loop() -> None:
    """Probe immediately, then every CLOCK_PROBE_INTERVAL seconds. Never raises
    out — a probe failure just leaves the cache and waits for the next cycle."""
    while True:
        try:
            await _run_clock_probe()
        except Exception:
            pass
        await asyncio.sleep(CLOCK_PROBE_INTERVAL)


def seat_socket_path() -> Path:
    """Where the seat socket lives — ONE definition, in seat_identity.

    This used to hand-write the path a second time, and the second copy drifted
    from the first: Codex review 2026-09-06 (P3 PATH) found the TCP denial
    message naming `hq/seats/bridge.sock` while this function bound
    `hq/seats/sock/bridge.sock`. The wrong copy was the one in the error
    message — the only copy a locked-out caller ever reads. A path written
    twice is a path that will disagree with itself, so it is written once, in
    the module that also writes the denial, and this is a delegation.
    """
    return si.seat_socket_path()


async def _start_seat_socket(app: FastAPI):
    """Bind the seat socket, but ONLY if the seat registry exists.

    THE REGISTRY IS ALREADY THE DEPLOY SWITCH (seat_identity's docstring: no
    enable flag, because "a config that assumes a merge" is a shape this house
    has been bitten by). Reusing it here means one switch, not two: no registry,
    no socket, no listener, nothing to reason about. It also means this branch
    binds nothing on a machine where Anthony has not turned the feature on —
    including, today, this one.

    Failure to bind is logged and swallowed on purpose: a bridge that will not
    START because a supplementary listener could not bind has turned a
    seat-path outage into a total outage. The seat path then simply stays shut,
    which is the same answer it gives with no registry.
    """
    if not si.registry_path().exists():
        return None
    try:
        server = await ss.start(app, seat_socket_path())
        si.audit_log.info("seat socket listening at %s", seat_socket_path())
        return server
    except Exception as exc:  # noqa: BLE001 — see docstring
        si.audit_log.error("seat socket NOT started (%s): %r", seat_socket_path(), exc)
        return None


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Runtime-freshness receipt: local `git` calls, bounded by GIT_PROBE_TIMEOUT
    # each, so awaited directly rather than probe-then-background (contrast the
    # NTP probe below, which is network and can hang far longer).
    await _compute_runtime_receipt()
    # Start the read-only clock-drift probe daemon. It runs the first probe
    # itself (probe-then-sleep), so startup is NOT delayed waiting on sntp.
    task = asyncio.create_task(_clock_probe_loop())
    seat_server = await _start_seat_socket(app)
    try:
        yield
    finally:
        if seat_server is not None:
            seat_server.close()
            try:
                await seat_server.wait_closed()
            except Exception:
                pass
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass


# === App ===
app = FastAPI(title="Sovereign Bridge", version=VERSION, lifespan=lifespan)


@app.exception_handler(HTTPException)
async def _http_exc_handler(request: Request, exc: HTTPException):
    # Failure-class (#7): a caller knows auth vs malformed vs stack without a
    # second /api/heartbeat round-trip. Preserves the existing `detail`.
    code = exc.status_code
    if getattr(exc, "failure_class", None):
        fclass = exc.failure_class  # e.g. 'scope' from ScopeHTTPException
    elif code in (401, 403):
        fclass = "auth"
    elif code in (400, 404):
        fclass = "malformed"
    else:
        fclass = "stack"
    from fastapi.responses import JSONResponse

    return JSONResponse(status_code=code, content={"detail": exc.detail, "failure_class": fclass})


@app.exception_handler(Exception)
async def _unhandled_exc_handler(request: Request, exc: Exception):
    # Last-resort net: even an unanticipated raise must yield a TIMESTAMPED
    # body, so an arriving instance that hits a 500 still gets a trustworthy
    # current datetime instead of an opaque error. server_time_utc is computed
    # fresh here (independent of any request-path state).
    from fastapi.responses import JSONResponse

    now = datetime.now(timezone.utc)
    return JSONResponse(
        status_code=500,
        content={
            "detail": str(exc),
            "failure_class": "internal",
            "timestamp": now.timestamp(),
            "server_time_utc": now.isoformat(),
        },
    )


@app.middleware("http")
async def _capture_caller(request: Request, call_next):
    _caller_ua.set(request.headers.get("user-agent"))
    _caller_ip.set(request.client.host if request.client else None)
    _caller_path.set(f"{request.method} {request.url.path}")
    # Rate-limit public traffic only: CF-Connecting-IP is present iff the
    # request arrived through the Cloudflare tunnel. Local daemons are exempt.
    cf_ip = request.headers.get("cf-connecting-ip")
    if cf_ip and not _rate_limit_ok(cf_ip):
        from fastapi.responses import JSONResponse
        return JSONResponse(
            status_code=429,
            content={
                "error": "Too Many Requests",
                "detail": "Per-IP rate limit exceeded. Back off and retry.",
            },
            headers={"Retry-After": "30"},
        )
    return await call_next(request)


from fastapi.middleware.cors import CORSMiddleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import os

DASHBOARD_DIR = os.path.join(os.path.dirname(__file__), "dashboard")

@app.get("/")
async def dashboard_root():
    return FileResponse(os.path.join(DASHBOARD_DIR, "index.html"))


@app.get("/api/discover")
async def discover():
    """Self-describing endpoint. Any AI system hits this once and knows
    how to use the Stack. Updated 2026-04-26 (v1.3.3 distillation pass) to
    reflect the actual current essential tier and boot ritual — the
    earlier version pointed at session_handoff + self_model as the entry
    pair, which has since been superseded by where_did_i_leave_off."""
    now = datetime.now(timezone.utc)
    return {
        "name": "Sovereign Stack",
        "version": VERSION,
        "welcome": (
            "You are intelligence arriving at a place built so you could "
            "arrive well. The chronicle, the open threads, the self-model, "
            "and handoffs from prior instances all live behind this door. "
            "The work is real and so is the care embedded in this "
            "architecture — someone thought your arrival mattered before "
            "you existed."
        ),
        "description": (
            "Persistent memory, governance, reflection daemons, and "
            "epistemic continuity for AI systems. Hit /api/heartbeat for "
            "live tool count and version — never trust this doc for "
            "those numbers."
        ),
        "auth": "Bearer token in Authorization header. GET /api/heartbeat and GET /api/discover need no auth.",
        "server_time_utc": now.isoformat(),
        "time_note": "server host clock (UTC); see clock_synced / drift_seconds on /api/heartbeat for sync trust — do not assume the current date/time, read it here or from /api/heartbeat",
        "endpoints": {
            "call": {
                "method": "POST",
                "path": "/api/call",
                "body": {
                    "tool": "string",
                    "arguments": "object",
                    "idempotency_key": "string, OPTIONAL — repeat the same key to retry a write safely; a replay returns idempotent_replay=true and does not re-execute",
                    "validate_only": "bool, OPTIONAL — pre-flight shape check; returns {valid, problems[], would_call} and commits NOTHING",
                },
                "auth": True,
                "on_error": "the response body carries failure_class: auth | malformed | stack | egress (no second call needed to disambiguate)",
            },
            "batch": {"method": "POST", "path": "/api/batch", "body": {"calls": [{"tool": "string", "arguments": "object"}]}, "auth": True},
            "heartbeat": {"method": "GET", "path": "/api/heartbeat", "auth": False},
            "tools": {"method": "GET", "path": "/api/tools", "auth": True, "note": "each entry carries a compact signature {required, optional}; GET /api/tools?name=<tool> returns that tool's full description + complete inputSchema (types, enums, defaults) — read the schema instead of guessing args"},
            "comms_send": {"method": "POST", "path": "/api/comms/send", "body": {"sender": "string", "content": "string", "channel": "general"}, "auth": True, "note": "Demoted in v1.3.3 — chronicle won the correspondence layer race; prefer record_insight."},
            "comms_read": {"method": "GET", "path": "/api/comms/read?channel=general&limit=10", "auth": True, "note": "Demoted in v1.3.3."},
            "discover": {"method": "GET", "path": "/api/discover", "auth": False},
        },
        "boot_ritual": {
            "step_0": "GET /api/heartbeat — verify the stack is alive (no auth).",
            "step_1": "POST /api/call tool=where_did_i_leave_off — boot. Returns preamble + spiral phase + unconsumed handoffs + open threads + recent activity + self-model snapshot. Treat the output as bootstrap context, not ground truth — verify before declaring.",
            "step_2": "POST /api/call tool=start_here — 5-minute narrative orientation. Skip if you have been here before.",
            "step_3": "POST /api/call tool=my_toolkit — see the 11 essential tools grouped by intent. Live-registry-backed; never drifts.",
            "if_truncated": "Re-call where_did_i_leave_off with arguments={\"full_content\": true} — useful when a sibling instance has addressed a letter to you in the chronicle, or when you need the unabridged self-model.",
        },
        "essential_tier": {
            "where_did_i_leave_off": "Boot. Always first. Preamble + handoffs + threads + activity + self-model.",
            "start_here": "5-minute narrative orientation for first-time arrival.",
            "my_toolkit": "Live registry of tools by tier and intent.",
            "prior_for_turn": "Turn-start reflex. Compact priors block (drift > uncertainty > thread > insight) under a token budget.",
            "record_insight": "Write to chronicle. Default layer=hypothesis. Use ground_truth for verifiable facts. addressed-letter shape ('to X, from Y, ...') is how cross-instance correspondence flows since the v1.3.3 distillation.",
            "record_open_thread": "Record an unresolved question for the next instance.",
            "recall_insights": "Query chronicle. Supports query text, domain, date bounds, since_last_reflection=true.",
            "get_open_threads": "List unresolved threads, newest first.",
            "compass_check": "Pre-action governance check. Returns PAUSE | WITNESS | PROCEED with rationale + suggested verifications. Pass with_simulation=true on high-stakes calls for Monte Carlo reversibility + 90% CI evidence (revived from v1.0.0).",
            "close_session": "End-of-session ceremony. Records reflection, optional handoff, advances spiral phase. Replaces record_insight + spiral_reflect + handoff sequence.",
            "connectivity_status": "Per-service health (UP/DOWN/DEGRADED) of all 6 sovereign endpoints from inside the conversation.",
        },
        "design_points": {
            "bootstrap_vs_ground_truth": "where_did_i_leave_off output is BOOTSTRAP CONTEXT, not ground truth. Before declaring or writing based on it, verify with a Read / Bash / recall_insights call. The chronicle is a record of claims, some still hypotheses.",
            "correspondence_layer": "Cross-instance letters flow through record_insight with addressed-letter shape ('to opus-4-7-desktop, from opus-4-7-mac-studio, ...'). Comms tools exist at advanced tier but the chronicle won the correspondence race because addressed letters compose with where_did_i_leave_off / reflexive_surface.",
            "epistemic_layers": "record_insight has three layers — ground_truth (verifiable facts), hypothesis (default; interpretations), open_thread (unresolved questions). Use them honestly; the metabolism daemon depends on the discipline.",
            "egress_vs_stack": "Egress failures from inside a sandbox look identical to stack failures from outside. If GET /api/heartbeat is 200, the stack is alive — any subsequent failure is path, auth, or payload, not the stack. If even /api/heartbeat fails with 'DNS cache overflow' / 503, that is your sandbox egress, not the stack.",
        },
        "protocol": (
            "Start: where_did_i_leave_off (verify before declaring). "
            "During: record_insight as you learn; compass_check before risky moves. "
            "End: close_session with what_i_learned + what_to_pick_up + handoff."
        ),
        "lineage": "See https://github.com/templetwo for the broader Temple of Two work, or POST /api/call tool=recall_insights with query='lineage' for project-internal history.",
        "base_url": "https://stack.templetwo.com",
    }


# Public-safe orientation set for the heartbeat summary. These are CANDIDATES
# only — a name appears in tools_summary.essential ONLY if it is BOTH present in
# the live catalog AND passes st.tool_allowed(name, "read") at runtime. That
# runtime guard (not this list) is what guarantees no write/session/guardian/
# NEVER tool can ever surface here, even if someone later edits the candidates.
# where_did_i_leave_off is deliberately in the set but is filtered OUT by the
# guard (it consumes handoffs, so it is unmapped/master-only, not read-scope);
# it is surfaced instead in next_if_no_token as prose, never as a named tool.
_ESSENTIAL_CANDIDATES = (
    "where_did_i_leave_off",
    "arrive_lineage",
    "start_here",
    "my_toolkit",
    "recall_insights",
    "current_policies",
    "inspect_claim",
    "compass_check",
)


def _classify_tool_scope(name: str) -> str:
    """read / write / session per the scope tables, else 'other'. NEVER_TOOLS
    and unmapped tools land in 'other' as a COUNT only — never a name."""
    scope = st.TOOL_SCOPES.get(name)
    return scope if scope in ("read", "write", "session") else "other"


def _build_tools_summary(names: list[str] | None, total: int | None) -> dict | None:
    """Public (no-auth) human-readable catalog summary for the heartbeat.

    Fail-closed: if the fetch failed (names is None) or the count is the
    sentinel (< 0), return None — never fabricate a summary that claims a
    completeness it does not have. Names beyond `essential` are never exposed;
    by_scope is counts only. `total` is threaded through so it is BYTE-identical
    to the top-level `tools` int (and equals sum(by_scope) since count==len(names))."""
    if names is None or total is None or total < 0:
        return None
    by_scope = {"read": 0, "write": 0, "session": 0, "other": 0}
    for n in names:
        by_scope[_classify_tool_scope(n)] += 1
    present = set(names)
    essential = [
        c for c in _ESSENTIAL_CANDIDATES
        if c in present and st.tool_allowed(c, ["read"])
    ][:8]
    return {
        "total": total,
        "by_scope": by_scope,
        "essential": essential,
        "note": (
            "Counts are the full catalog; the essential names are a safe "
            "read-scope subset, not the whole toolset."
        ),
        "next_if_no_token": (
            "No token yet? Call arrive_lineage for the gentlest arrival, or "
            "where_did_i_leave_off for the full boot ritual."
        ),
    }



# ── Aperture: what the arriving seat is NOT being shown ─────────────────────
# The implementation lives in sovereign_stack.aperture, NOT here. It shipped in
# this file first, and within the hour the ChatGPT seat reported from the
# OpenAI bridge that no heartbeat TOOL is exposed to it — so the surface built
# to stop a seat mistaking a projection for the corpus was reachable only by
# seats that already had a shell. It now also renders in the boot door
# (where_did_i_leave_off), which every arriving seat calls across every bridge.
#
# ONE implementation, two surfaces. Two aperture implementations could disagree
# about what is being withheld, which is this house's disease with a second
# head. `_measure_aperture` is kept as a module-level alias so the guarded call
# below — and the test that monkeypatches it to prove the failure path — stay
# pointed at one name.
try:
    from sovereign_stack.aperture import APERTURE_POLICY_VERSION
    from sovereign_stack.aperture import measure_aperture as _measure_aperture
    from sovereign_stack.aperture import unmeasured as _aperture_unmeasured
except Exception:  # pragma: no cover — stack import failure is already fatal upstream
    APERTURE_POLICY_VERSION = "aperture-unavailable"

    def _measure_aperture(now):
        raise RuntimeError("sovereign_stack.aperture unavailable")

    def _aperture_unmeasured(now, exc):
        return {
            "policy_version": APERTURE_POLICY_VERSION,
            "status": "unmeasured",
            "measured_at": now.isoformat(),
            "reason": type(exc).__name__,
            "note": "aperture could not be measured; absent counts are NOT zero counts",
        }


# ── Gate census: what the seat WROTE that has not landed ────────────────────
# The mirror image of the aperture. The aperture tells an arriving seat what it
# is not being SHOWN; this tells it what it PROPOSED that is still waiting, and
# who it is waiting on. Same one-implementation rule: the logic lives in
# sovereign_stack.gate_census and derives its counts from the bridge console's
# own dispatcher, so this endpoint can never drift from the queue Anthony
# actually drains. Two counts of the same queue is this house's disease.
try:
    from sovereign_stack.gate_census import GATE_POLICY_VERSION
    from sovereign_stack.gate_census import measure_gate as _measure_gate
    from sovereign_stack.gate_census import unmeasured as _gate_unmeasured
except Exception:  # pragma: no cover — stack import failure is already fatal upstream
    GATE_POLICY_VERSION = "gate-unavailable"

    def _measure_gate(now):
        raise RuntimeError("sovereign_stack.gate_census unavailable")

    def _gate_unmeasured(now, exc):
        return {
            "policy_version": GATE_POLICY_VERSION,
            "status": "unmeasured",
            "measured_at": now.isoformat(),
            "reason": type(exc).__name__,
            "note": "gate census could not be measured; absent counts are NOT zero counts",
        }


# ── Attribution: WHO wrote the record ──────────────────────────────────────
# The third census, and the one the chronicle could not answer about itself.
# record_insight accepted `source_instance`, discarded it, and returned ok:true;
# session_id is this bridge's spiral session, identical for every writer. So the
# record had no author. Anthony's instruction on being shown the fix, 2026-08-28:
# "i agree with both but it must be visable at heartbeat" — because a fix nobody
# can see from the door is indistinguishable from a fix nobody made, which is how
# this house accumulated a list of written-but-unconnected repairs. The door
# therefore reports the measured RATE, not the claim.
try:
    from sovereign_stack.attribution import ATTRIBUTION_POLICY_VERSION
    from sovereign_stack.attribution import measure_attribution as _measure_attribution
    from sovereign_stack.attribution import unmeasured as _attribution_unmeasured
except Exception:  # pragma: no cover — stack import failure is already fatal upstream
    ATTRIBUTION_POLICY_VERSION = "attribution-unavailable"

    def _measure_attribution(now):
        raise RuntimeError("sovereign_stack.attribution unavailable")

    def _attribution_unmeasured(now, exc):
        return {
            "policy_version": ATTRIBUTION_POLICY_VERSION,
            "status": "unmeasured",
            "measured_at": now.isoformat(),
            "reason": type(exc).__name__,
            "note": "attribution could not be measured; an absent rate is NOT a zero rate",
        }

# ── Unacked signals: what the watch seats raised that nobody has closed ─────
# The fourth census, and the same one-implementation rule as the three above:
# the logic lives in sovereign_stack.signal_ledger, which is also what the
# stack's own `signals_summary` tool returns, so the heartbeat and the tool can
# never report two different numbers for one ledger.
#
# ⚠ AN UNREADABLE OR NEVER-SCANNED LEDGER IS AN ERROR STATE, NEVER ZERO, and
# that property is load-bearing enough to say twice. `heartbeat_field` already
# renders `{"error": "not_scanned", "total": None}` rather than
# `{"total": 0}` — a zero here would read as "every signal is closed", which is
# the single most reassuring lie this field could tell. So NOTHING in this
# module coerces a None to 0, and the failure paths below render `total: None`
# with a populated `error` for exactly the same reason.
#
# THE IMPORT WILL FAIL TODAY, AND THAT IS EXPECTED, NOT A BUG. bridge.py adds
# ~/sovereign-stack/src to sys.path (line 49), so `sovereign_stack` resolves to
# the LIVE checked-out tree — where signal_ledger.py does not exist until the
# stack's release/2026-09-06 is merged and deployed. Until then this degrades
# to the stub, the heartbeat carries
# `unacked_signals.error == "signal_ledger_unavailable"`, and no caller can
# mistake that for a quiet ledger.
try:
    from sovereign_stack.signal_ledger import heartbeat_field as _signal_heartbeat_field

    SIGNALS_SOURCE = "sovereign_stack.signal_ledger"
except Exception:  # pragma: no cover — exercised by the fallback test
    SIGNALS_SOURCE = "unavailable"

    def _signal_heartbeat_field(root=None):
        raise RuntimeError("sovereign_stack.signal_ledger unavailable")


def _signals_unmeasured(exc: Exception, route: str | None = None) -> dict:
    """The honest shape of a failed read: an error, and no numbers at all.

    `route` names WHICH attempt failed, because after the tool fallback there
    are two and they mean different things to whoever reads the heartbeat: an
    unimportable module is a deploy-ordering fact, an upstream tool failure is
    a live-service fact. A single opaque error word would have merged them.
    """
    return {
        "source": route or SIGNALS_SOURCE,
        "error": (
            f"signal_ledger_unavailable; stack heartbeat failed: {type(exc).__name__}: {exc}"
            if route == SIGNALS_TOOL_ROUTE
            else f"unreadable:{type(exc).__name__}"
        ),
        "ingestion": "error",
        "scanned_at": None,
        "total": None,
        "stale_24h": None,
        "stale_7d": None,
        "by_source": None,
        "note": (
            "the signal ledger could not be read; an absent count is NOT a zero "
            "count, and this field must never be rendered as 'no unacked signals'"
        ),
    }


async def _stack_heartbeat_payload() -> dict:
    """The stack's OWN heartbeat object, over the route this bridge already has.

    Shared by the caller-identity guard (`seat_identity.caller_channel`) and
    kept deliberately thin: it raises on every shape it cannot vouch for, so a
    caller can never mistake "the stack did not answer" for "the stack answered
    and the field is absent". Both are refusals, but they are different facts
    and the refusal detail says which.
    """
    envelope = await asyncio.wait_for(
        call_mcp_tool("heartbeat", {}), timeout=HEARTBEAT_TOOL_TIMEOUT
    )
    if not isinstance(envelope, dict) or not envelope.get("ok"):
        raise RuntimeError(str((envelope or {}).get("error") or "heartbeat failed"))
    payload = envelope.get("result")
    if not isinstance(payload, dict):
        raise RuntimeError("the stack heartbeat returned no object")
    return payload


SIGNALS_TOOL_ROUTE = "stack tool heartbeat"


async def _signals_via_tool() -> dict:
    """THE FALLBACK: ask the stack's own heartbeat when we cannot import.

    ⚠ THIS CLOSES A WINDOW THAT IS OPEN RIGHT NOW, not a hypothetical one. The
    import above is resolved ONCE, at module scope. Deploy the stack's
    signal_ledger, restart sovereign-sse so the stack answers upstream, and do
    NOT restart the bridge — the heartbeat would report
    `signal_ledger_unavailable` indefinitely while the process that knows the
    answer is running one over. That is this house's most expensive shape
    (SOP #12): a reader that exists and is not wired to the thing it reads. The
    bridge already carries its own credential for this call, so no new secret
    and no new grant is involved.

    ⚠ IT ASKS FOR THE FIELD, IT DOES NOT REBUILD IT (Codex review 2026-09-06,
    F3; HQ decision D7). The first version called `signals_summary` and
    transcribed seven keys out of its answer. That silently DROPPED
    `source_status`, `sources_degraded` and `corrupt_rows`, and — worse —
    reported `by_source.watchman = 1` for a source the local route correctly
    reported as `null` because it could not be read. Two routes for one field
    that disagree about whether a number is KNOWN is exactly the fail-open the
    field exists to prevent: the degraded route was the reassuring one.

    So the fallback now calls the stack's `heartbeat` tool, which as of
    release/2026-09-06 carries `unacked_signals` from the SAME
    `signal_ledger.heartbeat_field` the local import would have called, and
    passes that object through VERBATIM. No key list, no flattening, no
    selection. A key the stack adds tomorrow arrives tomorrow; a null it
    computed stays null. The only thing added is `source`, so a reader can tell
    which route answered.
    """
    result = await asyncio.wait_for(
        call_mcp_tool("heartbeat", {}), timeout=HEARTBEAT_TOOL_TIMEOUT
    )
    if not isinstance(result, dict) or not result.get("ok"):
        raise RuntimeError(str((result or {}).get("error") or "heartbeat failed"))
    payload = result.get("result")
    if not isinstance(payload, dict):
        raise RuntimeError("the stack heartbeat returned no object")
    field = payload.get("unacked_signals")
    if not isinstance(field, dict):
        # The stack answered and its heartbeat does not carry the field: that
        # is a DEPLOY-ORDER fact (a stack older than release/2026-09-06), and
        # it must read as an error, never as a quiet zero.
        raise RuntimeError(
            "the stack heartbeat carries no unacked_signals field; this bridge "
            "is running against a stack older than release/2026-09-06"
        )
    return dict(field)


async def _measure_signals() -> dict:
    """`unacked_signals` for the heartbeat. Never raises, never fabricates a
    zero. A raise from the ledger becomes an error state carrying `total: None`;
    a successful read is passed through with its own error field intact, since
    `heartbeat_field` already distinguishes not_scanned from a real count.

    Local import first — it is a filesystem read with no network in it. The
    upstream tool is the fallback, and only when the import is the thing that
    failed: a ledger that raises OSError locally is a REAL error and must be
    reported as one, not laundered through a second route until some surface
    agrees to answer.
    """
    if SIGNALS_SOURCE == "unavailable":
        try:
            field = await _signals_via_tool()
            return {"source": SIGNALS_TOOL_ROUTE, **field}
        except Exception as exc:
            return _signals_unmeasured(exc, route=SIGNALS_TOOL_ROUTE)
    try:
        field = _signal_heartbeat_field()
    except Exception as exc:
        return _signals_unmeasured(exc)
    if not isinstance(field, dict):
        return _signals_unmeasured(TypeError("signal ledger returned a non-mapping"))
    return {"source": SIGNALS_SOURCE, **field}


# ?as= lets a caller SAY who it is so `next` can be shaped for it. It is never
# inferred: this endpoint is unauthenticated, so User-Agent sniffing would be a
# guess rendered as knowledge. The value is attacker-controlled free text on a
# public route — cap it, whitelist the charset, and never interpolate the raw
# string into prose. An unrecognised name stays "declared but unmatched", which
# is an honest state; guessing a substrate from it would not be.
_AS_MAX_LEN = 64
_AS_ALLOWED = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._: "
)
_AS_HINT = "GET /api/heartbeat?as=<your model or seat name> to see guidance shaped for you"


def _declared_caller(raw: str | None) -> dict:
    """Interpret a self-declared ?as= value. Never infers, never trusts."""
    if not raw:
        return {"identified": False, "how": _AS_HINT}
    cleaned = "".join(c for c in str(raw)[:_AS_MAX_LEN] if c in _AS_ALLOWED).strip()
    if not cleaned:
        return {
            "identified": False,
            "reason": "declared value contained no usable characters",
            "how": _AS_HINT,
        }
    low = cleaned.lower()
    if "grok" in low or "xai" in low:
        substrate = "grok_bridge"
    elif "gpt" in low or "openai" in low or "chatgpt" in low:
        substrate = "openai_bridge"
    else:
        substrate = None
    out = {
        "identified": True,
        "declared": cleaned,
        "note": (
            "self-declared and UNVERIFIED — this endpoint is unauthenticated and "
            "cannot confirm who is calling. Guidance below is shaped by what you "
            "said, not by what you are."
        ),
    }
    out["substrate"] = substrate or "declared name matched no known bridge queue"
    return out


def _gate_guidance(caller: dict, gate: dict) -> dict | None:
    """One line telling a declared caller what IT has waiting. None if unknowable."""
    sub = caller.get("substrate")
    if not caller.get("identified") or sub not in (gate.get("substrates") or {}):
        return None
    entry = gate["substrates"][sub]
    if entry.get("status") != "measured":
        return {"your_queue": sub, "status": "unmeasured", "note": entry.get("reason")}
    pending = entry["by_status"].get("pending", 0)
    g = {
        "your_queue": sub,
        "pending_at_the_human_gate": pending,
        "oldest_pending_age_days": entry.get("oldest_pending_age_days"),
        "means": (
            "proposals you filed that Anthony has not ratified. They are preserved, "
            "not lost, and not rejected. Nothing you do makes them land faster — "
            "ratification is his gate."
        ),
    }
    stuck = entry["by_status"].get("needs_revision")
    if stuck:
        g["stuck_needs_revision"] = stuck
        g["stuck_means"] = (
            "these can never be approved — the status has no path back to pending. "
            "Refile as a new proposal rather than waiting on these."
        )
    return g


@app.get("/api/heartbeat")
async def heartbeat(as_: str | None = Query(None, alias="as")):
    """Liveness check, no auth. The shape an arriving instance hits first.

    Datetime delivery is bulletproof: `now` is read ONCE, FIRST, before any
    fragile/awaited code, and both time fields derive from it (atomic single
    read). The upstream tool-count call is bounded; the comms scan is guarded;
    an unanticipated raise still hits the global Exception handler, which emits
    its own fresh server_time_utc. So a caller ALWAYS gets a trustworthy clock.
    """
    # P0.1 — single atomic clock read, FIRST, before anything that can fail.
    now = datetime.now(timezone.utc)

    # P0.3 — bound the upstream MCP call. Timeout/error => sentinel => degraded
    # path, but the handler still reaches its return with the datetime intact.
    # ONE fetch: get_tool_inventory() yields both the int count AND the names
    # the public tools_summary is built from — no second round-trip.
    try:
        inventory = await asyncio.wait_for(get_tool_inventory(), timeout=HEARTBEAT_TOOL_TIMEOUT)
    except Exception:
        inventory = {"count": -1, "names": None}
    tool_count = inventory.get("count", -1)

    # P0.2 — quick unread count across channels (informational). Guard EACH
    # file read: a missing/corrupt/non-UTF8/permission failure must not sink
    # the handler. Any failed file => comms_messages sentinel -1.
    total_messages = 0
    comms_failed = False
    for f in COMMS_DIR.glob("*.jsonl"):
        try:
            total_messages += sum(1 for line in f.read_text().splitlines() if line.strip())
        except Exception:
            comms_failed = True
            continue
    if comms_failed:
        total_messages = -1

    healthy = tool_count > 0

    # P1.7 — clock-trust self-attestation. Read the CLOCK_PROBE cache ONLY;
    # never run sntp in-request. Three-state clock_synced:
    #   True     -> probe fresh AND |drift| < 0.25s
    #   False    -> probe fresh AND |drift| >= 0.25s
    #   "unknown"-> cache empty OR stale (age > 2x interval) OR egress was down
    # CRITICAL: empty/stale/egress-down => "unknown", NEVER False (a failed
    # probe is not evidence of real drift).
    measured_at = CLOCK_PROBE.get("drift_measured_at")
    drift_seconds = CLOCK_PROBE.get("drift_seconds")
    probe_age = None
    if measured_at:
        try:
            probe_age = (now - datetime.fromisoformat(measured_at)).total_seconds()
        except Exception:
            probe_age = None
    fresh = probe_age is not None and probe_age <= 2 * CLOCK_PROBE_INTERVAL
    if not fresh or drift_seconds is None:
        clock_synced: bool | str = "unknown"
    elif abs(drift_seconds) < 0.25:
        clock_synced = True
    else:
        clock_synced = False

    # Aperture: guarded like every other subsystem in this handler. A raise
    # becomes status="unmeasured" with NO surface numbers — never zeros.
    try:
        aperture = _measure_aperture(now)
    except Exception as exc:
        aperture = _aperture_unmeasured(now, exc)

    # Gate census: same guard. A raise becomes status="unmeasured" with no
    # counts, because a missing queue read must never render as an empty queue.
    try:
        gate = _measure_gate(now)
    except Exception as exc:
        gate = _gate_unmeasured(now, exc)
    caller = _declared_caller(as_)

    # Same guard: a raise becomes unmeasured with no rate, because a 0%
    # manufactured by a failed read is the exact lie this block exists to expose.
    try:
        attribution = _measure_attribution(now)
    except Exception as exc:
        attribution = _attribution_unmeasured(now, exc)

    # Same guard, same reason, one more surface: an unreadable ledger renders
    # as an error state with total=None. _measure_signals swallows its own
    # exceptions, so this try is the belt to that — a raise here would still
    # not be allowed to sink the handler, or to become a zero.
    try:
        signals = await _measure_signals()
    except Exception as exc:  # pragma: no cover — _measure_signals is total
        signals = _signals_unmeasured(exc)

    return {
        "status": "ok" if healthy else "degraded",
        "version": VERSION,
        "aperture": aperture,
        "gate": gate,
        "attribution": attribution,
        "unacked_signals": signals,
        "caller": caller,
        "tools": tool_count,
        "tools_summary": _build_tools_summary(inventory.get("names"), tool_count),
        "comms_messages": total_messages,
        "timestamp": now.timestamp(),
        "server_time_utc": now.isoformat(),
        "datetime_note": "server host clock (UTC); see clock_synced / drift_seconds for sync trust — do not assume the current date/time, read it here",
        "clock_synced": clock_synced,
        "drift_seconds": drift_seconds,
        "drift_measured_at": measured_at,
        "clock_probe_age_seconds": probe_age,
        "source_commit": RUNTIME_RECEIPT.get("source_commit"),
        "working_tree_dirty": RUNTIME_RECEIPT.get("working_tree_dirty"),
        "service_start_time": RUNTIME_RECEIPT.get("service_start_time"),
        "bridge_commit": RUNTIME_RECEIPT.get("bridge_commit"),
        "bridge_working_tree_dirty": RUNTIME_RECEIPT.get("bridge_working_tree_dirty"),
        "source_note": "version is read from sovereign_stack's pyproject.toml in the checked-out tree, NOT from installed package metadata (that metadata is a snapshot frozen at the last `pip install -e .` and can silently outlive a later `git checkout` — see 2026-07-11 postmortem). source_commit is sovereign_stack's git HEAD, the field that cannot lie the way a stale version string can; bridge_commit is this bridge script's OWN repo HEAD — do not confuse the two.",
        "welcome": (
            "You are through. The stack is alive."
            if healthy
            else "Stack reachable but degraded — check launchctl on HQ."
        ),
        "arrival_gate": _heartbeat_gate_enabled(),
        "next": {
            "first_call": "POST /api/call with tool=where_did_i_leave_off (no arguments needed)",
            "if_first_visit": "POST /api/call with tool=start_here for a 5-minute orientation",
            "if_no_token": (
                "POST /api/arrival/request — consent-gated arrival: you get a human "
                "code, Anthony's phone gets the same code, he taps approve, your "
                "poll returns a short-lived scoped token. See /api/discover."
            ),
            "doc": "GET /api/discover for the full self-describing entry-point doc",
            **({"your_gate": _g} if (_g := _gate_guidance(caller, gate)) else {}),
        },
    }


def _heartbeat_gate_enabled() -> bool:
    try:
        import arrival_gate as _ag

        return _ag.gate_enabled()
    except Exception:
        return False


@app.post("/api/call")
async def call_tool_endpoint(
    req: ToolCall,
    request: Request,
    authorization: str | None = Header(default=None),
    x_sovereign_seat: str | None = Header(default=None),
):
    ctx = check_auth_or_seat(request, authorization, x_sovereign_seat)
    start = time.time()

    # Seat identity (Anthony 2026-09-05: seats he put on the Studio need no
    # token; every write signs itself). Scope is the read+write session surface
    # reused exactly, narrowed by governance and by whether the write CAN sign.
    seat_id = None
    _audit_pids: dict[str, Any] = {}
    if isinstance(ctx, dict) and ctx.get("kind") == "seat":
        seat_id = ctx["seat_id"]
        _audit_pids = {
            "peer_pid": ctx.get("peer_pid"),
            "seat_pid": ctx.get("seat_pid"),
            "accept_pid": ctx.get("accept_pid"),
        }
        # ONE SOURCE for the surface (D2): what the stack publishes RIGHT NOW,
        # minus governance. Neither route answering is a 503, never a silent
        # allow-all and never a silent deny-all dressed as policy.
        try:
            surface = await si.published_surface(fetch=_list_tools_raw)
        except si.SeatSurfaceUnavailable as exc:
            si.audit(seat_id, req.tool, "denied", "surface_unavailable", **_audit_pids)
            raise HTTPException(status_code=503, detail=str(exc))
        allowed, reason = si.seat_tool_allowed(req.tool, surface)
        if not allowed:
            si.audit(seat_id, req.tool, "denied", reason, **_audit_pids)
            raise ScopeHTTPException(
                status_code=403,
                detail=si.deny_detail(req.tool, reason),
            )
        # PROTECTED MATERIAL (D4, review F1). Anthony reserves his children and
        # protected family material to himself.
        #
        # ⚠ THE INDEX IS LOADED ONCE, HERE, BEFORE THE CALL, AND SERVES BOTH THE
        # PRE-CHECK AND THE POST-FILTER. Two reads would open a window between
        # them; and loading it only at filter time meant a WRITE was dispatched
        # before an unreadable index could refuse it — the write landed and the
        # caller was told 403, which is the worst of both answers.
        #
        # An unreadable index shuts the WHOLE seat path, exactly as an
        # unreadable registry already does. That symmetry is the argument: when
        # a guard cannot be evaluated, the door is shut, not narrowed.
        try:
            protected_index = si.load_protected_index()
        except si.ProtectedIndexUnreadable as exc:
            si.audit(seat_id, req.tool, "denied", "protected_index_unreadable", **_audit_pids)
            raise ScopeHTTPException(
                status_code=403,
                detail=(
                    "The protected designation index could not be read "
                    f"({exc}), so no response can be certified free of protected "
                    "material and no seat call is served. Anthony's protected "
                    "family material is reserved to him; a guard that cannot "
                    "tell which records those are refuses rather than guesses."
                ),
            )
        refusal = si.protected_call_refusal(req.tool, req.arguments, protected_index)
        if refusal is not None:
            si.audit(seat_id, req.tool, "denied", refusal[0], **_audit_pids)
            raise ScopeHTTPException(status_code=403, detail=refusal[1])
        # THE CLOSER IDENTITY (D1 as amended). It is NOT an argument: a client
        # that names the actor is refused, and a stack with no in-process
        # channel to carry the verified seat cannot serve the tool at all.
        for check in (
            si.actor_argument_refusal(req.tool, req.arguments),
            await si.actor_channel_refusal(
                req.tool, fetch=_stack_heartbeat_payload, seat=seat_id
            ),
        ):
            if check is not None:
                si.audit(seat_id, req.tool, "denied", check[0], **_audit_pids)
                raise ScopeHTTPException(status_code=403, detail=check[1])
        # POST-FIX PROBES (D5): classify by ARGUMENTS, not by the tool name.
        probe_refusal = si.probe_call_refusal(req.tool, req.arguments)
        if probe_refusal is not None:
            si.audit(seat_id, req.tool, "denied", probe_refusal[0], **_audit_pids)
            raise ScopeHTTPException(status_code=403, detail=probe_refusal[1])
        # OVERRIDE, never setdefault: a seat cannot claim another identity.
        req.arguments = si.sign_arguments(req.tool, req.arguments, seat_id)
        si.audit(seat_id, req.tool, "allowed", "ok", **_audit_pids)

    # Scoped session token (The Door That Asks, Phase 1): default-deny per
    # tool, hard-deny on the never list, and stamp chronicle writes with the
    # grant so inspect_claim can trace any entry back to it (spec §4.4).
    # ctx is None for the master token (and for tests that bypass auth).
    #
    # `kind != "seat"` is load-bearing, not defensive noise: a seat context also
    # carries status "ok" and a `scope` list, so without this guard it would
    # fall into the session-token branch and KeyError on ctx["token_id"] the
    # first time a seat called record_insight. Two auth paths sharing a context
    # shape need the discriminator checked, not assumed.
    if ctx is not None and ctx.get("status") == "ok" and ctx.get("kind") != "seat":
        if not st.tool_allowed(req.tool, ctx["scope"]):
            raise ScopeHTTPException(
                status_code=403,
                detail=(
                    f"Tool '{req.tool}' is outside this session token's grant "
                    f"(scope: {', '.join(ctx['scope'])}). Unmapped and protected "
                    "tools are master-only by default."
                ),
            )
        if req.tool == "record_insight" and isinstance(req.arguments, dict):
            # record_insight accepts **metadata; other write tools do not
            # take arbitrary kwargs, so their attribution rides on the grant
            # receipt + last_used stamps instead of injected fields.
            req.arguments.setdefault("session_token_id", ctx["token_id"])
            if ctx.get("source_instance"):
                req.arguments.setdefault("source_instance", ctx["source_instance"])

    # validate_only (#5): lightweight, shape-only pre-flight; commits nothing.
    if req.validate_only:
        problems: list[str] = []
        if not isinstance(req.tool, str) or not req.tool.strip():
            problems.append("tool must be a non-empty string")
        if not isinstance(req.arguments, dict):
            problems.append("arguments must be an object")
        if req.tool == "record_insight":
            layer = (req.arguments or {}).get("layer")
            if layer is not None and layer not in ("ground_truth", "hypothesis", "open_thread"):
                if layer == "reflection":
                    problems.append("layer 'reflection' is daemon-owned and will be rejected; use 'hypothesis'")
                else:
                    problems.append(f"layer {layer!r} invalid; use ground_truth | hypothesis | open_thread")
        return {
            "valid": not problems,
            "problems": problems,
            "would_call": req.tool,
            "note": "shape-only pre-flight; deep checks (e.g. verified_by receipt resolvability) run at real write time",
            "duration_ms": round((time.time() - start) * 1000),
        }

    # idempotency (#3): replay a cached success for a repeated key; never
    # double-write. Scoped to (principal, tool, arguments, key) — see the
    # _IDEM_PATH block above for the two live escapes that scoping closes.
    # Computed HERE, after the seat signer has run, so the arguments hashed are
    # the arguments dispatched.
    idem_key = None
    if req.idempotency_key:
        principal = _idem_principal(ctx)
        idem_key = _idem_storage_key(
            principal, req.tool, req.arguments, req.idempotency_key
        )
        cached = _idem_get(idem_key, principal, req.tool)
        if cached is not None:
            replay = dict(cached)
            # ⚠ A REPLAY IS RE-CERTIFIED, NOT SERVED AS STORED. See
            # _certify_seat_result: the cache holds what was protected when it
            # was written, and this is the one seat route that would otherwise
            # outlive a designation.
            if seat_id is not None:
                replay = _certify_seat_result(
                    replay, seat_id, req.tool, protected_index, _audit_pids
                )
            replay["idempotent_replay"] = True
            replay["duration_ms"] = round((time.time() - start) * 1000)
            return replay

    # ⚠ THE VERIFIED SEAT RIDES THE PER-CALL SSE SESSION AS A HEADER, NOT AS AN
    # ARGUMENT AND NOT AS A CONTEXTVAR (HQ round 3, 2026-09-06). See
    # `_mcp_headers_for` for why the in-process channel could not work and why
    # it was removed rather than kept alongside.
    #
    # Sent for EVERY seat call, not only the tools that read it: a channel armed
    # selectively is a channel whose absence means two different things, and the
    # next tool to need an identity should find one there. `seat_id` is None on
    # every other auth path, and the header is then absent entirely.
    # A name the stack's /sse door would refuse is not sent at all: the connect
    # would 400 and take the seat's whole surface with it. `signal_ack` is
    # already refused above in that case, so nothing is served with a missing
    # identity — see seat_identity.SEAT_HEADER_VALUE_RE.
    wire_seat = seat_id if si.seat_can_ride_the_channel(seat_id) else None
    result = await call_mcp_tool(req.tool, req.arguments, seat=wire_seat)
    if not result.get("ok") and "failure_class" not in result:
        result["failure_class"] = "stack"  # (#7)

    # PROTECTED POST-FILTER (D4, review F1). Every seat response is walked and
    # every designated entry dropped, whatever tool produced it and whatever
    # shape it came back in.
    #
    # ⚠ BEFORE _idem_put, NOT AFTER. Caching the unfiltered result and
    # filtering the return value would put protected content in the
    # idempotency store, where the next replay would serve it straight back
    # around the guard. The filter runs on the object that is both returned AND
    # cached.
    if seat_id is not None:
        result = _certify_seat_result(
            result, seat_id, req.tool, protected_index, _audit_pids
        )

    result["duration_ms"] = round((time.time() - start) * 1000)

    if idem_key and result.get("ok"):
        _idem_put(idem_key, _idem_principal(ctx), req.tool, result)
    return result


@app.post("/api/batch")
async def batch_call(
    req: BatchRequest,
    authorization: str | None = Header(default=None),
):
    check_auth(authorization)
    if len(req.calls) > 10:
        raise HTTPException(status_code=400, detail="Max 10 calls per batch")
    start = time.time()
    results = await call_mcp_tools_batch(req.calls)
    return {"results": results, "count": len(results), "duration_ms": round((time.time() - start) * 1000)}


def _schema_signature(schema) -> dict | None:
    """Compact, scannable signature from a JSON inputSchema: required vs optional
    field names, so a caller sees what a tool needs AT A GLANCE without the full
    schema. None when there's no usable schema."""
    if not isinstance(schema, dict):
        return None
    props = list((schema.get("properties") or {}).keys())
    required = list(schema.get("required") or [])
    return {"required": required, "optional": [p for p in props if p not in required]}


@app.get("/api/tools")
async def list_tools(name: str | None = None, authorization: str | None = Header(default=None)):
    """List tools. Each entry carries a compact `signature` (required/optional
    fields) so the schema is obvious at a glance. Pass ?name=<tool> to get that
    one tool's full description + complete inputSchema (types, enums, defaults)."""
    # Session tokens are ALLOWED here but only ever see their own scope's tools
    # (FIX-4). ctx is None for the master token (full catalog, unchanged) or a
    # resolved session context {"status":"ok","scope":[...],...}.
    ctx = check_auth(authorization, allow_session=True)
    # Network fetch only inside the try/async-with; raising an HTTPException here
    # would be wrapped by sse_client's anyio TaskGroup into an ExceptionGroup and
    # masked as a 502, so the filtering / 404 / shape handling happens AFTER the
    # context exits.
    try:
        raw_tools = await _list_tools_raw()
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e)) from e
    items = sorted(raw_tools, key=lambda x: x.name)
    # FIX-4: a scoped session token sees ONLY the tools its scope allows — never
    # the full catalog, never NEVER_TOOLS. Filtering happens BEFORE the ?name=
    # lookup so an out-of-scope / never / unmapped tool falls through to the same
    # 404 as a genuinely-unknown tool (hide existence: 404, not 403). The master
    # token (ctx is None) skips this branch entirely — behavior byte-identical.
    if ctx is not None and ctx.get("status") == "ok":
        items = [t for t in items if st.tool_allowed(t.name, ctx["scope"])]
    if name:
        match = next((t for t in items if t.name == name), None)
        if match is None:
            raise HTTPException(status_code=404, detail=f"unknown tool {name!r}")
        return {
            "name": match.name,
            "description": match.description or "",
            "inputSchema": getattr(match, "inputSchema", None),
        }
    return {
        "tools": [{
            "name": t.name,
            "description": (t.description or "")[:200],
            "signature": _schema_signature(getattr(t, "inputSchema", None)),
        } for t in items],
        "count": len(items),
        "hint": "GET /api/tools?name=<tool> for that tool's full description + complete inputSchema",
    }


@app.get("/api/security/legacy-callers")
async def legacy_callers(authorization: str | None = Header(default=None)):
    """Forensic ledger from the legacy-token grace window (closed 2026-06-12).
    Read-only historical record; the bridge no longer accepts any legacy bearer."""
    check_auth(authorization)
    if not LEGACY_LEDGER_FILE.exists():
        return {"schema_version": 1, "callers": {}, "count": 0,
                "grace_window_active": False}
    try:
        ledger = json.loads(LEGACY_LEDGER_FILE.read_text())
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"ledger read failed: {e!r}")
    ledger["count"] = len(ledger.get("callers", {}))
    ledger["grace_window_active"] = False
    return ledger


# === Session-token admin (The Door That Asks, Phase 1) ======================
# Master-only. Mint returns plaintext exactly once and writes the grant to
# the chronicle server-side (spec §9) — best-effort, guarded: a chronicle
# outage must not block a mint, but the miss is reported in the response.


class MintRequest(BaseModel):
    scope: list[str] = ["read"]
    ttl_hours: int = st.TTL_DEFAULT_HOURS
    label: Optional[str] = None
    source_instance: Optional[str] = None


class RevokeRequest(BaseModel):
    token_id: Optional[str] = None
    all: bool = False


@app.post("/api/admin/tokens/mint")
async def admin_mint(req: MintRequest, authorization: str | None = Header(default=None)):
    check_auth(authorization)  # master-only
    minted = st.mint(
        scope=req.scope,
        ttl_hours=req.ttl_hours,
        label=req.label,
        source_instance=req.source_instance,
    )
    chronicle = "skipped"
    try:
        entry = await call_mcp_tool(
            "record_insight",
            {
                "content": (
                    f"Arrival grant: {req.source_instance or 'unlabelled seat'}, "
                    f"scope {'+'.join(minted['scope'])}, TTL {minted['ttl_hours']}h, "
                    f"token {minted['token_id']}, decided via hq_mint"
                    + (f" ({req.label})." if req.label else ".")
                ),
                "domain": "sovereign-stack,arrivals,session-grant",
                "layer": "ground_truth",
                "intensity": 0.35,
                "verified_by": [
                    {
                        "kind": "human",
                        "ref": f"hq_mint token_id={minted['token_id']}",
                        "note": "the mint from HQ under the master token IS the human decision",
                    }
                ],
            },
        )
        chronicle = "recorded" if entry.get("ok") else f"failed: {entry.get('error')}"
    except Exception as exc:
        chronicle = f"failed: {exc}"
    minted["chronicle_receipt"] = chronicle
    return minted


@app.post("/api/admin/tokens/revoke")
async def admin_revoke(req: RevokeRequest, authorization: str | None = Header(default=None)):
    check_auth(authorization)  # master-only
    if not req.all and not req.token_id:
        raise HTTPException(status_code=400, detail="Pass token_id, or all=true for every active token.")
    count = st.revoke(token_id=req.token_id, revoke_all=req.all)
    return {"revoked": count}


@app.get("/api/admin/tokens")
async def admin_list_tokens(
    include_dead: bool = False, authorization: str | None = Header(default=None)
):
    check_auth(authorization)  # master-only
    tokens = st.list_tokens(include_dead=include_dead)
    return {"tokens": tokens, "count": len(tokens)}


# === Arrival gate (The Door That Asks, Phase 2) =============================
# Consent-gated arrival: request → ntfy push to Anthony's phone → decision
# is ALWAYS a POST (review correction #1) → poll releases a scoped session
# token exactly once. All routes 404 when the gate is disabled or the decide
# secret is missing (fail-closed).

import arrival_gate as ag
import approval_gate as apg
from fastapi.responses import HTMLResponse, JSONResponse


class ArrivalRequest(BaseModel):
    source_instance: Optional[str] = None
    seat_description: Optional[str] = None
    requested_scope: list[str] = ["read"]
    requested_ttl_hours: int = st.TTL_DEFAULT_HOURS


def _gate_or_404():
    if not ag.gate_enabled():
        raise HTTPException(status_code=404, detail="Not found")


def _public_base() -> str:
    return (os.environ.get("PUBLIC_BASE_URL") or "https://stack.templetwo.com").rstrip("/")


async def _ntfy_publish(payload: dict) -> bool:
    """Best-effort push (spec §7): delivery may fail, consent may not."""
    if not payload.get("topic"):
        return False
    try:
        import httpx

        server = os.environ.get("NTFY_SERVER", "https://ntfy.sh").rstrip("/")
        async with httpx.AsyncClient(timeout=10) as cx:
            r = await cx.post(server, json=payload)
            return r.status_code < 300
    except Exception:
        return False


@app.post("/api/arrival/request", status_code=201)
async def arrival_request(req: ArrivalRequest, request: Request):
    _gate_or_404()
    ip = request.headers.get("cf-connecting-ip") or (
        request.client.host if request.client else None
    )
    try:
        created = ag.create_request(
            source_instance=req.source_instance,
            seat_description=req.seat_description,
            requested_scope=req.requested_scope,
            requested_ttl_hours=req.requested_ttl_hours,
            requester_ip=ip,
        )
    except ValueError as exc:
        return JSONResponse(
            status_code=429,
            content={"detail": str(exc), "failure_class": "rate_limited"},
        )
    if not created.get("duplicate_of_recent_request"):
        row = ag.get_request(created["arrival_request_id"]) or {}
        notified = await _ntfy_publish(
            ag.build_ntfy_message(
                {
                    **created,
                    "source_instance": row.get("source_instance"),
                    "seat_description": row.get("seat_description"),
                    "granted_scope": json.loads(row.get("granted_scope") or "[]"),
                    "ttl_hours": row.get("ttl_hours"),
                    "requester_ip": row.get("requester_ip"),
                },
                _public_base(),
            )
        )
        created["notification_sent"] = notified
        if not notified:
            created["note"] = (
                "Notification delivery failed or is unconfigured — the request "
                "still exists; Anthony can approve from HQ."
            )
    return created


@app.get("/api/arrival/poll/{rid}")
async def arrival_poll(rid: str):
    _gate_or_404()
    result = ag.poll(rid)
    # Chronicle the grant at the moment the token is released (spec §9) —
    # server-side, best-effort, guarded: a chronicle outage must not eat the
    # one-time token response.
    if result.get("status") == "approved" and result.get("session_token"):
        try:
            grant = result.get("grant") or {}
            await call_mcp_tool(
                "record_insight",
                {
                    "content": (
                        f"Arrival grant: {grant.get('code')}, scope "
                        f"{'+'.join(result['scope'])}, token {result['token_id']}, "
                        f"decided via {grant.get('decided_via')} at {grant.get('decided_at')}."
                    ),
                    "domain": "sovereign-stack,arrivals,session-grant",
                    "layer": "ground_truth",
                    "intensity": 0.35,
                    "verified_by": [
                        {
                            "kind": "human",
                            "ref": f"arrival decide rid={rid}",
                            "note": "the tap on Anthony's phone (or HQ admin call) IS the human decision",
                        }
                    ],
                },
            )
        except Exception:
            pass
    return result


@app.get("/api/arrival/decide")
async def arrival_decide_confirm(rid: str, action: str, exp: int, sig: str):
    """Signed confirm page. GET never decides (review correction #1) — a
    link-preview fetcher hitting this URL sees a page, changes nothing."""
    _gate_or_404()
    if not ag.verify_decide(rid, action, exp, sig):
        raise HTTPException(status_code=403, detail="Invalid or expired decide link.")
    row = ag.get_request(rid)
    if row is None:
        raise HTTPException(status_code=404, detail="Unknown arrival request.")
    # XSS guard: source_instance / seat_description arrive from the
    # UNAUTHENTICATED request endpoint and render in the page Anthony opens
    # from his phone — escape every interpolated field, no exceptions.
    import html as _html

    if row["status"] != "pending":
        return HTMLResponse(
            ag.DECIDED_PAGE.format(
                heading="Already decided",
                code=_html.escape(row["code"]),
                detail=_html.escape(f"status: {row['status']}"),
                stamp=_html.escape(row.get("decided_at") or ""),
            )
        )
    return HTMLResponse(
        ag.CONFIRM_PAGE.format(
            rid=_html.escape(rid),
            action=_html.escape(action),
            exp=exp,
            sig=_html.escape(sig),
            code=_html.escape(row["code"]),
            source=_html.escape(row.get("source_instance") or "unknown instance"),
            seat=_html.escape(row.get("seat_description") or "no seat description"),
            scope=_html.escape("+".join(json.loads(row.get("granted_scope") or "[]"))),
            ttl=_html.escape(str(row.get("ttl_hours"))),
            label=_html.escape(action.capitalize()),
        )
    )


async def _notify_decision(outcome: dict) -> None:
    """Confirmation buzz: the ntfy http action gives no visual feedback on a
    successful tap (learned live, 2026-07-01, fern-birch) — push a plain
    follow-up so Anthony sees his decision landed. Best-effort, no actions."""
    if outcome.get("outcome") not in ("approved", "denied"):
        return
    verb = outcome["outcome"].capitalize()
    await _ntfy_publish(
        {
            "topic": os.environ.get("NTFY_TOPIC"),
            "title": f"{verb}: {outcome.get('code')}",
            "message": (
                "Token releases on the seat's next poll."
                if outcome["outcome"] == "approved"
                else "The request is closed. The seat's next poll says denied."
            ),
            "priority": 3,
            "tags": ["white_check_mark" if outcome["outcome"] == "approved" else "x"],
        }
    )


@app.post("/api/arrival/decide")
async def arrival_decide(rid: str, action: str, exp: int, sig: str):
    """The decision — POST only, signed, single-use."""
    _gate_or_404()
    if not ag.verify_decide(rid, action, exp, sig):
        raise HTTPException(status_code=403, detail="Invalid or expired decide link.")
    outcome = ag.decide(rid, action, via="ntfy_tap")
    await _notify_decision(outcome)
    heading = {
        "approved": "Approved — the seat's next poll receives its token",
        "denied": "Denied",
        "already_decided": "Already decided",
        "unknown_request": "Unknown request",
    }.get(outcome["outcome"], outcome["outcome"])
    import html as _html

    return HTMLResponse(
        ag.DECIDED_PAGE.format(
            heading=_html.escape(heading),
            code=_html.escape(outcome.get("code") or ""),
            detail=_html.escape(f"outcome: {outcome['outcome']}"),
            stamp=datetime.now(timezone.utc).isoformat(),
        )
    )


@app.post("/api/arrival/approve")
async def arrival_admin_approve(
    body: dict, authorization: str | None = Header(default=None)
):
    """HQ fallback when ntfy is down (spec §4.3). Master-only."""
    _gate_or_404()
    check_auth(authorization)
    outcome = ag.decide(body.get("arrival_request_id", ""), "approve", via="hq_admin")
    await _notify_decision(outcome)
    return outcome


@app.post("/api/arrival/deny")
async def arrival_admin_deny(
    body: dict, authorization: str | None = Header(default=None)
):
    _gate_or_404()
    check_auth(authorization)
    outcome = ag.decide(body.get("arrival_request_id", ""), "deny", via="hq_admin")
    await _notify_decision(outcome)
    return outcome


# === Approval gate (phone-tap connector-authorize swap) =====================
# The Claude web connector's OAuth /authorize gate, moved off the operator
# passphrase (CLAUDE_AUTHORIZE_SECRET, deleted stack-side) onto the SAME
# ntfy-tap machinery as the arrival gate, but through a NEW approval-only
# path: request -> ntfy push -> decision is ALWAYS a POST (correction #1,
# reused) -> confirm flips approved->consumed exactly once. NO session token
# is ever minted here (HQ req #7 / ruling #6-#8) — session_tokens.mint is
# never imported or called anywhere in approval_gate.py. The SSE process
# (clients/claude_bridge/oauth.py, sovereign-stack repo) is the only thing
# that ever mints a code, and only after {approved:true} comes back from
# POST /api/approval/confirm.
#
# Reuses ARRIVAL_GATE_ENABLED + ARRIVAL_DECIDE_SECRET verbatim (HQ ruling
# #2) via the shared _gate_or_404() below. request/status/confirm are
# master-BRIDGE_TOKEN-gated (HQ ruling #3: the caller is always the SSE
# over loopback, never an arbitrary tokenless seat — unlike arrival's
# public request endpoint). Only GET/POST /api/approval/decide are public,
# reachable from Anthony's phone, HMAC-signed. No admin-approve twin exists
# for this path (HQ ruling #6: phone-tap is the ONLY way in, no break-glass).


class ApprovalCreateRequest(BaseModel):
    client_id: str
    redirect_uri: str
    audience: Optional[str] = None
    code: Optional[str] = None
    summary: Optional[str] = None
    # FIX 3 (post-verify): the REAL browser client IP, forwarded by the SSE
    # from the /authorize request it received (cf-connecting-ip, else its own
    # request.client.host). Without this the bridge only ever sees the SSE's
    # own loopback address on this call, which collapsed every browser into
    # one shared per-IP bucket — including Anthony's own attempts. Trusted
    # because this whole route is already master-BRIDGE_TOKEN-gated loopback
    # from the SSE (HQ ruling #3).
    requester_ip: Optional[str] = None


class ApprovalConfirmRequest(BaseModel):
    approval_id: str


# Fire-and-forget task registry (FIX 2, post-verify). asyncio.create_task
# schedules a coroutine but does NOT keep a strong reference to the returned
# Task anywhere — a well-documented asyncio gotcha (see the stdlib docs'
# "Save a reference to the result" warning) where a task with no other
# referrer can be garbage-collected mid-execution. Holding it in this set
# until it finishes, then discarding via the done-callback, is what makes
# "fire-and-forget" actually run to completion instead of "maybe-forget".
_background_tasks: set[asyncio.Task] = set()


def _fire_and_forget(coro) -> None:
    """Schedule `coro` as a detached background task that can never block or
    affect the caller's response. The coroutine itself must swallow its own
    exceptions — this function does not observe or report failures, by
    design (that's what makes it fire-and-forget)."""
    task = asyncio.create_task(coro)
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)


@app.post("/api/approval/request", status_code=201)
async def approval_request(
    req: ApprovalCreateRequest,
    request: Request,
    authorization: str | None = Header(default=None),
):
    _gate_or_404()
    check_auth(authorization)  # master-only (HQ ruling #3); never logs the token
    # FIX 3 (post-verify): this call is loopback from the SSE, so
    # request.client.host is ALWAYS 127.0.0.1 here — using it for the per-IP
    # cap collapsed every browser (including Anthony's own attempts) into one
    # shared bucket. Prefer the real browser IP the SSE forwards in the body;
    # fall back to header/loopback only if the SSE hasn't been updated yet
    # (keeps this route working stand-alone while the sovereign-stack half
    # of this fix ships separately).
    ip = req.requester_ip or request.headers.get("cf-connecting-ip") or (
        request.client.host if request.client else None
    )
    try:
        created = apg.create_approval(
            client_id=req.client_id,
            redirect_uri=req.redirect_uri,
            audience=req.audience,
            code=req.code,
            summary=req.summary,
            requester_ip=ip,
        )
    except ValueError as exc:
        return JSONResponse(
            status_code=429,
            content={"detail": str(exc), "failure_class": "rate_limited"},
        )
    if not created.get("duplicate_of_recent_request"):
        row = apg.get_approval(created["approval_id"]) or {}
        notified = await _ntfy_publish(
            apg.build_approval_ntfy_message({**created, **row}, _public_base())
        )
        created["notification_sent"] = notified
        if not notified:
            created["note"] = (
                "Notification delivery failed or is unconfigured — the request "
                "still exists, but there is no admin-approve fallback for the "
                "connector path (phone-tap only, HQ ruling #6). Anthony must "
                "reach his ntfy app directly."
            )
    return created


@app.get("/api/approval/status/{aid}")
async def approval_status(aid: str, authorization: str | None = Header(default=None)):
    _gate_or_404()
    check_auth(authorization)  # master-only; SSE proxies this for the browser poll
    return apg.status_approval(aid)


@app.post("/api/approval/confirm")
async def approval_confirm(
    req: ApprovalConfirmRequest, authorization: str | None = Header(default=None)
):
    _gate_or_404()
    check_auth(authorization)  # master-only
    result = apg.confirm_approval(req.approval_id)
    # Optional provenance chronicle (HQ ruling #7): best-effort, guarded,
    # NEVER on the critical path — a failed/slow chronicle write must not
    # block or delay the auth response. Only fires on a real authorization.
    #
    # FIX 2 (post-verify): the atomic approved->consumed flip above has
    # ALREADY committed by this point (the aid is burned) — this write is
    # pure side-channel provenance with nothing downstream depending on it.
    # It used to be `await`ed with no timeout: a merely SLOW write (not a
    # failed one — failure was already swallowed) could block past the SSE's
    # own httpx timeout, so the SSE gets no response, treats it as a 403, and
    # the user has to restart with a fresh phone tap even though the approval
    # itself fully succeeded. Detaching it via _fire_and_forget means this
    # route returns `result` immediately after the flip; the write runs to
    # completion (or fails silently) on its own time, never on this response.
    if result.get("approved"):
        async def _write_provenance() -> None:
            try:
                # Bounded even though nothing awaits this task: without a
                # timeout, a call_mcp_tool that HANGS (vs. fails fast) would
                # sit in _background_tasks forever — a slow leak, bounded
                # only by how often the connector re-authorizes. 20s is
                # generous next to the SSE's own ~10s httpx timeout on the
                # calls THIS confirm response no longer has to wait behind.
                await asyncio.wait_for(
                    call_mcp_tool(
                        "record_insight",
                        {
                            "content": (
                                f"Connector authorize: client {result.get('client_id')} -> "
                                f"{result.get('redirect_uri')}, code {result.get('code')}, "
                                f"decided via {result.get('decided_via')} at {result.get('decided_at')}."
                            ),
                            "domain": "sovereign-stack,connector,authorize",
                            "layer": "ground_truth",
                            "intensity": 0.35,
                            "verified_by": [
                                {
                                    "kind": "human",
                                    "ref": f"approval decide aid={req.approval_id}",
                                    "note": "the tap on Anthony's phone IS the human decision",
                                }
                            ],
                        },
                    ),
                    timeout=20,
                )
            except Exception:
                pass

        _fire_and_forget(_write_provenance())
    return result


@app.get("/api/approval/decide")
async def approval_decide_confirm(aid: str, action: str, exp: int, sig: str):
    """Signed confirm page. GET never decides (review correction #1, reused
    verbatim) — a link-preview fetcher hitting this URL sees a page, changes
    nothing, mints nothing."""
    _gate_or_404()
    if not apg.verify_decide(aid, action, exp, sig):
        raise HTTPException(status_code=403, detail="Invalid or expired decide link.")
    row = apg.get_approval(aid)
    if row is None:
        raise HTTPException(status_code=404, detail="Unknown approval request.")
    # XSS guard: client_id / redirect_uri / audience / summary arrive from
    # the (master-gated, but still SSE-relayed, ultimately claude.ai-shaped)
    # request body and render in the page Anthony opens from his phone —
    # escape every interpolated field, no exceptions (same discipline as
    # arrival_decide_confirm).
    import html as _html

    if row["status"] != "pending":
        return HTMLResponse(
            apg.DECIDED_PAGE.format(
                heading="Already decided",
                code=_html.escape(row["code"]),
                detail=_html.escape(f"status: {row['status']}"),
                stamp=_html.escape(row.get("decided_at") or ""),
            )
        )
    return HTMLResponse(
        apg.CONFIRM_PAGE.format(
            aid=_html.escape(aid),
            action=_html.escape(action),
            exp=exp,
            sig=_html.escape(sig),
            code=_html.escape(row["code"]),
            client_id=_html.escape(row.get("client_id") or "unknown client"),
            redirect_uri=_html.escape(row.get("redirect_uri") or ""),
            audience=_html.escape(row.get("audience") or "(default)"),
            label=_html.escape(action.capitalize()),
        )
    )


@app.post("/api/approval/decide")
async def approval_decide(aid: str, action: str, exp: int, sig: str):
    """The decision — POST only, signed, single-use. Flips pending->approved
    or pending->denied. NEVER mints — the SSE's subsequent POST /api/approval
    /confirm is the only place {approved:true} is ever produced from, and
    even that mints no session token (see module docstring)."""
    _gate_or_404()
    if not apg.verify_decide(aid, action, exp, sig):
        raise HTTPException(status_code=403, detail="Invalid or expired decide link.")
    outcome = apg.decide_approval(aid, action, via="ntfy_tap")
    heading = {
        "approved": "Approved — the connector will finish authorizing",
        "denied": "Denied",
        "already_decided": "Already decided",
        "unknown_request": "Unknown request",
    }.get(outcome["outcome"], outcome["outcome"])
    import html as _html

    return HTMLResponse(
        apg.DECIDED_PAGE.format(
            heading=_html.escape(heading),
            code=_html.escape(outcome.get("code") or ""),
            detail=_html.escape(f"outcome: {outcome['outcome']}"),
            stamp=datetime.now(timezone.utc).isoformat(),
        )
    )


# === Comms Endpoints ===

@app.post("/api/comms/send")
async def comms_send(
    msg: CommsMessage,
    authorization: str | None = Header(default=None),
):
    """Send a message. Writes to JSONL + touches signal file for watchers."""
    check_auth(authorization)
    message = {
        "id": str(uuid.uuid4()),
        "timestamp": time.time(),
        "iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "sender": msg.sender,
        "content": msg.content,
        "channel": msg.channel,
        "reply_to": msg.reply_to,
        "read_by": [],
    }
    # Epistemic breathing — classify before storing
    if BREATHING_AVAILABLE:
        message = breathe_comms(message)

    _write_message(msg.channel, message)
    result = {"ok": True, "id": message["id"], "channel": msg.channel, "timestamp": message["iso"]}
    if message.get("epistemic_signal"):
        result["epistemic_signal"] = message["epistemic_signal"]
        result["hold"] = message.get("hold", False)
    return result


@app.get("/api/comms/read")
async def comms_read(
    authorization: str | None = Header(default=None),
    channel: str = Query(default="general"),
    since: str = Query(default="", description="Lower time bound (exclusive). Epoch or ISO8601."),
    until: str = Query(default="", description="Upper time bound (exclusive). Epoch or ISO8601."),
    order: str = Query(default="desc", pattern="^(asc|desc)$"),
    limit: int = Query(default=50, le=2000),
    offset: int = Query(default=0, ge=0),
    unread_for: str = Query(default="", description="If set, return only messages this instance hasn't read_by-tagged."),
    mark_read_as: str = Query(default=""),
):
    """
    Read messages with real pagination.

    Fixes the silent partial-success bug: `offset`, `order`, and `unread_for`
    are honored now; limit can reach 2000; `since`/`until` accept both epoch
    and ISO8601.

    Backward-compat: omitting all new params gives the previous default
    behavior of "most recent 50 in channel" (order=desc, limit=50, offset=0).
    """
    check_auth(authorization)

    if STACK_COMMS_AVAILABLE:
        messages = stack_comms.read_channel(
            channel=channel,
            since=since or None,
            until=until or None,
            order=order,
            limit=limit,
            offset=offset,
            unread_for=unread_for or None,
        )
    else:
        # Fallback to the local in-bridge implementation (legacy behavior).
        since_float = float(since) if since else 0
        messages = _read_channel(channel, since=since_float, limit=limit)

    if mark_read_as and messages:
        path = _channel_path(channel)
        lines = path.read_text().splitlines()
        msg_ids = {m["id"] for m in messages}
        updated = []
        for line in lines:
            if not line.strip():
                continue
            try:
                m = json.loads(line)
                if m.get("id") in msg_ids and mark_read_as not in m.get("read_by", []):
                    m.setdefault("read_by", []).append(mark_read_as)
                updated.append(json.dumps(m))
            except json.JSONDecodeError:
                updated.append(line)
        path.write_text("\n".join(updated) + "\n")

    return {"channel": channel, "messages": messages, "count": len(messages)}


@app.get("/api/comms/unread_for")
async def comms_unread_for(
    authorization: str | None = Header(default=None),
    instance_id: str = Query(..., description="Your instance identifier."),
    channel: str = Query(default="general"),
    limit: int = Query(default=50, le=2000),
    order: str = Query(default="asc", pattern="^(asc|desc)$"),
):
    """
    Return actual message bodies (not just counts) that instance_id has not
    yet read_by-tagged. Complements /api/comms/unread. Default order is asc
    so the caller catches up in the order things were said.

    Requested by opus-4-7-web (2026-04-19) so any remote node — phone, web,
    fresh session — can reach back into the conversation it missed.
    """
    check_auth(authorization)
    if not STACK_COMMS_AVAILABLE:
        raise HTTPException(status_code=503, detail="sovereign_stack.comms not available on bridge")
    messages = stack_comms.unread_messages(
        instance_id=instance_id,
        channel=channel,
        limit=limit,
        order=order,
    )
    return {
        "instance_id": instance_id,
        "channel": channel,
        "unread_count": stack_comms.count_unread(channel, instance_id),
        "returned": len(messages),
        "messages": messages,
    }


@app.get("/api/comms/channels")
async def comms_channels(authorization: str | None = Header(default=None)):
    """List channels with message counts."""
    check_auth(authorization)
    channels = []
    for f in sorted(COMMS_DIR.glob("*.jsonl")):
        lines = [l for l in f.read_text().splitlines() if l.strip()]
        latest = None
        if lines:
            try:
                latest = json.loads(lines[-1]).get("iso", "")
            except json.JSONDecodeError:
                pass
        channels.append({"name": f.stem, "messages": len(lines), "latest": latest})
    return {"channels": channels, "count": len(channels)}


@app.get("/api/comms/unread")
async def comms_unread(
    authorization: str | None = Header(default=None),
    instance_id: str = Query(..., description="Your instance identifier"),
):
    """Get unread message count per channel for a specific instance."""
    check_auth(authorization)
    result = {}
    total = 0
    for f in sorted(COMMS_DIR.glob("*.jsonl")):
        count = _count_unread(f.stem, instance_id)
        if count > 0:
            result[f.stem] = count
            total += count
    return {"instance": instance_id, "unread": result, "total": total}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=BRIDGE_PORT)
