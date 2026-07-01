"""Scoped session tokens for the Sovereign Bridge — Phase 1 of The Door That Asks.

Spec: consent-gated arrival, DRAFT v1.0 (2026-07-01, claude-fable-5 web seat,
relayed by Anthony), implemented with the four HQ review corrections:
scope-map fixes, default-deny on non-/api/call routes, house 401/403
semantics, SQLite for atomic one-time state transitions.

Design invariants (spec §10):
  * Plaintext tokens exist in exactly one HTTP response / one stdout. The
    store holds sha256 hashes only. Nothing here logs plaintext.
  * No session token, at any scope, can mint/revoke tokens, call set_policy,
    or touch the protected drawer (reads included).
  * The master bridge token's semantics are untouched — resolution of the
    master token never reaches this module.

Storage is SQLite (not the house JSON-file pattern) deliberately: the
exactly-once token release in Phase 2 and use_count increments here need
atomic transactions that a JSON file cannot give under concurrent polls.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

DB_PATH = Path(os.path.expanduser("~/.sovereign/bridge/session_tokens.db"))

TOKEN_PREFIX = "svs_"
TTL_MIN_HOURS = 1
TTL_MAX_HOURS = 24
TTL_DEFAULT_HOURS = 12

# ── Scope model (spec §6, corrected in HQ review 2026-07-01) ─────────────────
#
# Default-deny: a tool with no mapping here is refused to session tokens and
# allowed to the master token. A newly added stack tool is master-only until
# someone deliberately classifies it.
#
# Review corrections applied:
#   * check_mistakes moved write → read (it searches learnings, writes nothing)
#   * where_did_i_leave_off NOT in read — it consumes handoffs (side effect);
#     scoped seats arrive through arrive_lineage.
#   * close_session / spiral_inherit pulled out of write into a separate
#     'session' scope — they mutate global spiral state and are granted
#     deliberately, never bundled.
TOOL_SCOPES: dict[str, str] = {
    # read — orientation + recall, no side effects
    "arrive_lineage": "read",
    "start_here": "read",
    "my_toolkit": "read",
    "recall_insights": "read",
    "recall_reflections": "read",
    "get_open_threads": "read",
    "current_policies": "read",
    "inspect_claim": "read",
    "ask_scribe": "read",
    "season_review": "read",
    "compass_check": "read",
    "check_mistakes": "read",
    "spiral_status": "read",
    # write — chronicle authorship (read is NOT implied; grant both when meant)
    "record_insight": "write",
    "record_open_thread": "write",
    "handoff": "write",
    "archive_exchange": "write",
    "reflection_ack": "write",
    "spiral_reflect": "write",
    # session — global spiral-state mutation, granted deliberately
    "close_session": "session",
    "spiral_inherit": "session",
}

GRANTABLE_SCOPES = ("read", "write", "session")

# Never grantable / never reachable by session tokens regardless of scope
# (spec §6 "never" list). These are hard-denied even if a mapping above were
# ever added by mistake — belt and suspenders.
NEVER_TOOLS = frozenset(
    {
        "set_policy",
        "designate_protected",
        "list_protected_thresholds",
        "open_protected_record",
        "decline_protected_record",
        "audit_decoupling",
    }
)


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS session_tokens (
            token_id        TEXT PRIMARY KEY,
            token_hash      TEXT UNIQUE NOT NULL,
            scope           TEXT NOT NULL,
            source_instance TEXT,
            arrival_request_id TEXT,
            label           TEXT,
            issued_at       TEXT NOT NULL,
            expires_at      TEXT NOT NULL,
            revoked_at      TEXT,
            last_used_at    TEXT,
            use_count       INTEGER NOT NULL DEFAULT 0
        )
        """
    )
    return conn


def _now() -> datetime:
    return datetime.now(timezone.utc)


def clamp_ttl(ttl_hours: int | float | None) -> int:
    if ttl_hours is None:
        return TTL_DEFAULT_HOURS
    return max(TTL_MIN_HOURS, min(TTL_MAX_HOURS, int(ttl_hours)))


def clamp_scope(requested: list[str] | None) -> list[str]:
    """Silently reduce to grantable scopes (spec §4.1). Empty → read."""
    granted = [s for s in (requested or []) if s in GRANTABLE_SCOPES]
    return granted or ["read"]


def mint(
    scope: list[str] | None = None,
    ttl_hours: int | None = None,
    label: str | None = None,
    source_instance: str | None = None,
    arrival_request_id: str | None = None,
) -> dict:
    """Create a session token. Returns the plaintext token EXACTLY ONCE —
    the caller is responsible for it never being stored or logged."""
    granted = clamp_scope(scope)
    ttl = clamp_ttl(ttl_hours)
    token = TOKEN_PREFIX + secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    token_id = token_hash[:12]
    issued = _now()
    expires = issued + timedelta(hours=ttl)
    with _connect() as conn:
        conn.execute(
            "INSERT INTO session_tokens (token_id, token_hash, scope, source_instance,"
            " arrival_request_id, label, issued_at, expires_at) VALUES (?,?,?,?,?,?,?,?)",
            (
                token_id,
                token_hash,
                json.dumps(granted),
                source_instance,
                arrival_request_id,
                label,
                issued.isoformat(),
                expires.isoformat(),
            ),
        )
    return {
        "session_token": token,  # plaintext — the one appearance
        "token_id": token_id,
        "scope": granted,
        "ttl_hours": ttl,
        "expires_at": expires.isoformat(),
    }


def resolve(token: str) -> dict:
    """Resolve a bearer that starts with TOKEN_PREFIX.

    Returns {"status": "ok", "token_id", "scope", "source_instance"} on a
    live token (and atomically stamps last_used_at / use_count), or
    {"status": "unknown" | "expired" | "revoked"}.
    """
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    now = _now()
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM session_tokens WHERE token_hash = ?", (token_hash,)
        ).fetchone()
        if row is None:
            return {"status": "unknown"}
        if row["revoked_at"]:
            return {"status": "revoked"}
        if now > datetime.fromisoformat(row["expires_at"]):
            return {"status": "expired"}
        conn.execute(
            "UPDATE session_tokens SET last_used_at = ?, use_count = use_count + 1"
            " WHERE token_id = ?",
            (now.isoformat(), row["token_id"]),
        )
        return {
            "status": "ok",
            "token_id": row["token_id"],
            "scope": json.loads(row["scope"]),
            "source_instance": row["source_instance"],
        }


def tool_allowed(tool: str, scopes: list[str]) -> bool:
    """Default-deny scope check for session tokens (spec §6)."""
    if tool in NEVER_TOOLS:
        return False
    required = TOOL_SCOPES.get(tool)
    if required is None:
        return False  # unmapped → master-only
    return required in scopes


def revoke(token_id: str | None = None, revoke_all: bool = False) -> int:
    """Revoke one token by id, or every active token. Returns count revoked."""
    now = _now().isoformat()
    with _connect() as conn:
        if revoke_all:
            cur = conn.execute(
                "UPDATE session_tokens SET revoked_at = ? WHERE revoked_at IS NULL", (now,)
            )
        elif token_id:
            cur = conn.execute(
                "UPDATE session_tokens SET revoked_at = ? WHERE token_id = ? AND revoked_at IS NULL",
                (now, token_id),
            )
        else:
            return 0
        return cur.rowcount


def list_tokens(include_dead: bool = False) -> list[dict]:
    """Active tokens (or all with include_dead). Never returns plaintext —
    plaintext is never stored, so it cannot."""
    now = _now()
    out = []
    with _connect() as conn:
        for row in conn.execute(
            "SELECT token_id, label, scope, source_instance, issued_at, expires_at,"
            " revoked_at, last_used_at, use_count FROM session_tokens ORDER BY issued_at DESC"
        ):
            alive = not row["revoked_at"] and now <= datetime.fromisoformat(row["expires_at"])
            if not alive and not include_dead:
                continue
            d = dict(row)
            d["scope"] = json.loads(d["scope"])
            d["status"] = (
                "active" if alive else ("revoked" if row["revoked_at"] else "expired")
            )
            out.append(d)
    return out
