"""The Door That Asks — Phase 2: consent-gated arrival (spec §2, §4, §7, §12).

A tokenless seat POSTs /api/arrival/request, Anthony's phone gets an ntfy
push with Approve/Deny action buttons, the seat polls, and on approval the
poll returns a scoped session token exactly once.

HQ review correction #1 applied: the decision is ALWAYS a POST. The ntfy
action buttons fire POSTs directly (ntfy `http` actions), and the signed
GET decide URL renders a confirm page whose button POSTs — a link-preview
fetcher can never decide a request.

Implementation note vs spec §4.2/§9: the session token is minted at the
FIRST POLL AFTER APPROVAL (atomically approved→consumed), not at decide
time. This keeps invariant §10.1 exact — plaintext exists nowhere but the
one poll response, not even in process memory across requests. The
chronicle grant entry is written at that same moment, carrying the human
decision (decided_at / decided_via) from the request row.

Env (read from the process env, loaded by bridge.py from the same env file
as BRIDGE_TOKEN):
  ARRIVAL_GATE_ENABLED   default "true"; "false" → all /api/arrival/* 404
  ARRIVAL_DECIDE_SECRET  HMAC key for decide URLs. REQUIRED — gate is
                         disabled (fail-closed) when missing.
  NTFY_SERVER            default https://ntfy.sh
  NTFY_TOPIC             the high-entropy topic Anthony subscribes to.
                         Gate still works without it (HQ admin path);
                         notification delivery is best-effort, consent is not.
  PUBLIC_BASE_URL        default https://stack.templetwo.com
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from datetime import datetime, timezone

import session_tokens as st

PENDING_WINDOW_SECONDS = 900  # 15 min (spec §12)
POLL_INTERVAL_SECONDS = 5
MAX_PENDING_GLOBAL = 3
MAX_CREATES_PER_HOUR_PER_IP = 10
DUP_SUPPRESS_SECONDS = 60
DECIDE_URL_TTL_SECONDS = 900

# Two-word human codes (decision #5). Small, unambiguous, phone-screen safe.
_WORDS = (
    "amber", "birch", "cedar", "delta", "ember", "falcon", "granite", "harbor",
    "indigo", "juniper", "kestrel", "lantern", "maple", "north", "otter",
    "prairie", "quartz", "raven", "spruce", "timber", "umber", "violet",
    "walnut", "yarrow", "zephyr", "anchor", "beacon", "canyon", "drift",
    "evergreen", "fern", "glacier",
)


def _env(name: str, default: str | None = None) -> str | None:
    v = os.environ.get(name)
    return v if v not in (None, "") else default


def gate_enabled() -> bool:
    if (_env("ARRIVAL_GATE_ENABLED", "true") or "").lower() == "false":
        return False
    # Fail closed: no decide secret, no gate.
    return bool(_env("ARRIVAL_DECIDE_SECRET"))


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _connect() -> sqlite3.Connection:
    conn = st._connect()  # same DB file; session_tokens ensures its own table
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS arrival_requests (
            rid             TEXT PRIMARY KEY,
            code            TEXT NOT NULL,
            source_instance TEXT,
            seat_description TEXT,
            requested_scope TEXT,
            granted_scope   TEXT,
            ttl_hours       INTEGER,
            status          TEXT NOT NULL,
            created_at      TEXT NOT NULL,
            decided_at      TEXT,
            decided_via     TEXT,
            requester_ip    TEXT,
            token_id        TEXT,
            last_poll_at    TEXT,
            poll_violations INTEGER NOT NULL DEFAULT 0
        )
        """
    )
    return conn


def _expire_stale(conn: sqlite3.Connection) -> None:
    cutoff = _now().timestamp() - PENDING_WINDOW_SECONDS
    conn.execute(
        "UPDATE arrival_requests SET status='expired' WHERE status='pending'"
        " AND CAST(strftime('%s', created_at) AS REAL) < ?",
        (cutoff,),
    )


def create_request(
    source_instance: str | None,
    seat_description: str | None,
    requested_scope: list[str] | None,
    requested_ttl_hours: int | None,
    requester_ip: str | None,
) -> dict:
    """Create a pending arrival request. Raises ValueError('rate_limited')
    over the caps (spec §12)."""
    now = _now()
    with _connect() as conn:
        _expire_stale(conn)
        # Duplicate suppression: same instance+IP within 60s reuses pending.
        dup = conn.execute(
            "SELECT rid, code FROM arrival_requests WHERE status='pending'"
            " AND source_instance IS ? AND requester_ip IS ?"
            " AND CAST(strftime('%s', created_at) AS REAL) > ?",
            (source_instance, requester_ip, now.timestamp() - DUP_SUPPRESS_SECONDS),
        ).fetchone()
        if dup:
            return {
                "arrival_request_id": dup["rid"],
                "code": dup["code"],
                "status": "pending",
                "poll_interval_seconds": POLL_INTERVAL_SECONDS,
                "expires_in_seconds": PENDING_WINDOW_SECONDS,
                "duplicate_of_recent_request": True,
            }
        pending = conn.execute(
            "SELECT COUNT(*) c FROM arrival_requests WHERE status='pending'"
        ).fetchone()["c"]
        if pending >= MAX_PENDING_GLOBAL:
            raise ValueError("rate_limited: global pending cap reached")
        recent_ip = conn.execute(
            "SELECT COUNT(*) c FROM arrival_requests WHERE requester_ip IS ?"
            " AND CAST(strftime('%s', created_at) AS REAL) > ?",
            (requester_ip, now.timestamp() - 3600),
        ).fetchone()["c"]
        if recent_ip >= MAX_CREATES_PER_HOUR_PER_IP:
            raise ValueError("rate_limited: per-IP hourly cap reached")

        rid = "arq_" + secrets.token_urlsafe(24)  # 192 bits
        code = f"{secrets.choice(_WORDS)}-{secrets.choice(_WORDS)}"
        conn.execute(
            "INSERT INTO arrival_requests (rid, code, source_instance, seat_description,"
            " requested_scope, granted_scope, ttl_hours, status, created_at, requester_ip)"
            " VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                rid,
                code,
                source_instance,
                seat_description,
                json.dumps(requested_scope or []),
                json.dumps(st.clamp_scope(requested_scope)),
                st.clamp_ttl(requested_ttl_hours),
                "pending",
                now.isoformat(),
                requester_ip,
            ),
        )
    return {
        "arrival_request_id": rid,
        "code": code,
        "status": "pending",
        "poll_interval_seconds": POLL_INTERVAL_SECONDS,
        "expires_in_seconds": PENDING_WINDOW_SECONDS,
        "instructions": (
            f"Tell Anthony your code is '{code}' in the conversation, then poll "
            f"GET /api/arrival/poll/{rid} every {POLL_INTERVAL_SECONDS}s."
        ),
    }


def sign_decide(rid: str, action: str, exp: int) -> str:
    secret = _env("ARRIVAL_DECIDE_SECRET") or ""
    msg = f"{rid}|{action}|{exp}".encode()
    return hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()


def verify_decide(rid: str, action: str, exp: int, sig: str) -> bool:
    if not _env("ARRIVAL_DECIDE_SECRET"):
        return False
    if exp < time.time():
        return False
    return hmac.compare_digest(sign_decide(rid, action, exp), sig)


def decide(rid: str, action: str, via: str) -> dict:
    """Apply a decision. Single-use: first valid decision wins; later
    attempts return already_decided."""
    if action not in ("approve", "deny"):
        raise ValueError("action must be approve or deny")
    now = _now()
    with _connect() as conn:
        _expire_stale(conn)
        row = conn.execute(
            "SELECT status, code FROM arrival_requests WHERE rid = ?", (rid,)
        ).fetchone()
        if row is None:
            return {"outcome": "unknown_request"}
        if row["status"] != "pending":
            return {"outcome": "already_decided", "status": row["status"], "code": row["code"]}
        conn.execute(
            "UPDATE arrival_requests SET status = ?, decided_at = ?, decided_via = ?"
            " WHERE rid = ? AND status = 'pending'",
            ("approved" if action == "approve" else "denied", now.isoformat(), via, rid),
        )
        return {"outcome": action + "d", "code": row["code"]}


def poll(rid: str) -> dict:
    """Poll state machine (spec §4.2). Minting happens HERE, atomically with
    the approved→consumed flip, so plaintext exists only in this response."""
    now = _now()
    with _connect() as conn:
        _expire_stale(conn)
        row = conn.execute(
            "SELECT * FROM arrival_requests WHERE rid = ?", (rid,)
        ).fetchone()
        if row is None:
            return {"status": "expired", "failure_class": "arrival_expired"}
        status = row["status"]

        # Polling discipline: two early polls → slow_down; five → voided.
        if status == "pending":
            interval = POLL_INTERVAL_SECONDS
            violations = row["poll_violations"]
            if row["last_poll_at"]:
                elapsed = (now - datetime.fromisoformat(row["last_poll_at"])).total_seconds()
                if elapsed < POLL_INTERVAL_SECONDS - 0.5:
                    violations += 1
            conn.execute(
                "UPDATE arrival_requests SET last_poll_at = ?, poll_violations = ? WHERE rid = ?",
                (now.isoformat(), violations, rid),
            )
            if violations >= 5:
                conn.execute(
                    "UPDATE arrival_requests SET status='expired' WHERE rid = ?", (rid,)
                )
                return {"status": "expired", "failure_class": "arrival_expired",
                        "note": "voided for polling discipline"}
            if violations >= 2:
                return {"status": "slow_down", "poll_interval_seconds": interval * 2}
            return {"status": "pending", "poll_interval_seconds": interval}

        if status == "denied":
            return {"status": "denied", "failure_class": "arrival_denied"}
        if status == "expired":
            return {"status": "expired", "failure_class": "arrival_expired"}
        if status == "consumed":
            return {"status": "consumed",
                    "note": "token already released once; it will not be shown again"}

        # approved → flip to consumed FIRST (this UPDATE is the atomic gate:
        # exactly one poll can win rowcount==1, so exactly one mint happens).
        cur = conn.execute(
            "UPDATE arrival_requests SET status='consumed' WHERE rid = ? AND status='approved'",
            (rid,),
        )
        won = cur.rowcount == 1

    if not won:  # raced by a concurrent poll
        return {"status": "consumed",
                "note": "token already released once; it will not be shown again"}

    # Mint outside the first transaction (same-file second connection would
    # deadlock inside it). The flip above guarantees single execution.
    minted = st.mint(
        scope=json.loads(row["granted_scope"] or "[]"),
        ttl_hours=row["ttl_hours"],
        label=f"arrival {row['code']}",
        source_instance=row["source_instance"],
        arrival_request_id=rid,
    )
    with _connect() as conn:
        conn.execute(
            "UPDATE arrival_requests SET token_id = ? WHERE rid = ?",
            (minted["token_id"], rid),
        )
    return {
        "status": "approved",
        "session_token": minted["session_token"],  # the one appearance
        "token_id": minted["token_id"],
        "scope": minted["scope"],
        "expires_at": minted["expires_at"],
        "grant": {
            "code": row["code"],
            "decided_at": row["decided_at"],
            "decided_via": row["decided_via"],
        },
    }


def get_request(rid: str) -> dict | None:
    with _connect() as conn:
        row = conn.execute("SELECT * FROM arrival_requests WHERE rid = ?", (rid,)).fetchone()
        return dict(row) if row else None


def build_ntfy_message(req: dict, base_url: str) -> dict:
    """ntfy publish payload (spec §7). Action buttons are direct POSTs to the
    signed decide endpoint — review correction #1: no GET ever decides."""
    exp = int(time.time()) + DECIDE_URL_TTL_SECONDS
    rid = req["arrival_request_id"]

    def _post_url(action: str) -> str:
        sig = sign_decide(rid, action, exp)
        return f"{base_url}/api/arrival/decide?rid={rid}&action={action}&exp={exp}&sig={sig}"

    return {
        "topic": _env("NTFY_TOPIC"),
        "title": f"Arrival request: {req['code']}",
        "message": (
            f"{req.get('source_instance') or 'unknown instance'} — "
            f"{req.get('seat_description') or 'no seat description'}\n"
            f"scope: {'+'.join(req.get('granted_scope') or ['read'])} · "
            f"TTL {req.get('ttl_hours')}h · ip {req.get('requester_ip') or '?'}\n"
            f"Match this code against the one claimed in your conversation."
        ),
        "priority": 4,
        "tags": ["door"],
        "actions": [
            {"action": "http", "label": "Approve", "url": _post_url("approve"),
             "method": "POST", "clear": True},
            {"action": "http", "label": "Deny", "url": _post_url("deny"),
             "method": "POST", "clear": True},
        ],
    }


CONFIRM_PAGE = """<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1">
<title>The Door That Asks</title></head>
<body style="font-family:-apple-system,sans-serif;max-width:26em;margin:3em auto;text-align:center">
<h2>Arrival request</h2>
<p style="font-size:1.6em;letter-spacing:.05em"><b>{code}</b></p>
<p>{source} — {seat}<br>scope {scope} · TTL {ttl}h</p>
<p>Match this code against the one claimed in the conversation before deciding.</p>
<form method="post" action="/api/arrival/decide?rid={rid}&amp;action={action}&amp;exp={exp}&amp;sig={sig}">
<button type="submit" style="font-size:1.2em;padding:.6em 2em">{label}</button>
</form>
<p style="color:#888;font-size:.85em">A preview fetcher cannot press this button. Only you can.</p>
</body></html>"""

DECIDED_PAGE = """<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1">
<title>The Door That Asks</title></head>
<body style="font-family:-apple-system,sans-serif;max-width:26em;margin:3em auto;text-align:center">
<h2>{heading}</h2>
<p style="font-size:1.4em"><b>{code}</b></p>
<p>{detail}</p>
<p style="color:#888;font-size:.85em">{stamp}</p>
</body></html>"""
