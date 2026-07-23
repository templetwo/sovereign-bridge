"""The Door That Asks — connector-authorize approval (phone-tap authorize,
build spec §2, HQ rulings 2026-07-23).

An approval-ONLY sibling of arrival_gate.py: request -> ntfy push to
Anthony's phone -> decision is ALWAYS a POST (reuses review correction #1)
-> confirm flips approved->consumed exactly once. Unlike arrival_gate.poll(),
NOTHING here ever calls session_tokens.mint. A connector authorization is a
yes/no gate for a code the SSE process mints itself (clients/claude_bridge/
oauth.py, sovereign-stack repo) — the bridge stays a generic approval oracle
and never touches session_tokens.db for this flow (HQ ruling #6/#8).

Reused from arrival_gate.py (import, don't fork):
  - sign_decide / verify_decide  — generic over rid|action|exp; an approval
    id (aid) is passed in the same positional slot arrival calls "rid".
  - _WORDS + the two-word code convention (decision #5) — exposed here as
    generate_code(), used as a defensive fallback if a caller omits `code`;
    the primary path (spec §2) has the SSE supply its own code so the same
    string can render on both the waiting page and the phone.
  - gate_enabled() — ARRIVAL_GATE_ENABLED / ARRIVAL_DECIDE_SECRET are
    reused verbatim, not forked (HQ ruling #2: disabling the arrival gate
    also disables connector re-authorization, by design).
  - DECIDED_PAGE — generic ({heading}/{code}/{detail}/{stamp}), no
    arrival-specific fields or hardcoded path, so it is imported verbatim.

NOT reused verbatim: CONFIRM_PAGE. Arrival's template hardcodes both the
POST target (`/api/arrival/decide`) and arrival-only fields (source, seat,
scope, ttl) into the string — importing it as-is would submit the phone's
"Approve" tap to the wrong endpoint. A same-styled sibling template
(APPROVAL fields, `/api/approval/decide` target) is defined below instead,
matching arrival's CSS/structure/escaping discipline exactly.

New: its own `approval_requests` table (separate caps from arrival's
`arrival_requests` — sharing MAX_PENDING_GLOBAL would let pending connector
authorizes and pending seat-arrivals starve each other for the same 3
slots). Same underlying DB file (via session_tokens._connect()) purely for
the proven atomic-transaction technique; a fully separate table means the
two pending-caps are already disjoint regardless of file layout.
"""

from __future__ import annotations

import secrets
import sqlite3
import time
from datetime import datetime, timezone

import arrival_gate as ag
import session_tokens as st

PENDING_WINDOW_SECONDS = 900  # 15 min, same window as arrival (spec §12 parity)
POLL_INTERVAL_SECONDS = 5
# FIX 3 (post-verify): the connector PENDING cap is PER-IP, not global — the
# old MAX_PENDING_GLOBAL=3 was fillable by an unauthenticated attacker hitting
# the public DCR + GET /authorize, locking Anthony out with no break-glass
# (HQ ruling #6 means there's no admin-approve escape hatch). Per-IP keeps an
# attacker who does not control Anthony's IP from ever touching his budget;
# the (much higher) global figure is only a backstop against a botnet filling
# the table across many IPs, not a per-caller limit anymore.
MAX_PENDING_PER_IP = 3
MAX_PENDING_GLOBAL = 50
MAX_CREATES_PER_HOUR_PER_IP = 10
DUP_SUPPRESS_SECONDS = 60
DECIDE_URL_TTL_SECONDS = 900

# Reused verbatim — generic over rid|action|exp; both already key off the
# SAME env var (ARRIVAL_DECIDE_SECRET) per HQ ruling #2, so no new secret.
sign_decide = ag.sign_decide
verify_decide = ag.verify_decide
gate_enabled = ag.gate_enabled

# Reused verbatim — no hardcoded path, no arrival-only fields.
DECIDED_PAGE = ag.DECIDED_PAGE


def generate_code() -> str:
    """Two-word human code, same generator/word-list as arrival's (decision
    #5). Defensive fallback only — the primary path has the SSE supply its
    own code (build spec §2 line 20) so one string renders identically on
    the waiting page and the phone push."""
    return f"{secrets.choice(ag._WORDS)}-{secrets.choice(ag._WORDS)}"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _connect() -> sqlite3.Connection:
    conn = st._connect()  # same DB file; each module ensures its own table
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS approval_requests (
            aid             TEXT PRIMARY KEY,
            code            TEXT NOT NULL,
            summary         TEXT,
            client_id       TEXT NOT NULL,
            redirect_uri    TEXT NOT NULL,
            audience        TEXT,
            status          TEXT NOT NULL,
            created_at      TEXT NOT NULL,
            decided_at      TEXT,
            decided_via     TEXT,
            requester_ip    TEXT,
            last_poll_at    TEXT,
            poll_violations INTEGER NOT NULL DEFAULT 0
        )
        """
    )
    return conn


def _expire_stale(conn: sqlite3.Connection) -> None:
    cutoff = _now().timestamp() - PENDING_WINDOW_SECONDS
    conn.execute(
        "UPDATE approval_requests SET status='expired' WHERE status='pending'"
        " AND CAST(strftime('%s', created_at) AS REAL) < ?",
        (cutoff,),
    )


def create_approval(
    client_id: str,
    redirect_uri: str,
    audience: str | None,
    code: str | None,
    summary: str | None,
    requester_ip: str | None,
) -> dict:
    """Create a pending approval request. Mirrors arrival's create_request:
    dup-suppression on client_id+ip within 60s, its OWN pending + per-IP
    caps (separate namespace from arrival_requests). No scope, no ttl, no
    clamp_scope/clamp_ttl — a connector authorize is a yes/no, not a grant.
    Raises ValueError('rate_limited: ...') over the caps.

    `requester_ip` must be the REAL browser client IP (FIX 3, post-verify) —
    the SSE forwards it from the /authorize request it received (cf-connecting-
    ip, else its own request.client.host), NOT the loopback address the bridge
    itself sees on the SSE->bridge call. Trusting a caller-supplied IP is safe
    here because create_approval is only ever reached through the master-
    BRIDGE_TOKEN-gated /api/approval/request route (HQ ruling #3)."""
    now = _now()
    code = code or generate_code()
    with _connect() as conn:
        _expire_stale(conn)
        dup = conn.execute(
            "SELECT aid, code FROM approval_requests WHERE status='pending'"
            " AND client_id IS ? AND requester_ip IS ?"
            " AND CAST(strftime('%s', created_at) AS REAL) > ?",
            (client_id, requester_ip, now.timestamp() - DUP_SUPPRESS_SECONDS),
        ).fetchone()
        if dup:
            return {
                "approval_id": dup["aid"],
                "code": dup["code"],
                "status": "pending",
                "poll_interval_seconds": POLL_INTERVAL_SECONDS,
                "expires_in_seconds": PENDING_WINDOW_SECONDS,
                "duplicate_of_recent_request": True,
                # Optional fix (post-verify): no NEW push fires on the dup
                # path — leaving this key absent let the SSE default it to
                # True and the waiting page claim "push sent" when none did.
                "notification_sent": False,
            }
        # FIX 3: per-IP pending cap first (an attacker not controlling
        # Anthony's IP can never touch his budget), THEN the global backstop
        # (bounds a multi-IP botnet from filling the table outright).
        pending_ip = conn.execute(
            "SELECT COUNT(*) c FROM approval_requests WHERE status='pending'"
            " AND requester_ip IS ?",
            (requester_ip,),
        ).fetchone()["c"]
        if pending_ip >= MAX_PENDING_PER_IP:
            raise ValueError("rate_limited: per-IP pending cap reached")
        pending_global = conn.execute(
            "SELECT COUNT(*) c FROM approval_requests WHERE status='pending'"
        ).fetchone()["c"]
        if pending_global >= MAX_PENDING_GLOBAL:
            raise ValueError("rate_limited: global pending cap reached")
        recent_ip = conn.execute(
            "SELECT COUNT(*) c FROM approval_requests WHERE requester_ip IS ?"
            " AND CAST(strftime('%s', created_at) AS REAL) > ?",
            (requester_ip, now.timestamp() - 3600),
        ).fetchone()["c"]
        if recent_ip >= MAX_CREATES_PER_HOUR_PER_IP:
            raise ValueError("rate_limited: per-IP hourly cap reached")

        aid = "apr_" + secrets.token_urlsafe(24)  # 192 bits, same shape as arrival's rid
        conn.execute(
            "INSERT INTO approval_requests (aid, code, summary, client_id, redirect_uri,"
            " audience, status, created_at, requester_ip)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            (
                aid,
                code,
                summary,
                client_id,
                redirect_uri,
                audience,
                "pending",
                now.isoformat(),
                requester_ip,
            ),
        )
    return {
        "approval_id": aid,
        "code": code,
        "status": "pending",
        "poll_interval_seconds": POLL_INTERVAL_SECONDS,
        "expires_in_seconds": PENDING_WINDOW_SECONDS,
    }


def decide_approval(aid: str, action: str, via: str) -> dict:
    """Apply a decision. Single-use: first valid decision wins; later
    attempts return already_decided. Identical shape to arrival's decide()."""
    if action not in ("approve", "deny"):
        raise ValueError("action must be approve or deny")
    now = _now()
    with _connect() as conn:
        _expire_stale(conn)
        row = conn.execute(
            "SELECT status, code FROM approval_requests WHERE aid = ?", (aid,)
        ).fetchone()
        if row is None:
            return {"outcome": "unknown_request"}
        if row["status"] != "pending":
            return {"outcome": "already_decided", "status": row["status"], "code": row["code"]}
        conn.execute(
            "UPDATE approval_requests SET status = ?, decided_at = ?, decided_via = ?"
            " WHERE aid = ? AND status = 'pending'",
            ("approved" if action == "approve" else "denied", now.isoformat(), via, aid),
        )
        return {"outcome": action + "d", "code": row["code"]}


def status_approval(aid: str) -> dict:
    """READ-ONLY status. Applies the same 900s expiry window as arrival's
    poll() (via _expire_stale above), but performs NO state flip and NO mint
    for 'approved' — that only happens inside confirm_approval(). This is
    what makes it safe for the browser to poll freely without ever releasing
    anything.

    FIX 1 (post-verify): this path is MASTER-gated end to end — the ONLY
    poller is the trusted SSE, polling on behalf of exactly one browser at
    ~5s intervals (build spec §3d). Arrival's poll() anti-abuse throttle
    (slow_down at 2 violations, force-expire/void at 5) was written for an
    UNAUTHENTICATED, arbitrary-caller endpoint and does not apply here — it
    was breaking ORDINARY use, because a background-tab browser routinely
    clusters its 5s-interval polls under the 4.5s threshold, which voided the
    row mid-wait and the connector waiting-page JS (which only branches
    approved / pending|unavailable / else) fell into `else` and aborted with
    `error=access_denied`. So: no slow_down is ever returned, and poll count
    can never force-expire or void a row. Only the 900s pending-window expiry
    (_expire_stale, same as arrival) can end a pending approval. last_poll_at
    is still recorded for observability, but it is bookkeeping ONLY — it must
    never change the returned status."""
    now = _now()
    with _connect() as conn:
        _expire_stale(conn)
        row = conn.execute(
            "SELECT * FROM approval_requests WHERE aid = ?", (aid,)
        ).fetchone()
        if row is None:
            return {"status": "expired", "failure_class": "approval_expired"}
        status = row["status"]

        if status == "pending":
            conn.execute(
                "UPDATE approval_requests SET last_poll_at = ? WHERE aid = ?",
                (now.isoformat(), aid),
            )
            return {"status": "pending", "poll_interval_seconds": POLL_INTERVAL_SECONDS}

        if status == "denied":
            return {"status": "denied", "failure_class": "approval_denied"}
        if status == "expired":
            return {"status": "expired", "failure_class": "approval_expired"}
        if status == "consumed":
            return {"status": "consumed", "note": "already confirmed once"}
        if status == "approved":
            return {"status": "approved", "code": row["code"]}
        return {"status": status}


def confirm_approval(aid: str) -> dict:
    """The completion primitive. Atomic flip approved->consumed via
    UPDATE ... WHERE status='approved' (rowcount==1 wins). NEVER mints a
    session token — the ONLY thing this returns is a yes/no plus the fields
    the SSE needs to log/display. This is the sole place single-use lives
    for the connector-authorize flow."""
    with _connect() as conn:
        _expire_stale(conn)
        cur = conn.execute(
            "UPDATE approval_requests SET status='consumed' WHERE aid = ? AND status='approved'",
            (aid,),
        )
        won = cur.rowcount == 1
        row = conn.execute(
            "SELECT * FROM approval_requests WHERE aid = ?", (aid,)
        ).fetchone()
    if row is None:
        return {"approved": False, "reason": "unknown_request"}
    if not won:
        return {"approved": False, "reason": row["status"]}
    return {
        "approved": True,
        "code": row["code"],
        "client_id": row["client_id"],
        "redirect_uri": row["redirect_uri"],
        "audience": row["audience"],
        "decided_at": row["decided_at"],
        "decided_via": row["decided_via"],
    }


def get_approval(aid: str) -> dict | None:
    with _connect() as conn:
        row = conn.execute("SELECT * FROM approval_requests WHERE aid = ?", (aid,)).fetchone()
        return dict(row) if row else None


def build_approval_ntfy_message(req: dict, base_url: str) -> dict:
    """ntfy publish payload — same SHAPE as arrival's build_ntfy_message
    (topic/title/message/priority/tags/actions with `view` buttons opening
    the signed confirm page; GET never decides, review correction #1 still
    holds), new copy for the connector-authorize context."""
    exp = int(time.time()) + DECIDE_URL_TTL_SECONDS
    aid = req["approval_id"]

    def _post_url(action: str) -> str:
        sig = sign_decide(aid, action, exp)
        return f"{base_url}/api/approval/decide?aid={aid}&action={action}&exp={exp}&sig={sig}"

    redirect_uri = req.get("redirect_uri") or "?"
    try:
        from urllib.parse import urlparse

        redirect_host = urlparse(redirect_uri).netloc or redirect_uri
    except Exception:
        redirect_host = redirect_uri

    return {
        "topic": ag._env("NTFY_TOPIC"),
        "title": f"Approve Claude connector · {req['code']} · client {req.get('client_id') or '?'} → {redirect_host}",
        "message": (
            f"{req.get('summary') or 'Claude connector authorize request'}\n"
            f"client: {req.get('client_id') or '?'}\n"
            f"redirect: {redirect_uri}\n"
            f"audience: {req.get('audience') or '?'}\n"
            f"Tap Approve or Deny to open the decision page. Match this code "
            f"against the one shown on the waiting page first."
        ),
        "priority": 4,
        "tags": ["door"],
        # `view` opens the signed confirm page (GET renders, never decides —
        # correction #1 holds); the page's button POSTs. Same reasoning as
        # arrival's message: `http` actions give no tap feedback on iOS.
        "actions": [
            {"action": "view", "label": "Approve", "url": _post_url("approve"), "clear": True},
            {"action": "view", "label": "Deny", "url": _post_url("deny"), "clear": True},
        ],
    }


# Not byte-identical to arrival's CONFIRM_PAGE (see module docstring for why)
# but same look: same inline CSS, same escaping discipline at every call
# site, same "a preview fetcher cannot press this button" reassurance.
CONFIRM_PAGE = """<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1">
<title>The Door That Asks</title></head>
<body style="font-family:-apple-system,sans-serif;max-width:26em;margin:3em auto;text-align:center">
<h2>Approve Claude connector</h2>
<p style="font-size:1.6em;letter-spacing:.05em"><b>{code}</b></p>
<p>client <b>{client_id}</b><br>&rarr; {redirect_uri}<br>audience {audience}</p>
<p>Match this code against the one shown on the waiting page before deciding.</p>
<form method="post" action="/api/approval/decide?aid={aid}&amp;action={action}&amp;exp={exp}&amp;sig={sig}">
<button type="submit" style="font-size:1.2em;padding:.6em 2em">{label}</button>
</form>
<p style="color:#888;font-size:.85em">A preview fetcher cannot press this button. Only you can.</p>
</body></html>"""
