#!/usr/bin/env python3
"""
Sovereign Stack — The Watchman (mechanical tier).

Successor post to comms_dispatcher.py (which stays in place until Anthony
retires it — that ceremony is his, not this file's). launchd is the ear
(WatchPaths + a slow StartInterval); this script is the mechanical tier; the
mind is grok-4.5 via `cosmic-cli ask`, woken ONLY when deltas exist. The LLM
wakes on sound, never on the clock.

The watchman NEVER: enacts, texts Anthony (his phone is an HQ-and-him channel
only), writes the Stack chronicle, or executes actions. Notice, classify,
propose. Output lands in the machine-local spool (helix-side working memory)
for the HQ seat to read and relay.

Five surfaces, every sweep, each reported ok/error (never silently omitted):
  (a) pending_writes — grok_bridge / openai_bridge / antigravity_connector
  (b) daemons/halts
  (c) handoffs unconsumed count (consumed_at null)
  (d) bridge /api/heartbeat source_commit vs ~/sovereign-stack HEAD
  (e) legacy comms board channel=general (daemon.uncertainty still posts there)

State: <root>/watchman/state.json. Root defaults to ~/.sovereign; override
with SOVEREIGN_WATCHMAN_ROOT or --root (tests run under tmp roots).

Quiet sweep (no deltas, all surfaces ok): touch state, write one heartbeat
line to <root>/watchman/watchman.log, exit 0, cosmic NOT invoked, no spool
entry. Deltas: build the sanitized digest, wake Grok, spool the envelope.
Surface errors alone: spool an envelope with grok_invoked=false and a
mechanical 'attend' line about the surface itself.

--dry-run MUTATES NOTHING: no high-water state write, no mark_read_as, and no
append to the production spool/log. A dry run must never blind a subsequent
live sweep, so every dry byte lands in a dry-run-only file.
"""

import argparse
import contextlib
import fcntl
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sanitizer  # noqa: E402
import spool_writer  # noqa: E402

QUEUES = ("grok_bridge", "openai_bridge", "antigravity_connector")
SURFACE_NAMES = ("pending_writes", "halts", "handoffs", "heartbeat", "comms", "honks")

DEFAULT_ROOT = Path.home() / ".sovereign"
DEFAULT_STACK_REPO = Path.home() / "sovereign-stack"
DEFAULT_COSMIC_BIN = str(Path.home() / "cosmic-cli" / "venv" / "bin" / "cosmic-cli")
DEFAULT_BRIDGE_URL = "http://127.0.0.1:8100"
COSMIC_TIMEOUT_S = int(os.environ.get("WATCHMAN_GROK_TIMEOUT", "180"))
COMMS_CHANNEL = "general"
INSTANCE_ID = "watchman"

DIRECTIVE_PATH = Path(__file__).resolve().parent / "directive.md"
IDENTITY_LINE = "WATCHMAN SWEEP — grok-4.5 via cosmic-cli"

# Standing-blind detector: N consecutive sweeps in which EVERY item that
# reached the redactor came back 'sanitizer-failed' means the eyes are off and
# nobody has noticed. The instrument must report its own blindness rather than
# let a counter in one spool line be the only signal.
BLIND_STREAK_DEFAULT = 3

# Mind-rest guard (closure-round residual R4, fixed by HQ before the gate).
# A failure raised AFTER invoke_cosmic returns leaves the xAI spend made but
# the high-water unsaved, so the same deltas re-fire and re-spend every sweep
# — the scribe-greeting spend loop in a new costume. After N consecutive
# spawned-but-unsaved failures the watchman rests the mind phase: mechanical
# digests keep landing in the spool (nothing is lost, the seat still sees
# every item), Grok is not invoked, and an urgent instrument line says so.
MIND_REST_DEFAULT = 3

# Backlog-drain scale guard (found at the baptism, 2026-08-03): a 200-item
# comms-backlog digest blew the invocation timeout, and every drain sweep
# would have re-spent on a reply that could not finish. Grok classifies at
# most WATCHMAN_GROK_ITEM_CAP items per sweep (filesystem surfaces first,
# comms last); the remainder land in the spool mechanically and the envelope
# SAYS so — grok_scope states classified vs mechanical_only, and reply
# coverage is computed against exactly the capped set.
GROK_ITEM_CAP_DEFAULT = 60


def grok_item_cap():
    try:
        return max(1, int(os.environ.get("WATCHMAN_GROK_ITEM_CAP", "")))
    except ValueError:
        return GROK_ITEM_CAP_DEFAULT


def blind_streak_threshold():
    try:
        return max(1, int(os.environ.get("WATCHMAN_BLIND_STREAK_N", "")))
    except ValueError:
        return BLIND_STREAK_DEFAULT


def mind_rest_threshold():
    try:
        return max(1, int(os.environ.get("WATCHMAN_MIND_REST_N", "")))
    except ValueError:
        return MIND_REST_DEFAULT


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def resolve_root(cli_root=None):
    if cli_root:
        return Path(cli_root)
    env_root = os.environ.get("SOVEREIGN_WATCHMAN_ROOT")
    if env_root:
        return Path(env_root)
    return DEFAULT_ROOT


def load_bridge_token():
    """Same resolution order as bridge_config.py, kept dependency-free so the
    watchman runs from any checkout without sys.path games."""
    token_file = Path.home() / ".config" / "sovereign-bridge.env"
    if token_file.exists():
        try:
            for line in token_file.read_text().splitlines():
                if line.startswith("BRIDGE_TOKEN="):
                    return line.split("=", 1)[1].strip().strip('"').strip("'")
        except OSError:
            pass
    return os.environ.get("BRIDGE_TOKEN", "")


# ---------------------------------------------------------------- state


def state_path(root):
    return Path(root) / "watchman" / "state.json"


def load_state(root):
    default = {"files": {}, "handoffs_unconsumed": None, "heartbeat": {}, "sweeps": 0}
    try:
        data = json.loads(state_path(root).read_text(encoding="utf-8"))
    except Exception:
        return default
    # A state.json whose top-level value is syntactically valid but not an
    # object (`null`, `42`, `[1, 2]`, ...) parses cleanly and returns
    # something with no .get() — crashing run_sweep before collection even
    # starts. Same guard style as _extract_meta's `isinstance(data, dict)`.
    if not isinstance(data, dict):
        return default
    return data


def save_state(root, state):
    p = state_path(root)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(state, indent=2, default=str), encoding="utf-8")
    tmp.replace(p)


def sweep_lock_path(root):
    return Path(root) / "watchman" / "sweep.lock"


@contextlib.contextmanager
def sweep_lock(root):
    """Single-instance gate: yields True when this invocation holds the lock.

    launchd fires this script on BOTH a WatchPaths trigger and a StartInterval,
    so two sweeps can overlap on a busy queue. Two live sweeps race the same
    high-water state file and can each half-advance it — an overlap is a
    silent-data-loss shape, not a performance one. flock is per open file
    description, so a second invocation (even in the same process) is refused
    and must do NOTHING.
    """
    p = sweep_lock_path(root)
    p.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(p), os.O_RDWR | os.O_CREAT, 0o644)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            yield False
            return
        try:
            yield True
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def log_line(root, text, *, dry_run=False):
    """Append one heartbeat line. A dry run writes to its OWN log so that
    'the dry run mutated nothing a live sweep reads' is literally true."""
    name = "watchman.dry-run.log" if dry_run else "watchman.log"
    p = Path(root) / "watchman" / name
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "a", encoding="utf-8") as f:
        f.write(f"{now_iso()} {text}\n")


# ---------------------------------------------------------------- surfaces


def _file_sig(path: Path):
    st = path.stat()
    return {"mtime": st.st_mtime, "size": st.st_size}


def _extract_meta(path: Path, queue: str):
    """Parse a pending-write / halt file into (metadata, body_or_None).

    Metadata ALWAYS comes back (filename/size/mtime at minimum). body is the
    text the eyes policy may preview, None when nothing parseable."""
    st = path.stat()
    meta = {
        "queue": queue,
        "filename": path.name,
        "size": st.st_size,
        "timestamp": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat(
            timespec="seconds"
        ),
        "age_seconds": max(
            0, int(datetime.now(timezone.utc).timestamp() - st.st_mtime)
        ),
        "tool": None,
        "commit_target": None,
        "risk_level": None,
        "declared_domain": None,
    }
    body = None
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return meta, None
    if path.suffix == ".json":
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return meta, None
        if isinstance(data, dict):
            meta["tool"] = data.get("tool")
            meta["commit_target"] = data.get("commit_target")
            meta["risk_level"] = data.get("risk_level")
            args = data.get("arguments")
            if isinstance(args, dict):
                meta["declared_domain"] = args.get("domain")
                content = args.get("content")
                if isinstance(content, str) and content:
                    body = content
            if body is None:
                # No content field: the raw JSON text is the body candidate;
                # the redactor sees it before any preview does.
                body = raw
        else:
            body = raw
    else:
        body = raw
    return meta, body


def scan_file_surface(dir_path: Path, queue: str, state_files: dict, prefix: str):
    """Generic new/changed detection by (name, mtime, size) high-water."""
    items = []
    seen = {}
    for path in sorted(dir_path.iterdir()):
        if not path.is_file() or path.name.startswith("."):
            continue
        sig = _file_sig(path)
        key = f"{prefix}/{path.name}"
        seen[key] = sig
        prev = state_files.get(key)
        if prev is None:
            change = "new"
        elif prev.get("mtime") != sig["mtime"] or prev.get("size") != sig["size"]:
            change = "changed"
        else:
            continue
        meta, body = _extract_meta(path, queue)
        meta["change"] = change
        meta["ref"] = key
        items.append((meta, body))
    return items, seen


def scan_pending_writes(root: Path, state: dict):
    """Surface (a): three proposal queues. Per-queue ok/error, surface ok only
    when every queue read cleanly."""
    surface = {"ok": True, "error": None, "queues": {}}
    items = []
    seen = {}
    errors = []
    for queue in QUEUES:
        qdir = Path(root) / queue / "pending_writes"
        try:
            if not qdir.is_dir():
                raise FileNotFoundError(f"{qdir} is not a directory")
            q_items, q_seen = scan_file_surface(
                qdir, queue, state.get("files", {}), f"{queue}/pending_writes"
            )
            items.extend(q_items)
            seen.update(q_seen)
            surface["queues"][queue] = {
                "ok": True,
                "error": None,
                "deltas": len(q_items),
            }
        except OSError as e:
            surface["queues"][queue] = {"ok": False, "error": str(e), "deltas": 0}
            errors.append(f"{queue}: {e}")
    if errors:
        surface["ok"] = False
        surface["error"] = "; ".join(errors)
    surface["items"] = len(items)
    return surface, items, seen


def scan_halts(root: Path, state: dict):
    """Surface (b): daemon halt files."""
    surface = {"ok": True, "error": None}
    items, seen = [], {}
    hdir = Path(root) / "daemons" / "halts"
    try:
        if not hdir.is_dir():
            raise FileNotFoundError(f"{hdir} is not a directory")
        items, seen = scan_file_surface(
            hdir, "daemons/halts", state.get("files", {}), "daemons/halts"
        )
    except OSError as e:
        surface["ok"] = False
        surface["error"] = str(e)
    surface["items"] = len(items)
    return surface, items, seen


def scan_handoffs(root: Path, state: dict):
    """Surface (c): unconsumed handoff count (consumed_at null/missing).

    Reachability lesson (SOP #10): the count of unconsumed handoffs is the
    thing that goes wrong quietly, so the DELTA is the count changing."""
    surface = {"ok": True, "error": None}
    items = []
    hdir = Path(root) / "handoffs"
    unconsumed = 0
    newest = []
    corrupt = 0
    try:
        if not hdir.is_dir():
            raise FileNotFoundError(f"{hdir} is not a directory")
        for path in sorted(hdir.iterdir()):
            if not path.is_file() or path.suffix != ".json":
                continue
            try:
                data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
            except (json.JSONDecodeError, OSError):
                # Was a silent `continue` with no counter at all — a bad
                # handoff simply vanished from the unconsumed count while
                # the surface still reported ok. Report it instead.
                corrupt += 1
                continue
            if not isinstance(data, dict):
                # A syntactically valid but non-dict line (`null`, `42`,
                # `[1, 2]`, ...) parses cleanly; .get() below would crash on
                # it unguarded. Count it the same as a syntax-corrupt line.
                corrupt += 1
                continue
            if not data.get("consumed_at"):
                unconsumed += 1
                newest.append(path.name)
    except OSError as e:
        surface["ok"] = False
        surface["error"] = str(e)
        surface["items"] = 0
        return surface, items, state.get("handoffs_unconsumed")
    prev = state.get("handoffs_unconsumed")
    surface["note"] = f"unconsumed={unconsumed}" + (
        f", corrupt skipped={corrupt}" if corrupt else ""
    )
    if prev is not None and unconsumed != prev:
        meta = {
            "queue": "handoffs",
            "ref": "handoffs/unconsumed-count",
            "filename": None,
            "change": "count-changed",
            "size": None,
            "timestamp": now_iso(),
            "age_seconds": 0,
            "tool": None,
            "commit_target": None,
            "risk_level": None,
            "declared_domain": None,
            "detail": {
                "unconsumed": unconsumed,
                "previous": prev,
                "newest_unconsumed": newest[-5:],
            },
        }
        items.append((meta, None))
    surface["items"] = len(items)
    return surface, items, unconsumed


def default_heartbeat_fetch(bridge_url):
    with urllib.request.urlopen(f"{bridge_url}/api/heartbeat", timeout=10) as r:
        return json.loads(r.read().decode("utf-8"))


def default_git_head(stack_repo):
    proc = subprocess.run(
        ["git", "-C", str(stack_repo), "rev-parse", "--short", "HEAD"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    out = proc.stdout.strip()
    if proc.returncode != 0 or not out:
        raise RuntimeError(
            f"git rev-parse failed in {stack_repo}: {proc.stderr.strip() or 'no output'}"
        )
    return out


def scan_heartbeat(state: dict, *, heartbeat_fetch, git_head_fn):
    """Surface (d): the stale-process class — a bridge serving code that is no
    longer the checked-out tree. Alerts once per distinct (served, local) pair."""
    surface = {"ok": True, "error": None}
    items = []
    hb_state = dict(state.get("heartbeat") or {})
    try:
        hb = heartbeat_fetch()
        served = str(hb.get("source_commit") or "")
        local = str(git_head_fn())
        if not served:
            raise RuntimeError("heartbeat carried no source_commit")
        mismatch = not (served.startswith(local) or local.startswith(served))
        surface["note"] = f"served={served} local={local}" + (
            " MISMATCH" if mismatch else ""
        )
        pair_changed = (
            hb_state.get("source_commit") != served
            or hb_state.get("local_head") != local
        )
        if mismatch and pair_changed:
            meta = {
                "queue": "bridge",
                "ref": "bridge/heartbeat-source-commit",
                "filename": None,
                "change": "commit-mismatch",
                "size": None,
                "timestamp": now_iso(),
                "age_seconds": 0,
                "tool": None,
                "commit_target": None,
                "risk_level": None,
                "declared_domain": None,
                "detail": {"served": served, "local": local},
            }
            items.append((meta, None))
        hb_state = {"source_commit": served, "local_head": local, "mismatch": mismatch}
    except Exception as e:
        surface["ok"] = False
        surface["error"] = str(e)
    surface["items"] = len(items)
    return surface, items, hb_state


COMMS_READ_LIMIT = 200


def default_comms_fetch(bridge_url, token, mark_read):
    # Explicit limit: the endpoint's silent default is 50, which read as a
    # complete sweep during the first live demo while the real backlog was
    # larger — the silent-partial class. scan_comms flags count==limit.
    params = (
        f"channel={COMMS_CHANNEL}&unread_for={INSTANCE_ID}&limit={COMMS_READ_LIMIT}"
    )
    if mark_read:
        params += f"&mark_read_as={INSTANCE_ID}"
    req = urllib.request.Request(
        f"{bridge_url}/api/comms/read?{params}",
        headers={"Authorization": f"Bearer {token}"},
    )
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read().decode("utf-8"))


def _load_ack_ids(apath):
    ids = set()
    try:
        for ln in apath.read_text(encoding="utf-8").splitlines():
            try:
                rec = json.loads(ln)
            except ValueError:
                continue
            if not isinstance(rec, dict):
                # A syntactically valid but non-dict line — .get() below
                # would crash on it unguarded.
                continue
            hid = rec.get("honk_id")
            if hid is None:
                # A record missing honk_id must be SKIPPED, not added as
                # None: adding None poisons the set so any honk that also
                # lacks honk_id reads as already-acked and is silently
                # dropped from the unacked count.
                continue
            ids.add(hid)
    except OSError:
        pass
    return ids


def scan_honks(root, state):
    """Surface (f): the nape goose's honks — the house's soft governance flags.

    Watches <root>/nape/honks.jsonl for NEW unacked honks past a line-count
    high-water. The FIRST run BASELINES without itemizing — months of backlog
    are history for the triage lane, not signal for a sweep digest (the
    baptism lesson: never hand the mind a flood). Thereafter each new unacked
    honk is one item: observation as body (through the standard sanitizer
    pipeline), level mapped to declared risk (sharp->high, uneasy->medium).
    An ABSENT nape store is a stated note, not an error — the goose is an
    optional instrument, and an absence is a measurement, said out loud."""
    surface = {"ok": True, "error": None}
    items = []
    hpath = Path(root) / "nape" / "honks.jsonl"
    apath = Path(root) / "nape" / "acks.jsonl"
    prev_count = state.get("honks_line_count")
    new_count = prev_count if isinstance(prev_count, int) else None
    try:
        if not hpath.is_file():
            surface["note"] = "nape store absent — goose not installed at this root"
            surface["items"] = 0
            return surface, items, new_count
        lines = hpath.read_text(encoding="utf-8").splitlines()
        new_count = len(lines)
        acked_ids = _load_ack_ids(apath)
        corrupt = 0
        non_dict = 0
        if not isinstance(prev_count, int):
            unacked = sharp = 0
            for ln in lines:
                try:
                    h = json.loads(ln)
                except ValueError:
                    corrupt += 1
                    continue
                if not isinstance(h, dict):
                    # Syntactically valid but non-dict (`null`, `42`,
                    # `[1, 2]`, ...) — .get() below would crash unguarded.
                    corrupt += 1
                    non_dict += 1
                    continue
                if h.get("honk_id") in acked_ids:
                    continue
                unacked += 1
                if h.get("level") == "sharp":
                    sharp += 1
            surface["note"] = (
                f"baseline: {len(lines)} honks on file, {unacked} unacked "
                f"({sharp} sharp), corrupt={corrupt}"
                + (f" ({non_dict} non-dict)" if non_dict else "")
                + " — backlog NOT itemized "
                f"(triage lane owns history); watch begins at this high-water"
            )
            surface["items"] = 0
            return surface, items, new_count
        for ln in lines[prev_count:]:
            try:
                h = json.loads(ln)
            except ValueError:
                corrupt += 1
                continue
            if not isinstance(h, dict):
                # Same non-dict guard as the baseline loop above — THIS is
                # the loop that matters most: it is the only one that runs
                # after first boot, so a fix that guards only the baseline
                # leaves the real-world case dead.
                corrupt += 1
                non_dict += 1
                continue
            hid = str(h.get("honk_id", "?"))
            if hid in acked_ids:
                continue
            level = str(h.get("level") or "")
            body = str(h.get("observation") or "")
            meta = {
                "queue": "nape/honks",
                "ref": f"nape/honks/{hid}",
                "filename": hid,
                "change": "new-honk",
                "size": len(body),
                "timestamp": str(h.get("ts") or h.get("timestamp") or ""),
                "age_seconds": None,
                "tool": h.get("trigger_tool"),
                "commit_target": None,
                "risk_level": {"sharp": "high", "uneasy": "medium"}.get(level, "low"),
                "declared_domain": None,
                "sender": h.get("session_id"),
                "honk_pattern": h.get("pattern"),
                "honk_level": level,
            }
            items.append((meta, body))
        surface["note"] = (
            f"new lines={len(lines) - prev_count} -> items={len(items)}"
            + (f", corrupt skipped={corrupt}" if corrupt else "")
            + (f" ({non_dict} non-dict)" if non_dict else "")
        )
    except OSError as e:
        surface["ok"] = False
        surface["error"] = str(e)
        new_count = prev_count if isinstance(prev_count, int) else None
    surface["items"] = len(items)
    return surface, items, new_count


def scan_comms(*, comms_fetch):
    """Surface (e): the legacy comms board. daemon.uncertainty still posts
    there; the watchman inherits the watch so those whispers finally land."""
    surface = {"ok": True, "error": None}
    items = []
    try:
        data = comms_fetch()
        messages = data.get("messages", []) or []
        self_sent = 0
        malformed = 0
        if len(messages) >= COMMS_READ_LIMIT:
            # count == requested limit means the board may hold MORE unread
            # than this sweep saw. Say so — a capped read must never present
            # itself as a complete one (the silent-partial class).
            surface["possibly_partial"] = True
        for m in messages:
            if not isinstance(m, dict):
                malformed += 1
                continue
            if m.get("sender") == INSTANCE_ID:
                self_sent += 1
                continue
            content = m.get("content")
            body = content if isinstance(content, str) else json.dumps(content)
            meta = {
                "queue": f"comms/{COMMS_CHANNEL}",
                "ref": f"comms/{COMMS_CHANNEL}/{m.get('id', '?')}",
                "filename": str(m.get("id", "?")),
                "change": "new-message",
                "size": len(body) if body else 0,
                "timestamp": str(m.get("timestamp", "")),
                "age_seconds": None,
                "tool": None,
                "commit_target": None,
                "risk_level": None,
                "declared_domain": None,
                "sender": m.get("sender"),
            }
            items.append((meta, body))
        # Count reconciliation: the note used to say 'unread=N' while N
        # included messages the sweep then dropped, so the note and items_seen
        # disagreed by the skipped count with nothing saying why.
        surface["unread"] = len(messages)
        surface["self_sent_excluded"] = self_sent
        surface["malformed_excluded"] = malformed
        surface["items"] = len(items)
        surface["note"] = (
            f"unread={len(messages)} → items={len(items)} "
            f"(self-sent excluded={self_sent}, malformed excluded={malformed})"
        )
        if surface.get("possibly_partial"):
            surface["note"] += (
                f" (capped at limit={COMMS_READ_LIMIT}, possibly partial)"
            )
    except Exception as e:
        surface["ok"] = False
        surface["error"] = str(e)
    return surface, items


# ---------------------------------------------------------------- grok


def build_prompt(digest):
    directive = DIRECTIVE_PATH.read_text(encoding="utf-8")
    return (
        directive
        + "\n\n## DELTA DIGEST (input)\n\n```json\n"
        + json.dumps(digest, indent=2, ensure_ascii=False, default=str)
        + "\n```\n"
    )


def invoke_cosmic(prompt, *, cosmic_bin):
    """One-shot `cosmic-cli ask` — no agent loop, no tools, no enactment lane.

    COLUMNS: cosmic renders through a console that hard-wraps at terminal
    width (80 when piped), injecting raw newlines INSIDE JSON string
    literals — Grok's first live reply was perfect and unparseable at once
    (baptism, 2026-08-03). A huge COLUMNS disables the wrap at the source.
    """
    proc = subprocess.run(
        [cosmic_bin, "ask", prompt],
        capture_output=True,
        text=True,
        timeout=COSMIC_TIMEOUT_S,
        env={**os.environ, "COLUMNS": "4000"},
    )
    return proc.returncode, proc.stdout, proc.stderr


def _looks_like_watchman_envelope(parsed, expected_sweep_id) -> bool:
    """STRICT shape check before a parsed object is accepted as Grok's reply.

    Reply coverage is load-bearing, so 'first parseable object wins' is not
    harmless: a banner fragment that happens to be JSON-shaped would win and
    coverage would report 0 answered / N omitted, firing N false attend lines
    about an omission that never happened.

    Three requirements, all mandatory:
      - the reply's `sweep_id` EQUALS the digest's. A reply that does not name
        the sweep it answers cannot be reconciled against it — a stale reply,
        a replayed one, or a hallucinated envelope would otherwise be scored
        against the wrong digest;
      - `items` is a list;
      - every item is a dict bearing a non-empty `digest_id` — the only key
        coverage matches on.

    Anything else is grok-reply-unparseable and is quarantined intact.
    """
    if not isinstance(parsed, dict):
        return False
    if parsed.get("sweep_id") != expected_sweep_id:
        return False
    items = parsed.get("items")
    if not isinstance(items, list):
        return False
    for item in items:
        if not isinstance(item, dict):
            return False
        digest_id = item.get("digest_id")
        if not isinstance(digest_id, str) or not digest_id.strip():
            return False
    return True


def parse_grok_reply(raw: str, expected_sweep_id):
    """Extract the strict-JSON envelope from a reply that may carry the
    identity line, a CLI banner, or code fences around it. Returns
    (parsed_dict_or_None, identity_line_present)."""
    if not raw:
        return None, False
    identity_present = IDENTITY_LINE in raw
    text = raw.replace("```json", "```")
    # Balanced-brace scan from each '{' — first complete object that parses AND
    # carries the envelope shape wins.
    start = text.find("{")
    while start != -1:
        depth = 0
        in_str = False
        esc = False
        for i in range(start, len(text)):
            c = text[i]
            if in_str:
                if esc:
                    esc = False
                elif c == "\\":
                    esc = True
                elif c == '"':
                    in_str = False
                continue
            if c == '"':
                in_str = True
            elif c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    candidate = text[start : i + 1]
                    try:
                        parsed = json.loads(candidate)
                        if _looks_like_watchman_envelope(parsed, expected_sweep_id):
                            return parsed, identity_present
                    except json.JSONDecodeError:
                        pass
                    break
        start = text.find("{", start + 1)
    return None, identity_present


def compute_reply_coverage(items, reply):
    """Verify EVERY digest item appears exactly once in Grok's reply.

    The directive commands it ('Every digest item MUST appear exactly once');
    nothing verified it. A reply that omits the hot item was accepted as
    'parsed', and severity_ceiling — computed only over the items Grok
    returned — read as complete triage. Visible by eye, absent by field.

    Coverage keys on `digest_id` ONLY — a mechanical label the watchman mints
    (item-0001, ...) that no untrusted input can influence, so the accounting
    holds even when every metadata field failed sanitization.

    THE `ref` FALLBACK IS GONE. `ref` is attacker-derived (it is built from a
    filename or a board message id), so matching on it let a reply claim an
    expected slot by echoing a string the item's own source controls, and a
    truncated-or-redacted ref could match the wrong item. A reply item without
    a valid `digest_id` is grok-extra and can never claim a slot; the slot it
    tried to claim stays omitted and raises its own attend line.
    """
    expected = {it["digest_id"]: it.get("ref") for it in items}
    reply_items = []
    if isinstance(reply, dict) and isinstance(reply.get("items"), list):
        reply_items = [r for r in reply["items"] if isinstance(r, dict)]

    hits = {}
    extra = []
    for r in reply_items:
        did = r.get("digest_id")
        if did not in expected:
            extra.append(
                {
                    "digest_id": sanitizer.cap_field(str(r.get("digest_id") or "")),
                    "ref": sanitizer.cap_field(str(r.get("ref") or "")),
                }
            )
            continue
        hits[did] = hits.get(did, 0) + 1

    omitted = [
        {"digest_id": did, "ref": ref}
        for did, ref in expected.items()
        if did not in hits
    ]
    duplicated = [
        {"digest_id": did, "ref": expected[did], "times": n}
        for did, n in hits.items()
        if n > 1
    ]
    return {
        # Arithmetic a reader can check without trusting the label:
        #   expected    == answered + omitted
        #   reply_items == judgments + extra
        "expected": len(expected),
        "answered": len(hits),
        "omitted": len(omitted),
        "extra": len(extra),
        "duplicated": len(duplicated),
        "reply_items": len(reply_items),
        "judgments": sum(hits.values()),
        "omitted_refs": omitted,
        "extra_refs": extra,
        "duplicated_refs": duplicated,
    }


def reply_state_for(coverage):
    """The label, derived from the same numbers a reader can check.

    'parsed' is reserved for a reply that covers the digest exactly once each.
    Duplicates used to leave the label at 'parsed' while duplicated_refs was
    non-empty and an attend line fired — label and arithmetic disagreeing is
    the fail-open shape this whole build hunts.
    """
    if coverage["omitted"] or coverage["extra"]:
        return "parsed-partial"
    if coverage["duplicated"]:
        return "parsed-with-anomalies"
    return "parsed"


def quarantine_reply(root, sweep_id, stdout, stderr):
    qdir = Path(root) / "watchman" / "quarantine"
    qdir.mkdir(parents=True, exist_ok=True)
    qfile = qdir / f"{sweep_id}.grok-reply.txt"
    qfile.write_text(
        "== stdout ==\n" + (stdout or "") + "\n== stderr ==\n" + (stderr or ""),
        encoding="utf-8",
    )
    return qfile


# ---------------------------------------------------------------- sweep


def run_sweep(
    root,
    *,
    dry_run=False,
    cosmic_bin=None,
    bridge_url=None,
    stack_repo=None,
    policy_path=None,
    heartbeat_fetch=None,
    git_head_fn=None,
    comms_fetch=None,
    sanitize_kwargs=None,
):
    """One full mechanical sweep. Returns the envelope (also spooled when it
    carries deltas or surface errors), or None for a quiet clean sweep."""
    root = Path(root)
    cosmic_bin = cosmic_bin or os.environ.get("WATCHMAN_COSMIC_BIN", DEFAULT_COSMIC_BIN)
    bridge_url = bridge_url or os.environ.get("BRIDGE_URL", DEFAULT_BRIDGE_URL)
    stack_repo = stack_repo or os.environ.get(
        "SOVEREIGN_STACK_REPO", str(DEFAULT_STACK_REPO)
    )
    sanitize_kwargs = sanitize_kwargs or {}

    if heartbeat_fetch is None:
        heartbeat_fetch = lambda: default_heartbeat_fetch(bridge_url)  # noqa: E731
    if git_head_fn is None:
        git_head_fn = lambda: default_git_head(stack_repo)  # noqa: E731
    if comms_fetch is None:
        token = load_bridge_token()
        # Dry runs must not mutate anything: omit mark_read_as (pure read).
        comms_fetch = lambda: default_comms_fetch(  # noqa: E731
            bridge_url, token, mark_read=not dry_run
        )

    started_at = now_iso()
    sweep_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    state = load_state(root)
    policy, policy_state = sanitizer.load_policy(policy_path)

    surfaces = {}
    raw_items = []  # (surface_name, meta, body) triples

    def collect(surface_name, pairs):
        # The surface NAME is attached mechanically at collection time and is
        # the single source items_by_surface is later counted from (H6).
        for meta, body in pairs:
            raw_items.append((surface_name, meta, body))

    surfaces["pending_writes"], pw_items, pw_seen = scan_pending_writes(root, state)
    collect("pending_writes", pw_items)
    surfaces["halts"], halt_items, halt_seen = scan_halts(root, state)
    collect("halts", halt_items)
    surfaces["handoffs"], ho_items, unconsumed = scan_handoffs(root, state)
    collect("handoffs", ho_items)
    surfaces["heartbeat"], hb_items, hb_state = scan_heartbeat(
        state, heartbeat_fetch=heartbeat_fetch, git_head_fn=git_head_fn
    )
    collect("heartbeat", hb_items)
    surfaces["comms"], comms_items = scan_comms(comms_fetch=comms_fetch)
    collect("comms", comms_items)
    surfaces["honks"], honk_items, honks_line_count = scan_honks(root, state)
    collect("honks", honk_items)

    # Sanitize. Metadata always travels — but SANITIZED: every string field
    # runs through the same redactor as previews and is capped, because
    # metadata is copied out of untrusted files and board messages and is
    # handed to a third-party model in argv, in the prompt, and in the spool.
    # The denylist is evaluated against BOTH the raw and the sanitized
    # metadata: redaction can coarse-mask a whole field, and a denylist term
    # must not be able to disappear into a mask and open the eyes.
    items = []
    meta_only_counts = {
        "denylist": 0,
        "sanitizer-failed": 0,
        "unparseable": 0,
        "empty-body": 0,
        "content-flagged": 0,
    }
    previewed = 0
    sanitizer_attempts = 0
    sanitizer_failures = 0
    failed_refs = set()
    for index, (surface_name, meta, body) in enumerate(raw_items, start=1):
        safe_meta, meta_ok = sanitizer.sanitize_metadata(meta, **sanitize_kwargs)
        if sanitizer.denylisted(meta, policy):
            preview, preview_state = None, "metadata-only:denylist"
        else:
            preview, preview_state = sanitizer.preview_for(
                body, safe_meta, policy, **sanitize_kwargs
            )
        item = dict(safe_meta)
        # Mechanical, never attacker-derived: reply coverage keys on this, so
        # it must survive total sanitizer failure and stay unique.
        item["digest_id"] = f"item-{index:04d}"
        item["surface"] = surface_name
        item["metadata_sanitized"] = meta_ok
        item["body_bytes"] = (
            len(body.encode("utf-8", errors="replace"))
            if isinstance(body, str)
            else None
        )
        item["preview_state"] = preview_state
        if body is not None and preview_state not in (
            "metadata-only:denylist",
            "metadata-only:unparseable",
        ):
            sanitizer_attempts += 1
            if preview_state == "metadata-only:sanitizer-failed":
                sanitizer_failures += 1
                failed_refs.add(meta.get("ref"))
        if preview is not None:
            item["preview"] = preview
            previewed += 1
        else:
            reason = (
                preview_state.split(":", 1)[1]
                if ":" in preview_state
                else preview_state
            )
            meta_only_counts[reason] = meta_only_counts.get(reason, 0) + 1
        items.append(item)

    surface_errors = [n for n, s in surfaces.items() if not s.get("ok")]

    # Standing-blind detection. A sweep is BLIND when every item that actually
    # reached the redactor came back 'sanitizer-failed'. Blindness is
    # fail-closed (no body leaks) but it turns the eyes off SILENTLY, so the
    # instrument reports itself.
    sweep_blind = sanitizer_attempts > 0 and sanitizer_failures == sanitizer_attempts
    threshold = blind_streak_threshold()
    prev_streak = int(state.get("blind_streak", 0) or 0)
    prev_mind_streak = int(state.get("mind_failure_streak", 0) or 0)
    mind_resting = prev_mind_streak >= mind_rest_threshold()
    if sweep_blind:
        blind_streak = prev_streak + 1
    elif sanitizer_attempts > 0:
        blind_streak = 0
    else:
        # No attempts this sweep: no evidence either way. Leaving the streak
        # untouched errs toward reporting blindness, which is the safe side.
        blind_streak = prev_streak
    blindness = {
        "sweep_blind": sweep_blind,
        "streak": blind_streak,
        "threshold": threshold,
        "sanitizer_attempts": sanitizer_attempts,
        "sanitizer_failures": sanitizer_failures,
    }

    # High-water state update happens regardless of Grok's outcome — the
    # mechanical heartbeat is written even when grok is not invoked — EXCEPT
    # under --dry-run, which must mutate nothing a live sweep reads.
    #
    # HOLDBACK: a file whose preview failed sanitization does NOT advance its
    # high-water mark, so it is re-examined once the sanitizer is repaired. A
    # transient breakage used to blind the watchman to those items PERMANENTLY
    # (state advanced regardless of preview outcome; the repaired sweep saw an
    # unchanged file and went quiet).
    new_files = dict(state.get("files", {}))
    pw_keep = {k: v for k, v in pw_seen.items() if k not in failed_refs}
    halt_keep = {k: v for k, v in halt_seen.items() if k not in failed_refs}
    if surfaces["pending_writes"]["ok"] or pw_seen:
        for k in [k for k in new_files if any(k.startswith(q + "/") for q in QUEUES)]:
            if surfaces["pending_writes"]["ok"] and k not in pw_seen:
                del new_files[k]
        for k in failed_refs:
            new_files.pop(k, None)
        new_files.update(pw_keep)
    if surfaces["halts"]["ok"]:
        for k in [k for k in new_files if k.startswith("daemons/halts/")]:
            if k not in halt_seen:
                del new_files[k]
        for k in failed_refs:
            new_files.pop(k, None)
        new_files.update(halt_keep)
    state["files"] = new_files
    if surfaces["handoffs"]["ok"]:
        state["handoffs_unconsumed"] = unconsumed
    if surfaces["heartbeat"]["ok"]:
        state["heartbeat"] = hb_state
    if surfaces["honks"]["ok"] and honks_line_count is not None:
        state["honks_line_count"] = honks_line_count
    state["blind_streak"] = blind_streak
    state["last_sweep"] = started_at
    state["sweeps"] = int(state.get("sweeps", 0)) + 1

    if not items and not surface_errors:
        log_line(
            root,
            f"sweep {sweep_id} quiet — {len(SURFACE_NAMES)} surfaces ok, 0 deltas; state touched, "
            f"grok not invoked",
            dry_run=dry_run,
        )
        if not dry_run:
            save_state(root, state)
        return None

    # COUNTS COME FROM ONE SOURCE: the final items list. They used to be read
    # back out of each scanner's self-reported surface['items'], a second
    # source that can disagree with the first — a surface that raised
    # mid-iteration could report a count for items that never made it into the
    # digest, and items_by_surface would not sum to items_seen with nothing
    # saying why.
    by_surface = {name: 0 for name in SURFACE_NAMES}
    for it in items:
        by_surface[it["surface"]] = by_surface.get(it["surface"], 0) + 1
    for name, count in by_surface.items():
        if isinstance(surfaces.get(name), dict):
            surfaces[name]["items"] = count

    counts = {
        "items_seen": len(items),
        "items_previewed": previewed,
        "items_metadata_only": meta_only_counts,
        "items_by_surface": by_surface,
    }

    # THE SURFACES BLOCK TRAVELS TOO, so it is sanitized like any other
    # metadata. Its strings are not house-authored: a surface `error` is an
    # OSError message carrying a filesystem path, and a `note` carries commit
    # hashes and counts read off the wire. All of it goes into the digest handed
    # to Grok, into the spool, and into latest.md — and none of it used to see
    # the redactor.
    safe_surfaces, surfaces_ok = sanitizer.sanitize_metadata(
        surfaces, **sanitize_kwargs
    )

    # Surface errors are reported from the surface NAME (a house literal), with
    # the sanitized error text alongside. Deriving the attend lines from the
    # sanitized block's SHAPE would lose them entirely when that block collapses
    # under a dead redactor — a fail-open in the reporting path.
    def _sanitized_error(name):
        node = safe_surfaces.get(name) if isinstance(safe_surfaces, dict) else None
        if isinstance(node, dict) and isinstance(node.get("error"), str):
            return node["error"]
        return sanitizer.UNSANITIZED_TOKEN

    envelope = {
        "kind": "watchman-sweep",
        "sweep_id": sweep_id,
        "started_at": started_at,
        "finished_at": now_iso(),
        "root": str(root),
        "dry_run": bool(dry_run),
        "surfaces": safe_surfaces,
        "surfaces_sanitized": surfaces_ok,
        "surface_errors": [
            {"surface": name, "error": _sanitized_error(name)}
            for name in SURFACE_NAMES
            if not surfaces.get(name, {}).get("ok")
        ],
        "counts": counts,
        "policy_state": policy_state,
        "policy_path": str(policy_path) if policy_path else None,
        "blindness": blindness,
        "mind": {
            "failure_streak": prev_mind_streak,
            "threshold": mind_rest_threshold(),
            "resting": mind_resting,
        },
        "items": items,
        "grok_invoked": False,
        # Three states, because 'invoked' was stamped True even when no process
        # ever ran: an OSError on a missing binary looked identical in the
        # spool to a real call that came back garbage. A reader auditing spend
        # from spool.jsonl alone would have miscounted.
        "grok_process_state": "not-attempted",
        "grok_model": "grok-4.5",
        "grok_reply": None,
        "grok_reply_state": "not-invoked",
        "reply_coverage": None,
        "quarantine_file": None,
    }

    sweep_error = None

    def mind_phase():
        if items and sweep_blind:
            # Every item that reached the redactor failed. There is no sanitized
            # content to classify — waking Grok would spend a real call on a
            # digest the instrument itself cannot see. Same shape as the
            # surface-errors path: report the instrument, do not wake the mind.
            envelope["grok_reply_state"] = "not-invoked-sweep-blind"
            log_line(
                root,
                f"sweep {sweep_id} — {len(items)} deltas but the sanitizer failed "
                f"on all {sanitizer_attempts} attempt(s); grok not invoked, "
                f"blind_streak={blind_streak}/{threshold}",
                dry_run=dry_run,
            )
        elif items and dry_run:
            envelope["grok_reply_state"] = "dry-run"
            prompt_file = Path(root) / "watchman" / f"{sweep_id}.dry-run-prompt.txt"
            prompt_file.parent.mkdir(parents=True, exist_ok=True)
            digest = {
                k: envelope[k] for k in ("sweep_id", "surfaces", "counts", "items")
            }
            prompt_file.write_text(build_prompt(digest), encoding="utf-8")
            envelope["dry_run_prompt_file"] = str(prompt_file)
            log_line(
                root,
                f"sweep {sweep_id} DRY RUN — {len(items)} deltas, grok NOT invoked",
                dry_run=dry_run,
            )
        elif items and mind_resting:
            # Spend breaker. The streak only counts spawned-but-unsaved
            # failures — real xAI calls whose deltas re-fired. Resting consumes
            # the deltas MECHANICALLY (items land in the spool, state saves),
            # so the loop breaks without losing a single item; the seat reads
            # the mechanical digest itself until --reset-mind after repair.
            envelope["grok_reply_state"] = "not-invoked-mind-resting"
            log_line(
                root,
                f"sweep {sweep_id} — {len(items)} deltas but the mind is "
                f"RESTING after {prev_mind_streak} spawned-but-unsaved "
                f"failure(s) (threshold {mind_rest_threshold()}); grok not "
                f"invoked, no spend; run --reset-mind after repair",
                dry_run=dry_run,
            )
        elif items:
            cap = grok_item_cap()
            # Filesystem and instrument surfaces carry the operational signal;
            # a comms backlog is history draining. Keep original order within
            # each class.
            ordered = [i for i in items if i.get("surface") != "comms"] + [
                i for i in items if i.get("surface") == "comms"
            ]
            for_grok = ordered[:cap]
            envelope["grok_scope"] = {
                "cap": cap,
                "classified": len(for_grok),
                "mechanical_only": len(items) - len(for_grok),
            }
            digest = {k: envelope[k] for k in ("sweep_id", "surfaces", "counts")}
            digest["items"] = for_grok
            try:
                rc, stdout, stderr = invoke_cosmic(
                    build_prompt(digest), cosmic_bin=cosmic_bin
                )
                # A process ran. Only here does grok_invoked become true.
                envelope["grok_invoked"] = True
                envelope["grok_process_state"] = "spawned"
                parsed, identity_present = parse_grok_reply(
                    stdout if rc == 0 else "", sweep_id
                )
                if rc != 0 or parsed is None:
                    qfile = quarantine_reply(root, sweep_id, stdout, stderr)
                    envelope["grok_reply_state"] = "grok-reply-unparseable"
                    envelope["quarantine_file"] = str(qfile)
                else:
                    envelope["grok_reply"] = parsed
                    envelope["grok_identity_line_present"] = identity_present
                    coverage = compute_reply_coverage(for_grok, parsed)
                    envelope["reply_coverage"] = coverage
                    # A reply that does not cover the digest exactly once each is
                    # NOT 'parsed'. The state says which, and the mechanical tier
                    # raises an attend line per omitted / extra / duplicated item
                    # so severity_ceiling cannot understate.
                    envelope["grok_reply_state"] = reply_state_for(coverage)
            except subprocess.TimeoutExpired as e:
                # The process DID spawn; it just never answered in time.
                envelope["grok_invoked"] = True
                envelope["grok_process_state"] = "spawned"
                qfile = quarantine_reply(
                    root, sweep_id, "", f"invocation timed out: {e}"
                )
                envelope["grok_reply_state"] = "grok-reply-unparseable"
                envelope["quarantine_file"] = str(qfile)
            except OSError as e:
                # No process ever ran (missing binary, permission, ENOENT).
                # Saying 'invoked' here claims spend that did not happen.
                envelope["grok_invoked"] = False
                envelope["grok_process_state"] = "spawn-failed"
                qfile = quarantine_reply(root, sweep_id, "", f"invocation failed: {e}")
                envelope["grok_reply_state"] = "grok-spawn-failed"
                envelope["grok_spawn_error"] = str(e)
                envelope["quarantine_file"] = str(qfile)
            log_line(
                root,
                f"sweep {sweep_id} — {len(items)} deltas, "
                f"grok_process={envelope['grok_process_state']}, "
                f"reply={envelope['grok_reply_state']}",
                dry_run=dry_run,
            )
        else:
            # Surface errors only: mechanical envelope, no semantic content to
            # classify — the attend line is about the instrument itself.
            log_line(
                root,
                f"sweep {sweep_id} — 0 deltas but surface errors: "
                f"{', '.join(surface_errors)}; grok not invoked",
                dry_run=dry_run,
            )

    # AT-LEAST-ONCE, and the ordering that buys it. Anything that raises between
    # collection and the spool write leaves the high-water mark exactly where it
    # was, so the deltas re-fire next sweep. The state save used to run BEFORE
    # this phase: a crash in the mind phase consumed the deltas and the next
    # sweep went quiet — the work was gone and nothing said so.
    #
    # SCOPE, stated exactly: at-least-once covers the FILESYSTEM surfaces
    # (pending_writes, halts) and the two counter surfaces, which re-derive from
    # disk. It does NOT cover comms — `mark_read_as` is applied server-side
    # during collection, so those messages are already consumed and will not
    # re-fire. That gap is named in the README, not papered over here.
    try:
        mind_phase()
    except Exception as e:  # noqa: BLE001 — deliberately broad; see above
        sweep_error = sanitizer.cap_field(
            sanitizer.mask_token_shaped(f"{type(e).__name__}: {e}")
        )
        envelope["sweep_error"] = sweep_error
        log_line(
            root,
            f"sweep {sweep_id} — PARTIAL FAILURE after collection: {sweep_error}; "
            f"high-water NOT advanced, filesystem deltas re-fire next sweep",
            dry_run=dry_run,
        )
        if not dry_run and envelope["grok_process_state"] == "spawned":
            # The spend happened and the deltas will re-fire: that pairing is
            # the loop. Persist ONLY the streak — a fresh load keeps the
            # un-advanced high-water exactly as it is on disk.
            fresh = load_state(root)
            fresh["mind_failure_streak"] = prev_mind_streak + 1
            save_state(root, fresh)
            envelope["mind"]["failure_streak"] = prev_mind_streak + 1

    if sweep_error is None:
        if envelope["grok_process_state"] == "spawned":
            # A spawn that completed the whole sweep proves the mind path
            # works again; anything else (resting, blind, spawn-failed, no
            # items) is not evidence either way, so the streak holds.
            state["mind_failure_streak"] = 0
        else:
            state["mind_failure_streak"] = prev_mind_streak

    spool_writer.write_sweep(root, envelope, dry_run=dry_run)
    if not dry_run and sweep_error is None:
        save_state(root, state)
    return envelope


def main(argv=None):
    ap = argparse.ArgumentParser(description="Watchman mechanical sweep (one-shot)")
    ap.add_argument(
        "--root", default=None, help="sovereign root (default ~/.sovereign)"
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="full mechanical sweep that MUTATES NOTHING: cosmic is never "
        "invoked, mark_read_as is omitted, the high-water state is not written, "
        "and every output goes to dry-run-only files (dry-run-spool.jsonl, "
        "latest.dry-run.md, watchman.dry-run.log, <sweep>.dry-run-prompt.txt). "
        "A dry run can never blind a subsequent live sweep.",
    )
    ap.add_argument("--cosmic-bin", default=None, help="override cosmic-cli path")
    ap.add_argument(
        "--reset-mind",
        action="store_true",
        help="zero the mind-rest failure streak (after repairing the grok "
        "phase) so the next sweep invokes cosmic again",
    )
    args = ap.parse_args(argv)

    root = resolve_root(args.root)
    if args.reset_mind:
        fresh = load_state(root)
        fresh["mind_failure_streak"] = 0
        save_state(root, fresh)
        print("mind-rest streak reset to 0")
    with sweep_lock(root) as acquired:
        if not acquired:
            # An overlapping invocation touches NOTHING: no scan, no state, no
            # spool, no cosmic. One honest line so the skip is visible, and
            # exit 0 so launchd does not treat a correct skip as a failure.
            log_line(root, "sweep already live, skipping", dry_run=args.dry_run)
            print("watchman: sweep already live, skipping")
            return 0
        envelope = run_sweep(root, dry_run=args.dry_run, cosmic_bin=args.cosmic_bin)
    if envelope is None:
        print("watchman: quiet sweep — no deltas, grok not invoked")
    else:
        cov = envelope.get("reply_coverage") or {}
        print(
            f"watchman: sweep {envelope['sweep_id']} — "
            f"{envelope['counts']['items_seen']} item(s), "
            f"grok_invoked={envelope['grok_invoked']} "
            f"({envelope.get('grok_process_state')}), "
            f"reply={envelope['grok_reply_state']}, "
            f"coverage={cov.get('answered', '-')}/{cov.get('expected', '-')}, "
            f"ceiling={envelope.get('severity_ceiling')}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
