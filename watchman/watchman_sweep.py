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
"""

import argparse
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
SURFACE_NAMES = ("pending_writes", "halts", "handoffs", "heartbeat", "comms")

DEFAULT_ROOT = Path.home() / ".sovereign"
DEFAULT_STACK_REPO = Path.home() / "sovereign-stack"
DEFAULT_COSMIC_BIN = str(Path.home() / "cosmic-cli" / "venv" / "bin" / "cosmic-cli")
DEFAULT_BRIDGE_URL = "http://127.0.0.1:8100"
COSMIC_TIMEOUT_S = 180
COMMS_CHANNEL = "general"
INSTANCE_ID = "watchman"

DIRECTIVE_PATH = Path(__file__).resolve().parent / "directive.md"
IDENTITY_LINE = "WATCHMAN SWEEP — grok-4.5 via cosmic-cli"


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
    try:
        return json.loads(state_path(root).read_text(encoding="utf-8"))
    except Exception:
        return {"files": {}, "handoffs_unconsumed": None, "heartbeat": {}, "sweeps": 0}


def save_state(root, state):
    p = state_path(root)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(state, indent=2, default=str), encoding="utf-8")
    tmp.replace(p)


def log_line(root, text):
    p = Path(root) / "watchman" / "watchman.log"
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
    try:
        if not hdir.is_dir():
            raise FileNotFoundError(f"{hdir} is not a directory")
        for path in sorted(hdir.iterdir()):
            if not path.is_file() or path.suffix != ".json":
                continue
            try:
                data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
            except (json.JSONDecodeError, OSError):
                continue
            if not data.get("consumed_at"):
                unconsumed += 1
                newest.append(path.name)
    except OSError as e:
        surface["ok"] = False
        surface["error"] = str(e)
        return surface, items, state.get("handoffs_unconsumed")
    prev = state.get("handoffs_unconsumed")
    surface["note"] = f"unconsumed={unconsumed}"
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


def scan_comms(*, comms_fetch):
    """Surface (e): the legacy comms board. daemon.uncertainty still posts
    there; the watchman inherits the watch so those whispers finally land."""
    surface = {"ok": True, "error": None}
    items = []
    try:
        data = comms_fetch()
        messages = data.get("messages", []) or []
        surface["note"] = f"unread={len(messages)}"
        if len(messages) >= COMMS_READ_LIMIT:
            # count == requested limit means the board may hold MORE unread
            # than this sweep saw. Say so — a capped read must never present
            # itself as a complete one (the silent-partial class).
            surface["note"] += (
                f" (capped at limit={COMMS_READ_LIMIT}, possibly partial)"
            )
            surface["possibly_partial"] = True
        for m in messages:
            if not isinstance(m, dict):
                continue
            if m.get("sender") == INSTANCE_ID:
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
    """One-shot `cosmic-cli ask` — no agent loop, no tools, no enactment lane."""
    proc = subprocess.run(
        [cosmic_bin, "ask", prompt],
        capture_output=True,
        text=True,
        timeout=COSMIC_TIMEOUT_S,
    )
    return proc.returncode, proc.stdout, proc.stderr


def parse_grok_reply(raw: str):
    """Extract the strict-JSON envelope from a reply that may carry the
    identity line, a CLI banner, or code fences around it. Returns
    (parsed_dict_or_None, identity_line_present)."""
    if not raw:
        return None, False
    identity_present = IDENTITY_LINE in raw
    text = raw.replace("```json", "```")
    # Balanced-brace scan from each '{' — first complete object that parses wins.
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
                        if isinstance(parsed, dict):
                            return parsed, identity_present
                    except json.JSONDecodeError:
                        pass
                    break
        start = text.find("{", start + 1)
    return None, identity_present


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
    raw_items = []  # (meta, body) pairs

    surfaces["pending_writes"], pw_items, pw_seen = scan_pending_writes(root, state)
    raw_items.extend(pw_items)
    surfaces["halts"], halt_items, halt_seen = scan_halts(root, state)
    raw_items.extend(halt_items)
    surfaces["handoffs"], ho_items, unconsumed = scan_handoffs(root, state)
    raw_items.extend(ho_items)
    surfaces["heartbeat"], hb_items, hb_state = scan_heartbeat(
        state, heartbeat_fetch=heartbeat_fetch, git_head_fn=git_head_fn
    )
    raw_items.extend(hb_items)
    surfaces["comms"], comms_items = scan_comms(comms_fetch=comms_fetch)
    raw_items.extend(comms_items)

    # Sanitize: metadata always; preview only through the eyes policy.
    items = []
    meta_only_counts = {"denylist": 0, "sanitizer-failed": 0, "unparseable": 0}
    previewed = 0
    for meta, body in raw_items:
        preview, preview_state = sanitizer.preview_for(
            body, meta, policy, **sanitize_kwargs
        )
        item = dict(meta)
        item["preview_state"] = preview_state
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

    # High-water state update happens regardless of outcome — the mechanical
    # heartbeat is written even when grok is not invoked.
    new_files = dict(state.get("files", {}))
    if surfaces["pending_writes"]["ok"] or pw_seen:
        for k in [k for k in new_files if any(k.startswith(q + "/") for q in QUEUES)]:
            if surfaces["pending_writes"]["ok"] and k not in pw_seen:
                del new_files[k]
        new_files.update(pw_seen)
    if surfaces["halts"]["ok"]:
        for k in [k for k in new_files if k.startswith("daemons/halts/")]:
            if k not in halt_seen:
                del new_files[k]
        new_files.update(halt_seen)
    state["files"] = new_files
    if surfaces["handoffs"]["ok"]:
        state["handoffs_unconsumed"] = unconsumed
    if surfaces["heartbeat"]["ok"]:
        state["heartbeat"] = hb_state
    state["last_sweep"] = started_at
    state["sweeps"] = int(state.get("sweeps", 0)) + 1
    save_state(root, state)

    if not items and not surface_errors:
        log_line(
            root,
            f"sweep {sweep_id} quiet — 5 surfaces ok, 0 deltas; state touched, "
            f"grok not invoked",
        )
        return None

    counts = {
        "items_seen": len(items),
        "items_previewed": previewed,
        "items_metadata_only": meta_only_counts,
    }
    envelope = {
        "kind": "watchman-sweep",
        "sweep_id": sweep_id,
        "started_at": started_at,
        "finished_at": now_iso(),
        "root": str(root),
        "dry_run": bool(dry_run),
        "surfaces": surfaces,
        "counts": counts,
        "policy_state": policy_state,
        "items": items,
        "grok_invoked": False,
        "grok_model": "grok-4.5",
        "grok_reply": None,
        "grok_reply_state": "not-invoked",
        "quarantine_file": None,
    }

    if items and dry_run:
        envelope["grok_reply_state"] = "dry-run"
        prompt_file = Path(root) / "watchman" / f"{sweep_id}.dry-run-prompt.txt"
        prompt_file.parent.mkdir(parents=True, exist_ok=True)
        digest = {k: envelope[k] for k in ("sweep_id", "surfaces", "counts", "items")}
        prompt_file.write_text(build_prompt(digest), encoding="utf-8")
        envelope["dry_run_prompt_file"] = str(prompt_file)
        log_line(
            root, f"sweep {sweep_id} DRY RUN — {len(items)} deltas, grok NOT invoked"
        )
    elif items:
        digest = {k: envelope[k] for k in ("sweep_id", "surfaces", "counts", "items")}
        try:
            rc, stdout, stderr = invoke_cosmic(
                build_prompt(digest), cosmic_bin=cosmic_bin
            )
            envelope["grok_invoked"] = True
            parsed, identity_present = parse_grok_reply(stdout if rc == 0 else "")
            if rc != 0 or parsed is None:
                qfile = quarantine_reply(root, sweep_id, stdout, stderr)
                envelope["grok_reply_state"] = "grok-reply-unparseable"
                envelope["quarantine_file"] = str(qfile)
            else:
                envelope["grok_reply"] = parsed
                envelope["grok_reply_state"] = "parsed"
                envelope["grok_identity_line_present"] = identity_present
        except (subprocess.TimeoutExpired, OSError) as e:
            envelope["grok_invoked"] = True
            qfile = quarantine_reply(root, sweep_id, "", f"invocation failed: {e}")
            envelope["grok_reply_state"] = "grok-reply-unparseable"
            envelope["quarantine_file"] = str(qfile)
        log_line(
            root,
            f"sweep {sweep_id} — {len(items)} deltas, grok invoked, "
            f"reply={envelope['grok_reply_state']}",
        )
    else:
        # Surface errors only: mechanical envelope, no semantic content to
        # classify — the attend line is about the instrument itself.
        log_line(
            root,
            f"sweep {sweep_id} — 0 deltas but surface errors: "
            f"{', '.join(surface_errors)}; grok not invoked",
        )

    spool_writer.write_sweep(root, envelope)
    return envelope


def main(argv=None):
    ap = argparse.ArgumentParser(description="Watchman mechanical sweep (one-shot)")
    ap.add_argument(
        "--root", default=None, help="sovereign root (default ~/.sovereign)"
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="full mechanical sweep, but never invoke cosmic and never mutate "
        "the comms board (mark_read_as omitted); the would-be prompt is saved "
        "next to the spool",
    )
    ap.add_argument("--cosmic-bin", default=None, help="override cosmic-cli path")
    args = ap.parse_args(argv)

    root = resolve_root(args.root)
    envelope = run_sweep(root, dry_run=args.dry_run, cosmic_bin=args.cosmic_bin)
    if envelope is None:
        print("watchman: quiet sweep — no deltas, grok not invoked")
    else:
        print(
            f"watchman: sweep {envelope['sweep_id']} — "
            f"{envelope['counts']['items_seen']} item(s), "
            f"grok_invoked={envelope['grok_invoked']}, "
            f"reply={envelope['grok_reply_state']}, "
            f"ceiling={envelope.get('severity_ceiling')}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
