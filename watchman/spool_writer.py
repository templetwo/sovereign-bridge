#!/usr/bin/env python3
"""
Sovereign Stack — Watchman spool writer.

Appends sweep envelopes to <root>/watchman/spool.jsonl and renders
<root>/watchman/latest.md for the next booting seat.

The spool is machine-local WORKING MEMORY — helix-side of the two-layer
boundary. It is NOT the Stack record and nothing here writes to the Stack.
Durable findings travel only when the HQ seat reads the spool and lands them
with receipts. Escalation ceiling: an 'urgent' line in this spool. The
watchman never texts Anthony — his phone is an HQ-and-him channel only.

Envelope honesty rules (the fail-open class is the one we hunt):
  - surfaces_watched lists ALL FIVE surfaces every sweep, each with ok/error.
    A surface that could not be read is REPORTED, never silently omitted, and
    contributes a mechanical 'attend' line about the surface itself.
  - counts state items_seen / items_previewed / items_metadata_only with
    per-reason breakdown, so a partial view can never read as a full one.
  - grok_invoked is recorded either way; a mechanical-only sweep says so.
  - an unparseable Grok reply is recorded as 'grok-reply-unparseable' with the
    raw kept in a quarantine file — never silently dropped.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

SEVERITIES = ("info", "attend", "urgent")


def _now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _local_stamp():
    # Rendered for the human/next seat in the machine's local time (Eastern on
    # HQ), with UTC alongside so the stamp travels unambiguously.
    now = datetime.now().astimezone()
    return now.strftime("%Y-%m-%d %H:%M %Z")


def mechanical_lines(envelope):
    """Attend/urgent lines the MECHANICAL tier owns (no Grok involved):
    one 'attend' per surface that errored — the line is about the instrument,
    not the traffic it failed to read."""
    lines = []
    for name, info in (envelope.get("surfaces") or {}).items():
        if not info.get("ok", False):
            lines.append(
                {
                    "severity": "attend",
                    "ref": f"surface:{name}",
                    "reason": f"surface could not be read: {info.get('error', 'unknown error')}",
                    "source": "mechanical",
                }
            )
    return lines


def severity_ceiling(envelope):
    """Highest severity present across mechanical lines and Grok's items."""
    seen = set()
    for line in mechanical_lines(envelope):
        seen.add(line["severity"])
    reply = envelope.get("grok_reply") or {}
    for item in reply.get("items", []) if isinstance(reply, dict) else []:
        sev = item.get("severity")
        if sev in SEVERITIES:
            seen.add(sev)
    for sev in reversed(SEVERITIES):
        if sev in seen:
            return sev
    return None


def write_sweep(root, envelope):
    """Append the envelope to the spool and re-render latest.md.

    Returns the path of the spool file. The append is a single JSON line; the
    render is a full rewrite of latest.md (it is a view, not a record).
    Enriches the CALLER's envelope in place (mechanical_lines, severity_ceiling,
    spooled_at) so what the caller reports matches what was spooled."""
    watch_dir = Path(root) / "watchman"
    watch_dir.mkdir(parents=True, exist_ok=True)
    envelope.setdefault("spooled_at", _now_iso())
    envelope["mechanical_lines"] = mechanical_lines(envelope)
    envelope["severity_ceiling"] = severity_ceiling(envelope)

    spool_path = watch_dir / "spool.jsonl"
    with open(spool_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(envelope, ensure_ascii=False, default=str) + "\n")

    (watch_dir / "latest.md").write_text(render_latest(envelope), encoding="utf-8")
    return spool_path


def render_latest(envelope):
    """Render the most recent sweep for the next booting seat."""
    surfaces = envelope.get("surfaces") or {}
    counts = envelope.get("counts") or {}
    meta_only = counts.get("items_metadata_only") or {}
    reply = (
        envelope.get("grok_reply")
        if isinstance(envelope.get("grok_reply"), dict)
        else None
    )
    ceiling = envelope.get("severity_ceiling")

    lines = []
    lines.append("# Watchman — latest sweep")
    lines.append("")
    lines.append(
        f"Sweep `{envelope.get('sweep_id', '?')}` at {_local_stamp()} "
        f"(UTC {envelope.get('finished_at', envelope.get('started_at', '?'))})"
        + ("  **[DRY RUN]**" if envelope.get("dry_run") else "")
    )
    lines.append("")
    if ceiling:
        lines.append(f"**Severity ceiling this sweep: {ceiling.upper()}**")
    else:
        lines.append("Severity ceiling this sweep: none (quiet)")
    lines.append("")
    lines.append(
        "The watchman notices, classifies, proposes. It never enacts, never "
        "texts Anthony (his phone is an HQ-and-him channel), never writes the "
        "Stack chronicle. An 'urgent' line here is the escalation ceiling — "
        "the HQ seat relays."
    )
    lines.append("")

    lines.append("## Surfaces watched")
    lines.append("")
    lines.append("| surface | ok | detail |")
    lines.append("|---|---|---|")
    for name, info in surfaces.items():
        ok = "yes" if info.get("ok") else "**NO**"
        detail = info.get("error") or info.get("note") or ""
        lines.append(f"| {name} | {ok} | {detail} |")
    lines.append("")

    lines.append("## Coverage + confidence envelope")
    lines.append("")
    lines.append(f"- items_seen: {counts.get('items_seen', 0)}")
    lines.append(f"- items_previewed (sanitized): {counts.get('items_previewed', 0)}")
    lines.append(
        "- items_metadata_only: "
        + (", ".join(f"{k}={v}" for k, v in meta_only.items() if v) or "0")
    )
    lines.append(f"- eyes policy: {envelope.get('policy_state', '?')}")
    lines.append(f"- grok_invoked: {envelope.get('grok_invoked', False)}")
    lines.append(
        f"- grok_reply_state: {envelope.get('grok_reply_state', 'not-invoked')}"
    )
    if envelope.get("quarantine_file"):
        lines.append(f"- quarantined raw reply: `{envelope['quarantine_file']}`")
    lines.append("")

    mech = envelope.get("mechanical_lines") or []
    if mech:
        lines.append("## Mechanical attention lines (instrument, not traffic)")
        lines.append("")
        for m in mech:
            lines.append(f"- [{m['severity'].upper()}] {m['ref']}: {m['reason']}")
        lines.append("")

    items = envelope.get("items") or []
    if items:
        lines.append("## Delta items")
        lines.append("")
        reply_by_ref = {}
        if reply:
            for it in reply.get("items", []):
                if isinstance(it, dict) and it.get("ref"):
                    reply_by_ref[it["ref"]] = it
        for item in items:
            ref = item.get("ref", "?")
            head = (
                f"- `{ref}` [{item.get('change', '?')}] "
                f"size={item.get('size', '?')} risk={item.get('risk_level') or '-'} "
                f"preview={item.get('preview_state', '?')}"
            )
            lines.append(head)
            judged = reply_by_ref.get(ref)
            if judged:
                flag = (
                    " · flagged for richer review"
                    if judged.get("flagged_for_richer_review")
                    else ""
                )
                lines.append(
                    f"  - grok: [{judged.get('severity', '?')}] "
                    f"{judged.get('reason', '')}{flag}"
                )
                if judged.get("confidence_basis"):
                    lines.append(f"  - confidence basis: {judged['confidence_basis']}")
        lines.append("")

    if reply:
        obs = reply.get("observation") or {}
        prop = reply.get("proposal") or {}
        lines.append("## Grok — OBSERVATION")
        lines.append("")
        lines.append(str(obs.get("summary", "")).strip() or "(none)")
        for a in obs.get("anomalies", []) or []:
            lines.append(f"- {a}")
        lines.append("")
        lines.append("## Grok — PROPOSAL (proposals only; nothing here is enacted)")
        lines.append("")
        lines.append(str(prop.get("summary", "")).strip() or "(none)")
        for a in prop.get("actions_proposed", []) or []:
            lines.append(f"- {a}")
        lines.append("")

    lines.append("---")
    lines.append(
        "*This spool is machine-local working memory (helix-side of the "
        "two-layer boundary), not the Stack record. Durable findings are HQ's "
        "to land, with receipts.*"
    )
    lines.append("")
    return "\n".join(lines)
