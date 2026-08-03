#!/usr/bin/env python3
"""
Sovereign Stack — Watchman eyes policy (sanitized previews, fail-closed).

Implements Option C — Grok's own proposal for what the watchman's mind may see,
adopted by HQ with fail-closed tightenings. Metadata always travels. A body
preview travels ONLY when every gate passes:

  (a) the item is not denylisted (protected/consent floor + eyes_policy.json);
  (b) the t2helix redaction subprocess succeeded within its timeout;
  (c) the source file was parseable enough to yield a body at all.

Any gate failing yields metadata-only, with the honest preview_state recorded:
  'sanitized'                      — preview present, redacted
  'metadata-only:denylist'         — eyes policy says no preview, ever
  'metadata-only:sanitizer-failed' — subprocess error/timeout/empty output
  'metadata-only:unparseable'      — file gave no readable body

The redaction itself is t2helix's lib/secrets.js scrub() — the same single
source of truth that guards the helix write path — invoked via
sanitize_preview.js so the pattern table can never drift from the helix's.

ORDER OF OPERATIONS (fail-closed reading of the spec): the spec says "first 600
chars of a body run through the redaction patterns". Truncating BEFORE
redaction can split a credential across the cut so the pattern misses the
fragment; we therefore redact a wide window (SANITIZER_INPUT_WINDOW chars)
first and truncate the REDACTED text to PREVIEW_CHARS after. A secret split at
the window boundary lands at position ~window, far past the 600-char preview
cut, so it can never enter a preview.
"""

import json
import os
import subprocess
from pathlib import Path

PREVIEW_CHARS = 600
SANITIZER_INPUT_WINDOW = 8192
SANITIZER_TIMEOUT_S = 2.0

# The non-configurable floor. eyes_policy.json can only ADD to this — nothing
# in a config file can turn the protected/consent gate off.
FLOOR_TOOLS = frozenset({"comms_acknowledge"})
FLOOR_SUBSTRINGS = ("protected", "consent")

# Compiled-in seeds, byte-equivalent to the shipped eyes_policy.json. If the
# policy file is missing or unreadable we fall back HERE (policy_state
# 'builtin-fallback'), so a lost config file can never widen the eyes.
DEFAULT_POLICY = {
    "denylist_queues": ["antigravity_connector"],
    "denylist_tools": [],
    "denylist_domains": ["biomedical", "biomed", "security-audit"],
}

_SCRIPT_PATH = Path(__file__).resolve().parent / "sanitize_preview.js"


def default_t2helix_root() -> str:
    return os.environ.get("T2HELIX_ROOT", str(Path.home() / "t2helix"))


def load_policy(policy_path=None):
    """Return (policy_dict, policy_state). Never raises; never widens on error."""
    if policy_path is None:
        policy_path = Path(__file__).resolve().parent / "eyes_policy.json"
    try:
        raw = json.loads(Path(policy_path).read_text(encoding="utf-8"))
        policy = {
            "denylist_queues": [str(q).lower() for q in raw.get("denylist_queues", [])],
            "denylist_tools": [str(t).lower() for t in raw.get("denylist_tools", [])],
            "denylist_domains": [
                str(d).lower() for d in raw.get("denylist_domains", [])
            ],
        }
        return policy, "loaded"
    except Exception:
        return dict(DEFAULT_POLICY), "builtin-fallback"


def denylisted(meta: dict, policy: dict) -> bool:
    """True when the eyes policy forbids a preview for this item's metadata.

    Checks are substring/containment and case-insensitive, fail-closed: an
    absent field never grants a preview a present field would have denied.
    """
    queue = str(meta.get("queue") or "").lower()
    tool = str(meta.get("tool") or "").lower()
    filename = str(meta.get("filename") or "").lower()
    domain = str(meta.get("declared_domain") or "").lower()

    if tool in FLOOR_TOOLS:
        return True
    for needle in FLOOR_SUBSTRINGS:
        if needle in filename or needle in domain:
            return True
    if queue in policy.get("denylist_queues", []):
        return True
    if tool and tool in policy.get("denylist_tools", []):
        return True
    for deny_domain in policy.get("denylist_domains", []):
        if deny_domain and deny_domain in domain:
            return True
    return False


def run_redactor(
    body: str,
    *,
    node_bin: str = "node",
    script_path=None,
    t2helix_root: str | None = None,
    timeout: float = SANITIZER_TIMEOUT_S,
):
    """Run the t2helix scrub over `body` in a subprocess.

    Returns (redacted_text, 'sanitized') on success, (None, 'sanitizer-failed')
    on ANY failure — non-zero exit, timeout, spawn error, or empty output for
    non-empty input. The failure path never returns the raw body.
    """
    if script_path is None:
        script_path = _SCRIPT_PATH
    if t2helix_root is None:
        t2helix_root = default_t2helix_root()
    window = body[:SANITIZER_INPUT_WINDOW]
    env = dict(os.environ)
    env["T2HELIX_ROOT"] = str(t2helix_root)
    try:
        proc = subprocess.run(
            [node_bin, str(script_path)],
            input=window.encode("utf-8", errors="replace"),
            capture_output=True,
            timeout=timeout,
            env=env,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None, "sanitizer-failed"
    if proc.returncode != 0:
        return None, "sanitizer-failed"
    out = proc.stdout.decode("utf-8", errors="replace")
    if window.strip() and not out.strip():
        # A scrub of non-empty text is never empty; empty output means the
        # script did not actually run the patterns. Fail closed.
        return None, "sanitizer-failed"
    return out, "sanitized"


def preview_for(body, meta: dict, policy: dict, **redactor_kwargs):
    """The single decision point: (preview_text_or_None, preview_state).

    `body` is the extracted body text, or None when the source file yielded
    none (unparseable). The denylist is checked FIRST so a denylisted body is
    never even handed to the subprocess.
    """
    if denylisted(meta, policy):
        return None, "metadata-only:denylist"
    if body is None:
        return None, "metadata-only:unparseable"
    redacted, state = run_redactor(body, **redactor_kwargs)
    if state != "sanitized" or redacted is None:
        return None, "metadata-only:sanitizer-failed"
    return redacted[:PREVIEW_CHARS], "sanitized"
