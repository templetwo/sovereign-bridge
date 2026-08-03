#!/usr/bin/env python3
"""
Sovereign Stack — Watchman eyes policy (sanitized previews, fail-closed).

Implements Option C — Grok's own proposal for what the watchman's mind may see,
adopted by HQ with fail-closed tightenings. NOTHING attacker-controlled leaves
this module unredacted: metadata and body previews run through the SAME
redactor, and every gate failing yields metadata-only with an honest state.

A body preview travels ONLY when every gate passes:

  (a) the item is not denylisted (protected/consent floor + eyes_policy.json),
      checked against BOTH the raw and the sanitized metadata, homoglyph-folded;
  (b) the t2helix redaction subprocess succeeded within its timeout;
  (c) the source file was parseable enough to yield a body at all;
  (d) the redacted body is not whitespace-only;
  (e) the redacted body carries no eyes-policy sensitive-content term.

Preview states:
  'sanitized'                       — preview present, redacted
  'metadata-only:denylist'          — eyes policy says no preview, ever
  'metadata-only:sanitizer-failed'  — subprocess error/timeout/empty output
  'metadata-only:unparseable'       — file gave no readable body
  'metadata-only:empty-body'        — body was whitespace only; nothing inspected
  'metadata-only:content-flagged'   — redacted body hit a sensitive-content term

The redaction itself is t2helix's lib/secrets.js scrub() — the same single
source of truth that guards the helix write path — invoked via
sanitize_preview.js so the pattern table can never drift from the helix's.

ORDER OF OPERATIONS (fail-closed reading of the spec): the spec says "first 600
chars of a body run through the redaction patterns". Truncating BEFORE
redaction can split a credential across the cut so the pattern misses the
fragment; we therefore redact a wide window (SANITIZER_INPUT_WINDOW chars)
first, mask base64 blobs, run the content gate, and truncate LAST. A secret
split at the window boundary lands at position ~window, far past the 600-char
preview cut, so it can never enter a preview.
"""

import copy
import json
import os
import re
import subprocess
import unicodedata
from pathlib import Path

PREVIEW_CHARS = 600
METADATA_FIELD_CHARS = 200
SANITIZER_INPUT_WINDOW = 8192
SANITIZER_TIMEOUT_S = 2.0

# A metadata field whose redaction could not be completed is replaced by this
# typed token — never the verbatim value. Fail closed, and SAY so.
UNSANITIZED_TOKEN = "<field-unsanitized:omitted>"

# Runs of base64-alphabet characters this long or longer are replaced with
# '<BASE64-BLOB:len=N>' in previews. Watchman-side mitigation of an UPSTREAM
# t2helix limit: no pattern in lib/secrets.js decodes base64, and the watchman's
# exposure differs in kind from the helix's — the helix persists locally, the
# watchman ships the preview to a third-party model.
BASE64_RUN_MIN = 40
_BASE64_RUN_RE = re.compile(r"[A-Za-z0-9+/]{%d,}={0,2}" % BASE64_RUN_MIN)

# The non-configurable floor. eyes_policy.json can only ADD to this — nothing
# in a config file can turn the protected/consent gate off.
FLOOR_TOOLS = frozenset({"comms_acknowledge"})
FLOOR_SUBSTRINGS = ("protected", "consent")

# Compiled-in seeds, byte-equivalent to the shipped eyes_policy.json. If the
# policy file is MISSING we fall back HERE (policy_state 'builtin-fallback'),
# so a lost config file can never widen the eyes.
DEFAULT_POLICY = {
    "denylist_queues": ["antigravity_connector"],
    "denylist_tools": [],
    "denylist_domains": ["biomedical", "biomed", "security-audit"],
    "content_terms": [
        "consent",
        "protected",
        "privileged",
        "confidential",
        "off the record",
        "do not share",
        "personally identifiable",
        "medical record",
        "diagnosis",
        "prescription",
        "social security",
        "date of birth",
        "biomedical",
        "biomed",
        "plasmid",
        "titer",
        "assay",
        "pathogen",
        "virulence",
        "biosafety",
        "select agent",
        "gene synthesis",
        "nucleotide sequence",
        "in vitro",
        "reverse genetics",
    ],
}

# A policy file that EXISTS but does not validate means someone edited the
# config wrong — the config cannot be trusted at all, so the eyes close
# completely. metadata-only for everything, and the sweep says so out loud.
FLOOR_POLICY = {
    "deny_all": True,
    "denylist_queues": [],
    "denylist_tools": [],
    "denylist_domains": [],
    "content_terms": [],
}

POLICY_LIST_KEYS = (
    "denylist_queues",
    "denylist_tools",
    "denylist_domains",
    "content_terms",
)

_SCRIPT_PATH = Path(__file__).resolve().parent / "sanitize_preview.js"

# node is NOT on launchd's default PATH (verified: `env -i PATH=/usr/bin:/bin:
# /usr/sbin:/sbin which node` finds nothing; the real binary is under
# /opt/homebrew). A bare 'node' therefore turns the eyes off the moment the
# sweep runs from launchd instead of a login shell. Resolution chain:
#   WATCHMAN_NODE_BIN -> /opt/homebrew/bin/node -> /usr/local/bin/node -> node
NODE_BIN_CANDIDATES = ("/opt/homebrew/bin/node", "/usr/local/bin/node")


def resolve_node_bin() -> str:
    override = os.environ.get("WATCHMAN_NODE_BIN")
    if override:
        return override
    for candidate in NODE_BIN_CANDIDATES:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return "node"


def default_t2helix_root() -> str:
    return os.environ.get("T2HELIX_ROOT", str(Path.home() / "t2helix"))


# ---------------------------------------------------------------- folding

# Confusables that let one codepoint walk past an ASCII substring test. The
# review proved it: declared_domain 'prоtected-drawer' with a Cyrillic 'о'
# returned denylisted() == False and the body previewed in full.
CONFUSABLES = {
    # Cyrillic -> Latin
    "а": "a",
    "в": "b",
    "е": "e",
    "к": "k",
    "м": "m",
    "н": "h",
    "о": "o",
    "р": "p",
    "с": "c",
    "т": "t",
    "у": "y",
    "х": "x",
    "і": "i",
    "ј": "j",
    "ѕ": "s",
    "һ": "h",
    # Greek -> Latin
    "α": "a",
    "β": "b",
    "ε": "e",
    "η": "n",
    "ι": "i",
    "κ": "k",
    "ν": "v",
    "ο": "o",
    "ρ": "p",
    "σ": "o",
    "τ": "t",
    "υ": "u",
    "χ": "x",
    "μ": "u",
    # Latin lookalikes / fullwidth handled by NFKC, these are the leftovers
    "ı": "i",
    "ɡ": "g",
}

_CONFUSABLE_TABLE = str.maketrans(CONFUSABLES)


def fold(text) -> str:
    """Normalize a string for MATCHING ONLY — never persist the folded form.

    NFKC (collapses fullwidth/compatibility forms) + casefold + a small
    confusables map. Applied to both needle and haystack so a lookalike
    codepoint cannot walk past a denylist term.
    """
    if text is None:
        return ""
    s = unicodedata.normalize("NFKC", str(text))
    return s.translate(_CONFUSABLE_TABLE).casefold()


# ---------------------------------------------------------------- text shaping


def mask_base64_blobs(text: str) -> str:
    """Replace runs of BASE64_RUN_MIN+ base64-alphabet chars with a typed token.

    Applied to PREVIEWS ONLY (HQ's scoping). Metadata fields are redacted and
    capped at METADATA_FIELD_CHARS instead — masking there would eat 40-char
    git SHAs out of the heartbeat mismatch detail, which is the one field HQ
    reads that surface for.
    """
    if not text:
        return text

    def _repl(m):
        return f"<BASE64-BLOB:len={len(m.group(0))}>"

    return _BASE64_RUN_RE.sub(_repl, text)


def truncate_with_marker(text: str, limit: int, original_len: int) -> str:
    """Truncate to `limit` chars and SAY so. Silent truncation is the
    silent-partial class: a reader cannot tell a complete body from the first
    600 chars of a 50MB one."""
    shown = text[:limit]
    if len(text) > limit or original_len > SANITIZER_INPUT_WINDOW:
        return f"{shown}…[truncated: showing {len(shown)} of {original_len} chars]"
    return shown


def cap_field(value: str) -> str:
    """Length-cap one metadata field, with the same explicit marker."""
    if value is None:
        return value
    return truncate_with_marker(value, METADATA_FIELD_CHARS, len(value))


# ---------------------------------------------------------------- policy


def _validate_policy(raw):
    """Strict schema check. Returns the normalized policy or raises ValueError.

    Every field is TYPE-CHECKED, never coerced. The old loader ran a list
    comprehension over whatever it found, so `"denylist_queues":
    "antigravity_connector"` (a plausible hand-edit typo, brackets dropped)
    iterated the STRING into single characters and silently stopped denying the
    antigravity queue while still reporting policy_state 'loaded'.
    """
    if not isinstance(raw, dict):
        raise ValueError(f"policy root must be an object, got {type(raw).__name__}")
    policy = {}
    for key in POLICY_LIST_KEYS:
        if key not in raw:
            policy[key] = []
            continue
        value = raw[key]
        if not isinstance(value, list):
            raise ValueError(f"{key} must be a list, got {type(value).__name__}")
        entries = []
        for entry in value:
            if not isinstance(entry, str):
                raise ValueError(
                    f"{key} entries must be strings, got {type(entry).__name__}"
                )
            entries.append(entry.lower())
        policy[key] = entries
    return policy


def load_policy(policy_path=None):
    """Return (policy_dict, policy_state). Never raises; never widens on error.

    States:
      'loaded'           — file read and validated
      'builtin-fallback' — file absent; compiled-in seeds (byte-equal to the
                           shipped file, so nothing widens)
      'floor-fallback'   — file present but unreadable/unparseable/invalid:
                           the config is untrustworthy, so the eyes CLOSE
                           (metadata-only for everything)

    Anything other than 'loaded' also raises a mechanical 'attend' line about
    the policy file itself (spool_writer.mechanical_lines) — never silent.
    """
    if policy_path is None:
        policy_path = Path(__file__).resolve().parent / "eyes_policy.json"
    path = Path(policy_path)
    if not path.exists():
        return dict(DEFAULT_POLICY), "builtin-fallback"
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        return _validate_policy(raw), "loaded"
    except Exception:
        return dict(FLOOR_POLICY), "floor-fallback"


# ---------------------------------------------------------------- denylist


def _iter_strings(value):
    """Every string anywhere in a metadata structure (dicts, lists, scalars)."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from _iter_strings(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from _iter_strings(v)


def content_flagged(text, policy: dict) -> bool:
    """True when the eyes-policy sensitive-content terms hit `text`.

    The CONTENT leg of the denylist. The declaration leg (queue/tool/domain)
    only catches sensitivity the writer declared; this one reads what is
    actually there. Over-withholding is accepted by design — Grok's
    flag-for-richer-review covers what a withheld preview costs.
    """
    terms = policy.get("content_terms") or []
    if not terms:
        return False
    haystack = fold(text)
    return any(fold(term) in haystack for term in terms if term)


def denylisted(meta: dict, policy: dict) -> bool:
    """True when the eyes policy forbids a preview for this item's metadata.

    Checks are substring/containment, homoglyph-folded and case-insensitive,
    fail-closed: an absent field never grants a preview a present field would
    have denied. Floor substrings and content terms are checked against EVERY
    string in the metadata (including nested `detail`), not just the two fields
    a writer chose to declare.
    """
    if policy.get("deny_all"):
        return True

    queue = fold(meta.get("queue") or "")
    tool = fold(meta.get("tool") or "")
    domain = fold(meta.get("declared_domain") or "")
    all_strings = [fold(s) for s in _iter_strings(meta)]

    if tool in {fold(t) for t in FLOOR_TOOLS}:
        return True
    for needle in FLOOR_SUBSTRINGS:
        folded_needle = fold(needle)
        if any(folded_needle in s for s in all_strings):
            return True
    if queue in [fold(q) for q in policy.get("denylist_queues", [])]:
        return True
    if tool and tool in [fold(t) for t in policy.get("denylist_tools", [])]:
        return True
    for deny_domain in policy.get("denylist_domains", []):
        folded = fold(deny_domain)
        if folded and folded in domain:
            return True
    # The content leg, applied to metadata too: a sensitive term in a filename,
    # a sender, or a handoff detail is the same disclosure as one in a body.
    for term in policy.get("content_terms", []) or []:
        folded = fold(term)
        if folded and any(folded in s for s in all_strings):
            return True
    return False


# ---------------------------------------------------------------- redaction


def run_redactor(
    body: str,
    *,
    node_bin: str | None = None,
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
    if node_bin is None:
        node_bin = resolve_node_bin()
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


def run_redactor_batch(
    values,
    *,
    node_bin: str | None = None,
    script_path=None,
    t2helix_root: str | None = None,
    timeout: float = SANITIZER_TIMEOUT_S,
):
    """Scrub a LIST of strings independently in one subprocess.

    Returns (list_of_redacted, 'sanitized') or (None, 'sanitizer-failed').
    Used for metadata: one process per item instead of one per field, with
    every field still scrubbed on its own so scrub()'s coarse-mask backstop on
    one poisoned field cannot erase the rest.
    """
    if script_path is None:
        script_path = _SCRIPT_PATH
    if node_bin is None:
        node_bin = resolve_node_bin()
    if t2helix_root is None:
        t2helix_root = default_t2helix_root()
    payload = json.dumps([str(v)[:SANITIZER_INPUT_WINDOW] for v in values])
    env = dict(os.environ)
    env["T2HELIX_ROOT"] = str(t2helix_root)
    try:
        proc = subprocess.run(
            [node_bin, str(script_path), "--json"],
            input=payload.encode("utf-8", errors="replace"),
            capture_output=True,
            timeout=timeout,
            env=env,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None, "sanitizer-failed"
    if proc.returncode != 0:
        return None, "sanitizer-failed"
    try:
        out = json.loads(proc.stdout.decode("utf-8", errors="replace"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None, "sanitizer-failed"
    if not isinstance(out, list) or len(out) != len(values):
        return None, "sanitizer-failed"
    if not all(isinstance(v, str) for v in out):
        return None, "sanitizer-failed"
    return out, "sanitized"


# ---------------------------------------------------------------- metadata


def _collect_string_paths(node, prefix, paths, values):
    if isinstance(node, str):
        paths.append(tuple(prefix))
        values.append(node)
    elif isinstance(node, dict):
        for k, v in node.items():
            _collect_string_paths(v, prefix + [k], paths, values)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            _collect_string_paths(v, prefix + [i], paths, values)


def _set_path(root, path, value):
    node = root
    for step in path[:-1]:
        node = node[step]
    node[path[-1]] = value


def sanitize_metadata(meta: dict, **redactor_kwargs):
    """Return (sanitized_meta, ok).

    EVERY string metadata field — at any depth — runs through the same redactor
    as previews, then is capped at METADATA_FIELD_CHARS with an explicit
    truncation marker. This closes the leak-hunt's headline finding: metadata
    was copied VERBATIM out of untrusted files and board messages and travelled
    to xAI in argv, in the prompt, and into the spool. A field whose redaction
    could not be completed becomes UNSANITIZED_TOKEN — never the raw value.
    """
    paths, values = [], []
    _collect_string_paths(meta, [], paths, values)
    safe = copy.deepcopy(meta)
    if not values:
        return safe, True
    redacted, state = run_redactor_batch(values, **redactor_kwargs)
    ok = state == "sanitized" and redacted is not None
    for i, path in enumerate(paths):
        if ok:
            value = redacted[i]
            if values[i].strip() and not value.strip():
                # scrub of non-empty text is never empty — treat as a failure
                # of THIS field rather than trusting the blank.
                value = UNSANITIZED_TOKEN
            else:
                value = cap_field(value)
        else:
            value = UNSANITIZED_TOKEN
        _set_path(safe, path, value)
    return safe, ok


# ---------------------------------------------------------------- decision


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
    masked = mask_base64_blobs(redacted)
    if not masked.strip():
        # Nothing was actually inspected — counting this as 'previewed' would
        # inflate the coverage number with empty reads.
        return None, "metadata-only:empty-body"
    if content_flagged(masked, policy):
        # The CONTENT leg: sensitivity that was never declared in metadata.
        return None, "metadata-only:content-flagged"
    return truncate_with_marker(masked, PREVIEW_CHARS, len(body)), "sanitized"
