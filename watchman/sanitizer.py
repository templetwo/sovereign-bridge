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
  (b) no token in the sanitized metadata mixes Unicode scripts;
  (c) the t2helix redaction subprocess succeeded within its timeout;
  (d) the source file was parseable enough to yield a body at all;
  (e) the redacted body is not whitespace-only;
  (f) the redacted body carries no eyes-policy sensitive-content term and no
      mixed-script token.

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

# A dict KEY whose redaction could not be completed takes the WHOLE PAIR with
# it: the key cannot be named safely, so key and value both drop and the dict
# carries a count of how many pairs were dropped under this token. A count (not
# a bare marker) because two dropped pairs would otherwise collide on one key
# and the second would vanish silently — the silent-partial class.
PAIR_UNSANITIZED_TOKEN = "<pair-unsanitized:omitted>"

# Runs of base64-alphabet characters this long or longer are replaced with
# '<BASE64-BLOB:len=N>' in previews. Watchman-side mitigation of an UPSTREAM
# t2helix limit: no pattern in lib/secrets.js decodes base64, and the watchman's
# exposure differs in kind from the helix's — the helix persists locally, the
# watchman ships the preview to a third-party model.
#
# TWO ALPHABETS, exactly: standard ('+' '/') and URL-safe ('-' '_'), including
# runs that mix them. Base32, base85, and custom alphabets are NOT covered and
# are a named residual in the README.
BASE64_RUN_MIN = 40
_BASE64_RUN_RE = re.compile(r"[A-Za-z0-9+/_-]{%d,}={0,2}" % BASE64_RUN_MIN)

# ---------------------------------------------------------------- token pre-pass
#
# WATCHMAN-SIDE MITIGATION OF AN UPSTREAM GAP, and it does not close it.
#
# t2helix's lib/secrets.js anchors its patterns on \b — '\\bsk-[A-Za-z0-9_-]{16,}',
# '\\bghp_[A-Za-z0-9]{20,}\\b', '\\bAKIA[0-9A-Z]{16}\\b'. A WORD character
# (letter, digit, or '_') on the anchored side therefore defeats the match.
# Measured against the live table, not assumed:
#     'OPENAI_sk-<28>'  -> passes scrub UNCHANGED
#     'MYKEYsk-<28>'    -> passes scrub UNCHANGED
#     '123sk-<28>'      -> passes scrub UNCHANGED
#     'ghp_<30>_backup' -> passes scrub UNCHANGED
#     'AKIA<16>TAIL'    -> passes scrub UNCHANGED
# Punctuation-glued forms are NOT affected and are caught upstream correctly:
# '/sk-…', 'token=sk-…', 'file.sk-….bak' all redact.
#
# The watchman cannot fix the helix from here, so it masks token-shaped runs
# itself, UNANCHORED, BEFORE handing anything to the redactor — previews AND
# metadata. THE UPSTREAM GAP REMAINS OPEN and is flagged for the Grok helm: a
# word-glued credential still passes t2helix's own write-path scrub straight
# into the helix chronicle. This pre-pass protects the watchman's egress only.
TOKEN_PREFIXES = (
    "sk-",
    "sk_live_",
    "sk_test_",
    "pk_live_",
    "rk_live_",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "github_pat_",
    "gitlab_pat_",
    "glpat-",
    "xai-",
    "xoxb-",
    "xoxp-",
    "xoxa-",
    "xoxr-",
    "xoxs-",
    "AKIA",
    "ASIA",
    "AIza",
    "ya29.",
    "shpat_",
    "shpss_",
    "npm_",
    "dckr_pat_",
    "hf_",
)
TOKEN_TAIL_MIN = 16
BARE_TOKEN_MIN = 32
TOKEN_SHAPED_TOKEN = "<TOKEN-SHAPED:len=%d>"

_PREFIXED_TOKEN_RE = re.compile(
    "(?:"
    + "|".join(re.escape(p) for p in TOKEN_PREFIXES)
    + r")[A-Za-z0-9_-]{%d,}" % TOKEN_TAIL_MIN
)
# "high-entropy" here is a STATED mechanical rule, not Shannon entropy: a run of
# BARE_TOKEN_MIN+ [A-Za-z0-9] that carries at least one digit AND at least one
# letter. A long run of one repeated letter is therefore NOT masked.
_BARE_TOKEN_RE = re.compile(r"[A-Za-z0-9]{%d,}" % BARE_TOKEN_MIN)

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

    This is the FAST PATH for pure-single-script lookalike folding only. It is
    NOT the mixed-script defence — see mixed_script(), which must run on RAW
    text because fold() has already erased the evidence.
    """
    if text is None:
        return ""
    s = unicodedata.normalize("NFKC", str(text))
    return s.translate(_CONFUSABLE_TABLE).casefold()


# ---------------------------------------------------------------- mixed script

_WORD_RE = re.compile(r"\w+", re.UNICODE)


def _script_of(ch: str) -> str:
    """The Unicode script family of one character, from its NAME prefix.

    Dependency-free: 'CYRILLIC SMALL LETTER O' -> 'CYRILLIC', 'LATIN SMALL
    LETTER A' -> 'LATIN', 'CJK UNIFIED IDEOGRAPH-4E00' -> 'CJK'. Unnamed
    codepoints come back as 'UNKNOWN' (unicodedata.name RAISES without a
    default — that default is load-bearing).
    """
    name = unicodedata.name(ch, "")
    if not name:
        return "UNKNOWN"
    return name.split(" ", 1)[0]


def mixed_script(text) -> bool:
    """True when any word-token's LETTERS come from more than one script.

    THIS RUNS ON RAW TEXT. It must never be handed fold()ed input: fold()
    applies the confusables map, so a Cyrillic 'о' has already become a Latin
    'o' and the mixed-script evidence is gone. A test with a canary built from
    MAPPED confusables ('соnfig') guards that ordering — it goes red the moment
    anyone folds first.

    The map (fold) catches pure-single-script lookalikes it happens to know.
    THIS catches the actual attack shape — an ASCII word with one foreign
    codepoint spliced in — by construction, for every script, without a map.
    Non-letters (digits, '-', '_', '…') are ignored, so masking tokens and
    truncation markers never trip it.
    """
    if not text:
        return False
    for token in _WORD_RE.findall(str(text)):
        scripts = set()
        for ch in token:
            if not unicodedata.category(ch).startswith("L"):
                continue
            scripts.add(_script_of(ch))
            if len(scripts) > 1:
                return True
    return False


def any_mixed_script(value) -> bool:
    """mixed_script() over every string anywhere in a structure."""
    return any(mixed_script(s) for s in _iter_strings(value))


# ---------------------------------------------------------------- text shaping


def mask_token_shaped(text: str) -> str:
    """Mask credential-shaped runs BEFORE the redactor ever sees them.

    Two rules, both UNANCHORED so a glued credential cannot hide behind a word
    boundary the way it does on t2helix's own write path:

      1. a known prefix (TOKEN_PREFIXES) followed by TOKEN_TAIL_MIN+ characters
         of [A-Za-z0-9_-], anywhere — glued, dotted, slashed, inside a URL;
      2. a bare run of BARE_TOKEN_MIN+ [A-Za-z0-9] carrying at least one digit
         AND at least one letter.

    Both become '<TOKEN-SHAPED:len=N>'. Over-withholding is accepted: rule 2
    also eats full-length git SHAs and other long alnum identifiers, which is
    why the heartbeat surface reports SHORT commits.
    """
    if not text:
        return text

    def _prefixed(m):
        return TOKEN_SHAPED_TOKEN % len(m.group(0))

    def _bare(m):
        run = m.group(0)
        if not (any(c.isdigit() for c in run) and any(c.isalpha() for c in run)):
            return run
        return TOKEN_SHAPED_TOKEN % len(run)

    return _BARE_TOKEN_RE.sub(_bare, _PREFIXED_TOKEN_RE.sub(_prefixed, text))


def mask_base64_blobs(text: str) -> str:
    """Replace runs of BASE64_RUN_MIN+ base64-alphabet chars with a typed token.

    Both alphabets: standard ('+' '/') and URL-safe ('-' '_'), including runs
    that mix them.

    Applied to PREVIEWS ONLY, and it runs AFTER redaction, so it catches what
    the pre-pass left. A pure-alnum base64 run is claimed first by
    mask_token_shaped() and renders as '<TOKEN-SHAPED:len=N>'; a run carrying
    '+', '/', '-' or '_' survives the pre-pass (those characters split the bare
    alnum rule) and lands here as '<BASE64-BLOB:len=N>'. Two labels, one
    guarantee: neither form travels in the clear.
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

    Four gates, each earned by a plausible hand-edit that used to pass:

      1. every field is TYPE-CHECKED, never coerced — `"denylist_queues":
         "antigravity_connector"` (brackets dropped) iterated the STRING into
         single characters and silently stopped denying the antigravity queue
         while still reporting policy_state 'loaded';
      2. WRONG NESTING is rejected — a dict where a list belongs, or a list of
         non-strings;
      3. UNKNOWN KEYS are rejected, which is what catches a singular-key typo
         (`denylist_domain`): the typo'd key used to be ignored and the real
         key defaulted to empty, so the policy read as loaded and denied
         nothing. Keys beginning with '_' are comments and are allowed — the
         shipped eyes_policy.json carries a `_comment`, and a validator that
         rejected it would close the eyes on every production sweep;
      4. at least ONE recognized key must be present, and the policy must deny
         SOMETHING. A file that parses to all-empty denylists AND empty
         content_terms is not a plausible intent — an eyes policy with no eyes
         is a config that was truncated, emptied, or half-written, so it falls
         to the floor rather than being honoured.
    """
    if not isinstance(raw, dict):
        raise ValueError(f"policy root must be an object, got {type(raw).__name__}")

    unknown = [
        k
        for k in raw
        if k not in POLICY_LIST_KEYS and not (isinstance(k, str) and k.startswith("_"))
    ]
    if unknown:
        raise ValueError(f"unknown policy key(s): {sorted(map(str, unknown))}")
    if not any(k in raw for k in POLICY_LIST_KEYS):
        raise ValueError(
            "policy declares none of "
            f"{list(POLICY_LIST_KEYS)} — nothing recognized to enforce"
        )

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

    if not any(policy[key] for key in POLICY_LIST_KEYS):
        raise ValueError(
            "policy denies nothing: every denylist and content_terms is empty"
        )
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

    The watchman-side token pre-pass (mask_token_shaped) runs BEFORE the
    subprocess, so a glued credential t2helix's boundary-anchored scrub would
    miss is already a '<TOKEN-SHAPED:len=N>' by the time scrub() sees it.
    """
    if script_path is None:
        script_path = _SCRIPT_PATH
    if node_bin is None:
        node_bin = resolve_node_bin()
    if t2helix_root is None:
        t2helix_root = default_t2helix_root()
    window = mask_token_shaped(body[:SANITIZER_INPUT_WINDOW])
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
    payload = json.dumps(
        [mask_token_shaped(str(v)[:SANITIZER_INPUT_WINDOW]) for v in values]
    )
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


def _collect_string_paths(node, out):
    """EVERY string in a metadata structure — dict KEYS INCLUDED — in a fixed
    traversal order (key, then that key's value). The rebuild pass walks the
    identical order, so the two stay in lockstep without carrying paths.

    Keys used to be skipped entirely: a dict key was copied verbatim into the
    digest handed to xAI. No surface produces attacker-controlled keys TODAY
    (every metadata key in _extract_meta, scan_comms and the `detail` blocks is
    a literal), so this is defence in depth, not a live leak closed.
    """
    if isinstance(node, str):
        out.append(node)
    elif isinstance(node, dict):
        for k, v in node.items():
            if isinstance(k, str):
                out.append(k)
            _collect_string_paths(v, out)
    elif isinstance(node, (list, tuple)):
        for v in node:
            _collect_string_paths(v, out)


def _safe_string(raw: str, redacted, ok: bool):
    """(safe_value, field_ok) for one string. Fail closed, never verbatim."""
    if not ok or not isinstance(redacted, str):
        return UNSANITIZED_TOKEN, False
    if raw.strip() and not redacted.strip():
        # scrub of non-empty text is never empty — treat as a failure of THIS
        # field rather than trusting the blank.
        return UNSANITIZED_TOKEN, False
    return cap_field(redacted), True


def _rebuild_sanitized(node, feed, ok):
    """Rebuild `node` consuming redacted strings from `feed` in collect order."""
    if isinstance(node, str):
        value, _ = _safe_string(node, next(feed), ok)
        return value
    if isinstance(node, dict):
        rebuilt = {}
        dropped = 0
        for k, v in node.items():
            if isinstance(k, str):
                safe_key, key_ok = _safe_string(k, next(feed), ok)
            else:
                safe_key, key_ok = k, True
            # The value is consumed EITHER WAY: the feed must stay in lockstep
            # with the collect order even for a pair we are about to drop.
            safe_value = _rebuild_sanitized(v, feed, ok)
            if not key_ok or safe_key in rebuilt:
                # A key we could not clean cannot be named, and two distinct
                # keys that redact to the same string would silently overwrite
                # one another. Both drop the whole pair and are COUNTED.
                dropped += 1
                continue
            rebuilt[safe_key] = safe_value
        if dropped:
            rebuilt[PAIR_UNSANITIZED_TOKEN] = dropped
        return rebuilt
    if isinstance(node, (list, tuple)):
        return [_rebuild_sanitized(v, feed, ok) for v in node]
    return copy.deepcopy(node)


def sanitize_metadata(meta, **redactor_kwargs):
    """Return (sanitized_meta, ok).

    EVERY string — at any depth, KEYS AND VALUES — runs through the same
    redactor as previews, then is capped at METADATA_FIELD_CHARS with an
    explicit truncation marker. This closes the leak-hunt's headline finding:
    metadata was copied VERBATIM out of untrusted files and board messages and
    travelled to xAI in argv, in the prompt, and into the spool.

    A VALUE whose redaction could not be completed becomes UNSANITIZED_TOKEN.
    A KEY whose redaction could not be completed takes its whole pair with it
    (PAIR_UNSANITIZED_TOKEN carries the count). CONSEQUENCE, stated plainly:
    when the redactor is wholly down every key fails, so the block collapses to
    `{'<pair-unsanitized:omitted>': N}`. That is fail-closed and loud — the
    standing-blind detector escalates to urgent in the same sweep — but a
    reader must not mistake a collapsed block for an empty surface.
    """
    values = []
    _collect_string_paths(meta, values)
    if not values:
        return copy.deepcopy(meta), True
    redacted, state = run_redactor_batch(values, **redactor_kwargs)
    ok = state == "sanitized" and redacted is not None
    feed = iter(redacted if ok else [None] * len(values))
    return _rebuild_sanitized(meta, feed, ok), ok


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
    if any_mixed_script(meta):
        # MIXED SCRIPT FAILS CLOSED. Checked here, before the subprocess, so a
        # mixed-script item's body is never handed to the redactor either.
        # NOTE the precise scope: this is the CONTENT leg, so it only fires on
        # an item that would otherwise have produced a preview — a denylisted
        # or unparseable item short-circuits above and keeps its own state.
        return None, "metadata-only:content-flagged"
    redacted, state = run_redactor(body, **redactor_kwargs)
    if state != "sanitized" or redacted is None:
        return None, "metadata-only:sanitizer-failed"
    masked = mask_base64_blobs(redacted)
    if not masked.strip():
        # Nothing was actually inspected — counting this as 'previewed' would
        # inflate the coverage number with empty reads.
        return None, "metadata-only:empty-body"
    # THE CONTENT LEG READS THE RAW WINDOW AS WELL AS THE MASKED ONE, and that
    # is not belt-and-braces — the masks BLIND this gate otherwise.
    # mask_token_shaped runs inside run_redactor and mask_base64_blobs runs
    # above, both UPSTREAM of here, so a sensitive term living inside a masked
    # run is gone before the gate can see it:
    #     'domain-biomedical-assay-protocol-reference-2026'
    #        -> one 47-char base64-alphabet run -> <BASE64-BLOB:len=47>
    #     'biomedicalassay2026protocolreference00'
    #        -> one 38-char high-entropy run    -> <TOKEN-SHAPED:len=38>
    # Nothing LEAKS either way (the run is masked), but the item silently loses
    # its 'content-flagged' state — and that state is what sets
    # flagged_for_richer_review, the second net. Fail-closed on disclosure,
    # fail-OPEN on signalling, which is the exact shape this build hunts.
    # Reading the raw window is strictly tightening and can only add flags.
    raw_window = body[:SANITIZER_INPUT_WINDOW]
    if (
        content_flagged(masked, policy)
        or mixed_script(masked)
        or content_flagged(raw_window, policy)
        or mixed_script(raw_window)
    ):
        # The CONTENT leg: sensitivity that was never declared in metadata, and
        # any mixed-script token — checked before AND after masking.
        return None, "metadata-only:content-flagged"
    return truncate_with_marker(masked, PREVIEW_CHARS, len(body)), "sanitized"
