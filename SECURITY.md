# Security Policy

## Reporting a Vulnerability

Email **templetwo@proton.me** with a description of the issue, steps to reproduce,
affected version(s) or commit, and any relevant log output or proof-of-concept code.

Please do not file a public GitHub issue before a fix has been coordinated.
Public disclosure before a patch is available puts all users at risk. Encrypted
email is welcome; request a public key at the same address.

We follow coordinated disclosure. Reporters are credited in release notes unless
they prefer anonymity.

## Supported Versions

Security patches land on `main` and in the latest tagged release (`v1.11.x` at the
time of writing). Older tags receive no patches — upgrade before reporting.

This repo does not carry its own semantic version at runtime: the bridge's
heartbeat derives its `version` live from the companion
[sovereign-stack](https://github.com/templetwo/sovereign-stack) checkout it is
serving, and reports its own git HEAD separately as `bridge_commit`. **When you
report an issue, cite `bridge_commit` (or a commit sha), not the heartbeat's
`version` field** — the latter describes the stack, not this code.

## Scope

**In scope** — vulnerabilities in:

- `bridge.py` — every REST route, the auth check, the rate limiter, request
  validation, the idempotency cache, and the CORS/static-file configuration
- `session_tokens.py` — the scoped-token store, the scope map, and any path by
  which a scoped token reaches a capability its scope does not grant
- `arrival_gate.py` / `approval_gate.py` — the consent-gated arrival flow: signed
  decide URLs and their HMAC, the approve→consume transition, replay of a poll or
  a decide link, and the pending-request caps
- `stack_tokens.py` — the mint/revoke/list CLI
- `watchman/sanitizer.py`, `watchman/spool_writer.py`, `watchman/eyes_policy.json`
  — redaction and content-leak boundaries on anything the watchman ships outward
- `bridge_config.py` — credential loading
- `dashboard/index.html` — XSS or credential-handling flaws in the served page

**Out of scope** — issues in:

- The [sovereign-stack](https://github.com/templetwo/sovereign-stack) package
  itself, including its tools, chronicle, and governance circuits — report those
  under that repo's own security policy
- User-managed infrastructure: Cloudflare Tunnel configuration, reverse proxies,
  launchd plist deployment, and similar operational concerns
- The operator's own secret management — file modes on
  `~/.config/sovereign-bridge.env`, where bearer tokens are pasted, and the like
- ntfy.sh itself, or the delivery reliability of push notifications
- Third-party dependencies, unless this repo's usage is what makes them
  exploitable — report those upstream
- Vulnerabilities in Claude Desktop, Claude Code, or any Anthropic product

If you are unsure whether something is in scope, report it anyway and we will triage it.

## Response Timeline

| Stage                            | Target                     |
|----------------------------------|----------------------------|
| Initial acknowledgment           | Within 72 hours of receipt |
| Triage and severity assessment   | Within 5 business days     |
| Status update or coordinated fix | Within 14 days (confirmed) |
| CVE assignment                   | For CVSS >= 7.0 severity   |

These are targets, not guarantees. This is a single-maintainer project; complex
issues may require more time, and delays will be communicated. If you receive no
acknowledgment within 72 hours, follow up at the same address.

## Known Boundaries

The following are by design, and are noted here so they are not reported as
vulnerabilities — and so operators know what they are accepting.

**The bridge binds to localhost only.** `bridge.py` runs on `127.0.0.1:8100`.
Every deployment that reaches it from outside the machine does so through an
operator-supplied tunnel or reverse proxy. Exposing the port on a public
interface without one is an operator error, not a defect here.

**Two credentials, deliberately unequal.** The master token (`BRIDGE_TOKEN`, read
from `~/.config/sovereign-bridge.env`) is full access; mode `600` on that file is
strongly recommended, and it is never logged. Scoped session tokens (`svs_`
prefix) are least-privilege and revocable: at no scope may one mint or revoke
tokens, set policy, or reach the protected drawer. Session tokens are stored as
sha256 only — plaintext exists in exactly one poll response and nowhere else,
which also means **a lost session token cannot be recovered, only revoked and
reminted.**

**The arrival gate fails closed.** With `ARRIVAL_DECIDE_SECRET` unset, every
`/api/arrival/*` route returns 404 rather than running unauthenticated. This is
intended: a missing signing key must disable the door, not open it.

**`PUBLIC_BASE_URL` is security-relevant configuration.** It is the origin signed
into the approve/deny links pushed to a phone. It defaults to the maintainer's own
host, so any other deployment must set it — left at the default, approval links
point at a host the operator does not control.

**`/api/arrival/request` is unauthenticated by design.** That is the whole point
of the door: a tokenless seat must be able to knock. It is bounded by a global
pending cap and a per-IP hourly cap rather than by auth. Report a way to *bypass*
those caps; the absence of auth on that route is not itself the bug.

**CORS is `allow_origins=["*"]`.** The bridge is meant to be called from arbitrary
web seats, and it authenticates with an `Authorization` header rather than
cookies, so a hostile page cannot ride an ambient session. A hostile page in an
operator's browser can still reach unauthenticated routes on localhost; the caps
above are what bound that.

**The dashboard takes its token from the query string.** `dashboard/index.html`
reads `?token=`, which means the token can land in browser history and in any
intermediary's logs. Use a short-TTL scoped session token for the dashboard, never
the master token, and treat the URL itself as a credential.

**Local data is plaintext.** Session-token metadata, arrival requests, and the
watchman spool live under `~/.sovereign/` unencrypted. Ensure the directory is not
world-readable (`chmod 700 ~/.sovereign`).
