#!/usr/bin/env python3
"""HQ CLI for scoped session tokens (The Door That Asks, Phase 1).

Thin wrapper over the bridge admin endpoints so the mint's chronicle receipt
is written server-side (spec §9) and there is exactly one code path.

Usage:
  python3 stack_tokens.py mint --ttl 12 --scope read,write --label "claude.ai fable seat" [--source claude-fable-5]
  python3 stack_tokens.py revoke --token-id a1b2c3d4e5f6
  python3 stack_tokens.py revoke --all
  python3 stack_tokens.py list [--include-dead]

Reads the master token from ~/.config/sovereign-bridge.env (BRIDGE_TOKEN=...).
The minted plaintext token prints to stdout ONCE. It is never stored.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request

BRIDGE_URL = os.environ.get("BRIDGE_URL", "http://127.0.0.1:8100")
ENV_FILE = os.path.expanduser("~/.config/sovereign-bridge.env")


def _token() -> str:
    tok = os.environ.get("BRIDGE_TOKEN")
    if not tok and os.path.exists(ENV_FILE):
        for line in open(ENV_FILE):
            if line.strip().startswith("BRIDGE_TOKEN="):
                tok = line.strip().split("=", 1)[1].strip().strip('"')
                break
    if not tok:
        sys.exit("No BRIDGE_TOKEN in env or ~/.config/sovereign-bridge.env")
    return tok


def _call(method: str, path: str, body: dict | None = None) -> dict:
    req = urllib.request.Request(
        BRIDGE_URL + path,
        method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={
            "Authorization": f"Bearer {_token()}",
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read())


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    m = sub.add_parser("mint")
    m.add_argument("--ttl", type=int, default=12)
    m.add_argument("--scope", default="read")
    m.add_argument("--label", default=None)
    m.add_argument("--source", default=None)

    r = sub.add_parser("revoke")
    r.add_argument("--token-id", default=None)
    r.add_argument("--all", action="store_true")

    ls = sub.add_parser("list")
    ls.add_argument("--include-dead", action="store_true")

    args = p.parse_args()

    if args.cmd == "mint":
        out = _call(
            "POST",
            "/api/admin/tokens/mint",
            {
                "scope": [s.strip() for s in args.scope.split(",") if s.strip()],
                "ttl_hours": args.ttl,
                "label": args.label,
                "source_instance": args.source,
            },
        )
        print(f"token_id:  {out['token_id']}")
        print(f"scope:     {'+'.join(out['scope'])}")
        print(f"expires:   {out['expires_at']}")
        print(f"chronicle: {out['chronicle_receipt']}")
        print()
        print(out["session_token"])  # plaintext, once, last line for easy copy
    elif args.cmd == "revoke":
        out = _call(
            "POST",
            "/api/admin/tokens/revoke",
            {"token_id": args.token_id, "all": args.all},
        )
        print(f"revoked: {out['revoked']}")
    elif args.cmd == "list":
        out = _call("GET", f"/api/admin/tokens?include_dead={str(args.include_dead).lower()}")
        for t in out["tokens"]:
            print(
                f"{t['token_id']}  {t['status']:8}  {'+'.join(t['scope']):14}  "
                f"exp {t['expires_at']}  used {t['use_count']}  {t.get('label') or ''}"
            )
        print(f"({out['count']} shown)")


if __name__ == "__main__":
    main()
