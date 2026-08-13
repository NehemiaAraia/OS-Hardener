#!/usr/bin/env python3
"""One CLI, two commands, both platforms:

    python main.py scan     --target windows|linux --host <ip> [--fixture <scenario>]
    python main.py remediate --target windows|linux --host <ip> --dry-run|--apply

Platform only changes which rules load and which connection backend is used;
the scan/score/report path is identical for Windows and Linux.
"""
from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone

from scanner.connection import make_connection
from scanner.reporter import build_document, write_html, write_json
from scanner.scanner import run_scan

RULES_DIR = os.environ.get("HARDENING_RULES_DIR", "rules")
REPORTS_DIR = os.environ.get("HARDENING_REPORTS_DIR", "reports")

_STATUS_COLOR = {"PASS": "\033[32m", "FAIL": "\033[31m", "WARN": "\033[33m"}
_RESET = "\033[0m"


def _open_connection(target: str, args):
    """Build a connection backend. Credentials come from env vars, never flags."""
    if args.fixture:
        return make_connection("fixture", scenario=args.fixture)
    if not args.host:
        sys.exit("--host is required for a live scan (or use --fixture for offline dev)")
    if target == "windows":
        user = os.environ.get("WINRM_USER")
        password = os.environ.get("WINRM_PASS")
        if not user or not password:
            sys.exit("set WINRM_USER and WINRM_PASS (env vars) for a live Windows scan")
        return make_connection(
            "winrm",
            host=args.host,
            username=user,
            password=password,
            insecure=args.insecure,
        )
    user = os.environ.get("SSH_USER")
    key = os.environ.get("SSH_KEY")
    if not user or not key:
        sys.exit("set SSH_USER and SSH_KEY (env vars) for a live Linux scan")
    return make_connection("ssh", host=args.host, username=user, key_filename=key)


def cmd_scan(args) -> int:
    target = args.target
    host = args.host or ("fixture:" + args.fixture if args.fixture else "unknown")
    print(f"[*] connecting to {target} target ({host})...")
    conn = _open_connection(target, args)
    try:
        results, summary = run_scan(target, conn, RULES_DIR)
    finally:
        conn.close()

    total = len(results)
    print(f"[*] loaded {total} rules from {RULES_DIR}/{target}/\n")
    for i, r in enumerate(results, 1):
        color = _STATUS_COLOR.get(r.status.value, "")
        dots = "." * max(3, 52 - len(r.check.title))
        note = ""
        if r.status.value == "FAIL":
            note = f"  ({r.check.severity})"
        elif r.status.value == "WARN":
            note = "  (manual review)" if r.check.manual else "  (review)"
        print(f"[{i}/{total}]  {r.check.id:<16} {r.check.title} {dots} {color}{r.status.value}{_RESET}{note}")

    print(
        f"\n[*] scan complete: {summary['pass']} PASS / {summary['fail']} FAIL / "
        f"{summary['warn']} WARN — compliance score: {summary['score']}% "
        f"(verified {summary['scored_total']}/{summary['scored_defined']} scored controls)"
    )
    if summary["coverage"] < 100:
        print(
            f"[!] coverage {summary['coverage']}% — "
            f"{summary['scored_defined'] - summary['scored_total']} scored control(s) "
            f"could not be verified; the score above is computed only from those that were"
        )

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    meta = {"platform": target, "host": host, "timestamp": ts}
    doc = build_document(results, summary, meta)
    os.makedirs(REPORTS_DIR, exist_ok=True)
    json_path = write_json(doc, f"{REPORTS_DIR}/{target}_{ts}.json")
    html_path = write_html(doc, f"{REPORTS_DIR}/{target}_{ts}.html")
    print(f"[*] report: {html_path}")
    print(f"[*] json:   {json_path}")
    return 0


def cmd_remediate(args) -> int:
    # exits non-zero on purpose: reporting success for work that didn't happen is
    # the same class of lie as passing a control that wasn't verified
    print("[!] remediation is not implemented yet (Tier 2).", file=sys.stderr)
    print("    planned: Python backend for Windows, Ansible playbook for Linux.", file=sys.stderr)
    return 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="main.py", description="CIS/NIST hardening scanner & remediator")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="scan a host against its rule set")
    s.add_argument("--target", required=True, choices=["windows", "linux"])
    s.add_argument("--host", help="host/IP for a live scan")
    s.add_argument("--fixture", help="dev/CI only: replay a recorded fixture scenario instead of a live host")
    s.add_argument(
        "--insecure",
        action="store_true",
        help="skip TLS certificate validation (lab self-signed certs only)",
    )
    s.set_defaults(func=cmd_scan)

    r = sub.add_parser("remediate", help="remediate failed controls (Tier 2)")
    r.add_argument("--target", required=True, choices=["windows", "linux"])
    r.add_argument("--host")
    g = r.add_mutually_exclusive_group()
    g.add_argument("--dry-run", action="store_true")
    g.add_argument("--apply", action="store_true")
    r.set_defaults(func=cmd_remediate)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
