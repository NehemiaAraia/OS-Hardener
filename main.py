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

from scanner import delta as delta_mod
from scanner import remediation
from scanner.connection import make_connection
from scanner.remediation import linux as linux_remediation
from scanner.remediation import windows as win_remediation
from scanner.reporter import build_document, write_html, write_json
from scanner.scanner import run_scan
from scanner.storage import DEFAULT_DB, Store

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
    # the host identifies the target across scans, so it must not encode which
    # fixture was replayed — otherwise before/after look like two different hosts
    # and the delta never fires
    host = args.host or "fixture"
    label = f"{host} ({args.fixture})" if args.fixture else host
    print(f"[*] connecting to {target} target ({label})...")
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

    now = datetime.now(timezone.utc)
    ts = now.strftime("%Y%m%d_%H%M%S")
    # milliseconds in the filename only: two scans in the same second during a
    # before/after demo would otherwise overwrite the first report
    file_ts = f"{ts}_{now.microsecond // 1000:03d}"
    meta = {"platform": target, "host": host, "timestamp": ts, "scenario": args.fixture or ""}
    doc = build_document(results, summary, meta)
    os.makedirs(REPORTS_DIR, exist_ok=True)
    json_path = write_json(doc, f"{REPORTS_DIR}/{target}_{file_ts}.json")
    html_path = write_html(doc, f"{REPORTS_DIR}/{target}_{file_ts}.html")
    print(f"[*] report: {html_path}")
    print(f"[*] json:   {json_path}")

    with Store(args.db) as store:
        scan_id = store.save_scan(results, summary, meta)
        d = delta_mod.compute(store, scan_id, target, host)
    if d:
        _print_delta(d)
    return 0


def _print_delta(d) -> None:
    sign = "+" if d.score_change >= 0 else ""
    print(f"\n[*] compared to previous scan ({d.previous_timestamp}):")
    print(f"    score: {d.score_before}% -> {d.score_after}%  ({sign}{d.score_change})")

    if d.coverage_changed:
        print(
            f"    [!] coverage also moved {d.coverage_before}% -> {d.coverage_after}%, "
            f"so this is not a like-for-like comparison"
        )

    for c in d.changes:
        marker = "REGRESSED" if c.regressed else ""
        print(f"    {c.check_id:<16} {c.title[:38]:<38} {c.before} -> {c.after}  {marker}")
    for c in d.unchanged_failures:
        print(f"    {c.check_id:<16} {c.title[:38]:<38} {c.before} -> {c.after}  (unchanged)")


def _remediation_credentials(target: str):
    """Remediation deliberately uses a different identity than scanning. The
    scanner account is read-only by design, so if it could apply these fixes the
    least-privilege claim would be theatre."""
    if target == "windows":
        user = os.environ.get("WINRM_ADMIN_USER")
        secret = os.environ.get("WINRM_ADMIN_PASS")
        names = "WINRM_ADMIN_USER and WINRM_ADMIN_PASS"
    else:
        user = os.environ.get("REMEDIATE_SSH_USER")
        secret = os.environ.get("REMEDIATE_SSH_KEY")
        names = "REMEDIATE_SSH_USER and REMEDIATE_SSH_KEY"
    if not user or not secret:
        sys.exit(
            f"set {names} for remediation — the read-only scanner account cannot "
            f"apply changes, which is intentional"
        )
    return user, secret


def cmd_remediate(args) -> int:
    target, host = args.target, args.host
    apply = args.apply
    if not apply and not args.dry_run:
        print("[*] no mode given, defaulting to --dry-run")

    # remediate only what a scan just found failing, rather than blanket-applying
    print(f"[*] scanning {target} target to find failing controls...")
    conn = _open_connection(target, args)
    try:
        results, summary = run_scan(target, conn, RULES_DIR)
        catalog = win_remediation.CATALOG if target == "windows" else linux_remediation.CATALOG
        plan = remediation.build_plan(results, catalog, target, host or "fixture")

        if not plan.actionable and not plan.skipped:
            print("[*] nothing to remediate — no failing controls have a defined fix")
            return 0

        if apply:
            _remediation_credentials(target)
            if not remediation.confirm(plan.host, len(plan.fixes)):
                print("[*] aborted, no changes made")
                return 1
        else:
            print("[*] dry-run mode, no changes will be made")

        if target == "linux":
            outcomes = _remediate_linux(plan, args, apply)
        else:
            runner = win_remediation.make_runner(conn)
            outcomes = remediation.execute(plan, runner, apply)
    finally:
        conn.close()

    return _report_outcomes(outcomes, apply)


def _remediate_linux(plan, args, apply):
    """Linux runs one ansible-playbook invocation for the whole plan; --dry-run
    maps to Ansible's own --check rather than a Python imitation of it."""
    tags = [f.check_id for f in plan.fixes]
    outcomes = [
        remediation.FixOutcome(f, "SKIP", f.reason_no_fix) for f in plan.skipped
    ]
    if not tags:
        return outcomes

    user, key = (
        _remediation_credentials("linux") if apply else ("<unset>", "<unset>")
    )
    if not apply:
        print(f"[*] would run: ansible-playbook {linux_remediation.PLAYBOOK} --check "
              f"--tags {','.join(sorted(tags))}")
        return outcomes + [remediation.FixOutcome(f, "DRY-RUN", f.command or "") for f in plan.fixes]

    print(f"[*] invoking ansible-playbook ({linux_remediation.PLAYBOOK})...\n")
    ok, detail = linux_remediation.run_playbook(plan.host, user, key, tags, check=False)
    action = "APPLY" if ok else "FAIL"
    return outcomes + [remediation.FixOutcome(f, action, detail if not ok else "done") for f in plan.fixes]


def _report_outcomes(outcomes, apply) -> int:
    reboot = False
    applied = failed = 0
    for o in outcomes:
        if o.action == "SKIP":
            print(f"[SKIP]    {o.fix.check_id:<14} {o.fix.title} — {o.detail}")
        elif o.action == "DRY-RUN":
            print(f"[DRY-RUN] {o.fix.check_id:<14} {o.fix.title}")
            print(f"    would run: {o.detail}")
        elif o.action == "APPLY":
            print(f"[APPLY]   {o.fix.check_id:<14} {o.fix.title} .......... {o.detail}")
            applied += 1
            reboot = reboot or o.fix.requires_reboot
        else:
            print(f"[FAIL]    {o.fix.check_id:<14} {o.fix.title} — {o.detail}")
            failed += 1

    if apply:
        print(f"\n[*] {applied} control(s) remediated, {failed} failed.")
        if reboot:
            print("[*] reboot flagged, not forced.")
        print("[*] re-run 'scan' to verify the fixes and see the delta.")
    else:
        print("\n[*] dry-run complete, nothing was changed.")
    # a failed fix is a non-zero exit: the caller should not treat this as success
    return 1 if failed else 0


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
    s.add_argument("--db", default=DEFAULT_DB, help="scan history database")
    s.set_defaults(func=cmd_scan)

    r = sub.add_parser("remediate", help="remediate controls a scan found failing")
    r.add_argument("--target", required=True, choices=["windows", "linux"])
    r.add_argument("--host")
    r.add_argument("--fixture", help="dev/CI only: replay a recorded fixture scenario")
    r.add_argument("--insecure", action="store_true", help=argparse.SUPPRESS)
    g = r.add_mutually_exclusive_group()
    g.add_argument("--dry-run", action="store_true", help="show what would change (default)")
    g.add_argument("--apply", action="store_true", help="make live changes, after confirmation")
    r.set_defaults(func=cmd_remediate)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
