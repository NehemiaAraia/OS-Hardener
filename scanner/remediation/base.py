"""Remediation model. Dry-run is the default; applying needs --apply plus an
interactive confirmation."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from ..model import CheckResult, Status

ACTION_LOG = "reports/remediation.log"


@dataclass
class Fix:
    check_id: str
    title: str
    command: Optional[str]          # None means no safe automated fix exists
    requires_reboot: bool = False
    reason_no_fix: str = ""


@dataclass
class FixOutcome:
    fix: Fix
    action: str                     # DRY-RUN | APPLY | SKIP | FAIL
    detail: str = ""


@dataclass
class RemediationPlan:
    """Fixes for the controls a scan found failing, not a blanket apply."""
    target: str
    host: str
    fixes: list[Fix] = field(default_factory=list)
    skipped: list[Fix] = field(default_factory=list)
    # failing controls with no catalog entry, reported rather than dropped
    no_fix_defined: list[tuple[str, str]] = field(default_factory=list)

    @property
    def actionable(self) -> bool:
        return bool(self.fixes)


def build_plan(
    results: list[CheckResult], catalog: dict[str, Fix], target: str, host: str
) -> RemediationPlan:
    """Only FAILs are remediated; a WARN was never verified."""
    plan = RemediationPlan(target=target, host=host)
    for r in results:
        if r.status is not Status.FAIL:
            continue
        if r.waived:
            continue  # accepted risk; fixing it would overrule that
        fix = catalog.get(r.check.id)
        if fix is None:
            plan.no_fix_defined.append((r.check.id, r.check.title))
            continue
        (plan.fixes if fix.command else plan.skipped).append(fix)
    return plan


def _logger(log_path: str | Path) -> logging.Logger:
    # keyed by path so a second run doesn't log to the first run's file
    path = Path(log_path)
    log = logging.getLogger(f"remediation.{path}")
    if not log.handlers:
        path.parent.mkdir(parents=True, exist_ok=True)
        handler = logging.FileHandler(path)
        handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
        log.addHandler(handler)
        log.setLevel(logging.INFO)
        log.propagate = False
    return log


def confirm(host: str, count: int, stream=None) -> bool:
    """Anything but 'y' declines; non-interactive sessions decline."""
    import sys

    opened = None
    if stream is None:
        # read from the terminal: a pasted newline in stdin would answer this
        try:
            opened = open("/dev/tty")
            stream = opened
        except OSError:
            stream = sys.stdin

    try:
        if not stream.isatty():
            print("[!] refusing to apply changes from a non-interactive session", file=sys.stderr)
            return False
        print(
            f"[!] this will make live changes to {host} ({count} control(s)). continue? [y/N]: ",
            end="",
            flush=True,
        )
        return stream.readline().strip().lower() == "y"
    finally:
        if opened:
            opened.close()


def execute(
    plan: RemediationPlan,
    runner: Callable[[Fix], tuple[bool, str]],
    apply: bool,
    log_path: str | Path = ACTION_LOG,
) -> list[FixOutcome]:
    """Walk the plan; runner is only called when apply is True."""
    log = _logger(log_path)
    started = datetime.now(timezone.utc).isoformat()
    mode = "APPLY" if apply else "DRY-RUN"
    log.info(f"--- {mode} {plan.target} {plan.host} started {started} ---")

    outcomes: list[FixOutcome] = []
    for fix in plan.skipped:
        outcomes.append(FixOutcome(fix, "SKIP", fix.reason_no_fix))
        log.info(f"SKIP {fix.check_id} {fix.reason_no_fix}")

    for fix in plan.fixes:
        if not apply:
            outcomes.append(FixOutcome(fix, "DRY-RUN", fix.command or ""))
            log.info(f"DRY-RUN {fix.check_id} would run: {fix.command}")
            continue
        ok, detail = runner(fix)
        outcomes.append(FixOutcome(fix, "APPLY" if ok else "FAIL", detail))
        log.info(f"{'APPLY' if ok else 'FAIL'} {fix.check_id} {detail}")

    return outcomes
