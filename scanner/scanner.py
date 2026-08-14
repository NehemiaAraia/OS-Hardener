"""Orchestrate the pipeline: parser -> executor/evaluator -> scoring -> reporter."""
from __future__ import annotations

from datetime import date, timezone
from pathlib import Path

from . import waivers as waivers_mod
from .evaluator import evaluate
from .model import CheckResult, Status
from .parser import load_policies
from .scoring import summarize


def apply_waivers(results, waiver_list, host, today):
    """Attach risk acceptances to failing controls, and report anything the
    waiver file says that no longer lines up with reality."""
    notes = []
    known = {r.check.id for r in results}

    for r in results:
        if r.status is Status.FAIL:
            w = waivers_mod.find(waiver_list, r.check.id, host, today)
            if w:
                r.waiver = w
                continue
            expired = waivers_mod.expired_for(waiver_list, r.check.id, host, today)
            if expired:
                notes.append(
                    f"{r.check.id}: waiver expired {expired.expires.isoformat()} "
                    f"({expired.owner}) — counting as a finding again"
                )
        elif r.status is Status.WARN:
            # accepting a risk you never measured is not risk acceptance
            if waivers_mod.find(waiver_list, r.check.id, host, today):
                notes.append(
                    f"{r.check.id}: waived, but the control is WARN (unverified) — "
                    f"the waiver does not apply"
                )

    for w in waiver_list:
        if w.check_id not in known:
            notes.append(f"{w.check_id}: waiver refers to a control that no longer exists")

    return notes


def run_scan(
    platform: str,
    conn,
    rules_dir: str | Path = "rules",
    waiver_list=None,
    host: str = "",
    today: date | None = None,
) -> tuple[list[CheckResult], dict, list[str]]:
    policies = load_policies(rules_dir, platform)
    results: list[CheckResult] = []
    for pol in policies:
        for check in pol.checks:
            results.append(evaluate(check, platform, conn))

    notes = []
    if waiver_list:
        from datetime import datetime

        today = today or datetime.now(timezone.utc).date()
        notes = apply_waivers(results, waiver_list, host, today)

    summary = summarize(results)
    return results, summary, notes
