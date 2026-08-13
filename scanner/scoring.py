"""Aggregate check results into counts and a compliance score.

Score counts only scored controls that resolved to a definite PASS/FAIL. WARNs
are excluded from the denominator (they're unverified, not failures) but reported
separately so they never quietly inflate the number."""
from __future__ import annotations

from .model import CheckResult, Status


def summarize(results: list[CheckResult]) -> dict:
    counts = {"PASS": 0, "FAIL": 0, "WARN": 0}
    for r in results:
        counts[r.status.value] += 1

    scored = [
        r for r in results
        if r.check.scored == "scored" and r.status in (Status.PASS, Status.FAIL)
    ]
    denom = len(scored)
    passed = sum(1 for r in scored if r.status is Status.PASS)
    score = round(100 * passed / denom) if denom else 0

    return {
        "total": len(results),
        "pass": counts["PASS"],
        "fail": counts["FAIL"],
        "warn": counts["WARN"],
        "scored_total": denom,
        "scored_pass": passed,
        "score": score,
    }
