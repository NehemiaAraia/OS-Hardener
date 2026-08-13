"""Orchestrate the pipeline: parser -> executor/evaluator -> scoring -> reporter."""
from __future__ import annotations

from pathlib import Path

from .evaluator import evaluate
from .model import CheckResult
from .parser import load_policies
from .scoring import summarize


def run_scan(platform: str, conn, rules_dir: str | Path = "rules") -> tuple[list[CheckResult], dict]:
    policies = load_policies(rules_dir, platform)
    results: list[CheckResult] = []
    for pol in policies:
        for check in pol.checks:
            results.append(evaluate(check, platform, conn))
    summary = summarize(results)
    return results, summary
