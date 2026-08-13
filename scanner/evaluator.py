"""Apply matchers to collected output and resolve each check to PASS/FAIL/WARN.

The load-bearing rule: an unreachable host, an unrecognized matcher, or a probe
that could not run resolves to WARN (unknown) — never PASS. Silently passing an
unverified control is the single worst failure mode for a compliance tool.
"""
from __future__ import annotations

from typing import Optional

from .connection.base import CommandOutput
from .executor import collect
from .model import Check, CheckResult, Evidence, Status, SubRule


def _match(matcher: str, out: CommandOutput) -> Optional[bool]:
    """Return True/False if the matcher can be decided, or None if unknown.
    None propagates to WARN. out.ok is False only when the command could not
    run at all (unreachable) -> always unknown."""
    import re

    if not out.ok:
        return None

    kind, _, arg = matcher.partition(":")
    kind = kind.strip()
    arg = arg.strip()
    text = out.stdout.strip()
    ran_clean = out.exit_status == 0

    if kind in ("equals", "eq"):
        return ran_clean and text == arg
    if kind in ("regex", "match"):
        return ran_clean and re.search(arg, text, re.MULTILINE) is not None
    if kind == "notregex":
        if not ran_clean:
            return False
        return re.search(arg, text, re.MULTILINE) is None
    if kind == "maxmode":
        if not (ran_clean and text):
            return None
        try:
            return int(text, 8) <= int(arg, 8)
        except ValueError:
            return None
    if kind in ("maxint", "minint"):
        if not (ran_clean and text):
            return None
        try:
            value = int(text.splitlines()[0].strip())
        except ValueError:
            return None  # unparseable -> unknown, never a pass
        return value <= int(arg) if kind == "maxint" else value >= int(arg)
    if kind in ("running", "active"):
        return ran_clean and text.lower() in ("running", "active")
    if kind in ("stopped", "inactive", "disabled"):
        # empty output means the service isn't installed at all, which satisfies
        # a 'should not be running' control
        return text.lower() in ("", "stopped", "inactive", "disabled", "unknown")
    if kind == "exists":
        return ran_clean and bool(text)
    if kind == "absent":
        return ran_clean and not text
    # unrecognized matcher -> unknown, never a pass
    return None


def _evaluate_subrule(sub: SubRule, platform: str, conn) -> Evidence:
    out = collect(sub, platform, conn)
    satisfied = _match(sub.matcher, out)
    snippet = out.stdout.strip()
    if not out.ok:
        snippet = "<unreachable>"
    return Evidence(subrule=sub.raw, output=snippet[:400], satisfied=satisfied)


def _resolve(condition: str, evidence: list[Evidence]) -> Status:
    flags = [e.satisfied for e in evidence]
    matched = sum(1 for f in flags if f is True)
    unmatched = sum(1 for f in flags if f is False)
    unknown = sum(1 for f in flags if f is None)

    if condition == "all":
        if unmatched:
            return Status.FAIL
        if unknown:
            return Status.WARN
        return Status.PASS
    if condition == "any":
        if matched:
            return Status.PASS
        if unknown:
            return Status.WARN
        return Status.FAIL
    if condition == "none":
        if matched:
            return Status.FAIL
        if unknown:
            return Status.WARN
        return Status.PASS
    # unknown condition keyword -> fail safe
    return Status.WARN


def evaluate(check: Check, platform: str, conn) -> CheckResult:
    evidence = [_evaluate_subrule(s, platform, conn) for s in check.rules]
    if check.manual:
        # evidence is still collected — the point of a manual control is to put
        # the list in front of a human, not to hide it behind a WARN
        return CheckResult(check, Status.WARN, "manual review required", evidence)
    status = _resolve(check.condition, evidence)
    if status is Status.WARN and any(e.output == "<unreachable>" for e in evidence):
        msg = "host unreachable or evidence unavailable — not passed by default"
    elif status is Status.WARN:
        msg = "could not be verified cleanly — flagged for review"
    elif status is Status.FAIL:
        msg = "control not satisfied"
    else:
        msg = "control satisfied"
    return CheckResult(check, status, msg, evidence)
