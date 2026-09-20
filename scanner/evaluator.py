"""Resolve each check to PASS/FAIL/WARN.

Anything that could not be verified resolves to WARN, never PASS.
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

    # failed with no output usually means unreadable, not non-compliant
    if not ran_clean and not text:
        return None

    # nothing to match against means nothing was observed
    if kind in ("equals", "eq", "regex", "match", "notregex") and not text:
        return None

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
            actual, allowed = int(text, 8), int(arg, 8)
        except ValueError:
            return None
        # compare bits, not magnitude: 0007 is not "less" than 0640
        return actual & ~allowed == 0
    if kind in ("maxint", "minint"):
        if not (ran_clean and text):
            return None
        try:
            value = int(text.splitlines()[0].strip())
        except ValueError:
            return None  # unparseable -> unknown, never a pass
        return value <= int(arg) if kind == "maxint" else value >= int(arg)
    if kind in ("running", "active", "stopped", "inactive", "disabled"):
        # systemctl exits non-zero when inactive, so trust the state word
        want_running = kind in ("running", "active")
        state = text.lower()
        if state:
            if state in ("running", "active"):
                return want_running
            if state in ("stopped", "inactive", "failed", "dead", "unknown", "not-found"):
                return not want_running
            return None  # unrecognized state word -> unknown, never a pass
        # empty output only means "absent" if the probe itself succeeded
        return (not want_running) if ran_clean else None
    if kind == "exists":
        return ran_clean and bool(text)
    if kind == "absent":
        return ran_clean and not text
    # unrecognized matcher -> unknown, never a pass
    return None


def _evaluate_subrule(sub: SubRule, platform: str, conn) -> Evidence:
    try:
        out = collect(sub, platform, conn)
    except ValueError as e:
        # an unsupported rule is unknown, and must not kill the scan
        return Evidence(subrule=sub.raw, output=f"<unsupported: {e}>", satisfied=None)
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
        # evidence still collected so a reviewer has something to look at
        return CheckResult(check, Status.WARN, "manual review required", evidence)
    if not check.rules:
        # nothing was actually verified, so this cannot be a pass
        return CheckResult(check, Status.WARN, "no sub-rules defined, nothing verified", [])
    status = _resolve(check.condition, evidence)
    if status is Status.WARN and any(e.output == "<unreachable>" for e in evidence):
        msg = "host unreachable or evidence unavailable, not passed by default"
    elif status is Status.WARN:
        msg = "could not be verified cleanly, flagged for review"
    elif status is Status.FAIL:
        msg = "control not satisfied"
    else:
        msg = "control satisfied"
    return CheckResult(check, status, msg, evidence)
