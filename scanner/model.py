"""Core data types shared across the pipeline."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Status(str, Enum):
    # a compliance status, not a credential
    PASS = "PASS"  # nosec B105  # noqa: S105
    FAIL = "FAIL"
    WARN = "WARN"


# recognized sub-rule prefixes -> collection kind
SUBRULE_TYPES = {"r", "f", "cmd", "svc", "perm"}


@dataclass
class SubRule:
    type: str          # r | f | cmd | svc | perm
    target: str        # registry path, file path, command, service, or file path
    name: Optional[str]  # registry value name (only for type == 'r')
    matcher: str       # e.g. "equals:0", "regex:^PermitRootLogin no", "maxmode:0640"
    raw: str


@dataclass
class Check:
    id: str
    title: str
    level: str                 # level1 | level2
    scored: str                # scored | notscored
    nist: str                  # e.g. NIST800-53R5_IA-5_1_d
    scope: str                 # memberserver (Windows) etc.
    severity: str              # critical | high | medium | low | info
    condition: str             # all | any | none
    rules: list[SubRule]
    description: str = ""
    remediation: str = ""
    manual: bool = False       # controls that can't be cleanly auto-verified -> always WARN
    references: list[str] = field(default_factory=list)


@dataclass
class Policy:
    id: str
    name: str
    platform: str              # windows | linux
    checks: list[Check]


@dataclass
class Evidence:
    subrule: str
    output: str
    satisfied: Optional[bool]  # True / False / None (unknown)


@dataclass
class CheckResult:
    check: Check
    status: Status
    message: str
    evidence: list[Evidence] = field(default_factory=list)
    waiver: Optional["object"] = None  # scanner.waivers.Waiver when risk-accepted

    @property
    def waived(self) -> bool:
        return self.waiver is not None

    def to_dict(self) -> dict:
        c = self.check
        w = self.waiver
        return {
            "id": c.id,
            "title": c.title,
            "status": self.status.value,
            "waived": self.waived,
            "waiver": (
                {
                    "reason": w.reason,
                    "owner": w.owner,
                    "ticket": w.ticket,
                    "expires": w.expires.isoformat(),
                }
                if w
                else None
            ),
            "severity": c.severity,
            "level": c.level,
            "scored": c.scored,
            "nist": c.nist,
            "scope": c.scope,
            "message": self.message,
            "remediation": c.remediation,
            "evidence": [
                {"rule": e.subrule, "satisfied": e.satisfied, "output": e.output}
                for e in self.evidence
            ],
        }
