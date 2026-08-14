"""Load YAML rule files (Wazuh SCA-style: policy / requirements / checks) into
Policy objects, and parse the typed sub-rule grammar."""
from __future__ import annotations

from pathlib import Path

import yaml

from .model import SUBRULE_TYPES, Check, Policy, SubRule


def parse_subrule(raw: str) -> SubRule:
    """Grammar: '<type>:<target>[ -> <name>] -> <matcher>'.
    Registry rules ('r:') carry a value name, so they have three ' -> ' segments;
    every other type has two."""
    if ":" not in raw:
        raise ValueError(f"sub-rule missing type prefix: {raw!r}")
    prefix, rest = raw.split(":", 1)
    prefix = prefix.strip()
    if prefix not in SUBRULE_TYPES:
        raise ValueError(f"unknown sub-rule type {prefix!r} in {raw!r}")
    parts = [p.strip() for p in rest.split("->")]
    name = None
    if prefix == "r":
        if len(parts) != 3:
            raise ValueError(f"registry rule needs 'path -> name -> matcher': {raw!r}")
        target, name, matcher = parts
    else:
        if len(parts) != 2:
            raise ValueError(f"rule needs 'target -> matcher': {raw!r}")
        target, matcher = parts
    return SubRule(type=prefix, target=target, name=name, matcher=matcher, raw=raw)


def _parse_check(d: dict) -> Check:
    rules = [parse_subrule(r) for r in d.get("rules", [])]
    return Check(
        id=d["id"],
        title=d["title"],
        level=d.get("level", "level1"),
        scored=d.get("scored", "scored"),
        nist=d.get("nist", ""),
        scope=d.get("scope", ""),
        severity=d.get("severity", "medium"),
        condition=d.get("condition", "all"),
        rules=rules,
        description=d.get("description", ""),
        remediation=d.get("remediation", ""),
        manual=bool(d.get("manual", False)),
        references=d.get("references", []) or [],
    )


def load_policy_file(path: str | Path) -> Policy:
    data = yaml.safe_load(Path(path).read_text())
    pol = data["policy"]
    checks = [_parse_check(c) for c in data.get("checks", [])]
    return Policy(id=pol["id"], name=pol["name"], platform=pol["platform"], checks=checks)


def load_policies(rules_dir: str | Path, platform: str) -> list[Policy]:
    """Load every *.yml under rules/<platform>/, sorted for stable ordering."""
    base = Path(rules_dir) / platform
    if not base.exists():
        raise FileNotFoundError(f"no rules directory for platform {platform!r}: {base}")
    files = sorted(base.glob("*.yml")) + sorted(base.glob("*.yaml"))
    if not files:
        raise FileNotFoundError(f"no rule files found in {base}")
    return [load_policy_file(f) for f in files]
