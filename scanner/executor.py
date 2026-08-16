"""Turn a sub-rule into the concrete command that collects its evidence, run it
over the connection, and hand back the raw output. No pass/fail logic lives here."""
from __future__ import annotations

import shlex

from .connection.base import CommandOutput, Connection
from .model import SubRule


def _ps_quote(value: str) -> str:
    """PowerShell single-quoted literal; an embedded quote is doubled."""
    return "'" + value.replace("'", "''") + "'"


def probe_command(sub: SubRule, platform: str) -> str:
    """The exact command a backend runs to collect evidence for a sub-rule.
    Also the lookup key for fixture scenarios, so it must be stable."""
    t = sub.type
    if t == "cmd":
        return sub.target
    # quote targets so a typo in a rule file can't escape the shell
    if platform == "windows":
        if t == "r":
            path = sub.target.replace("HKLM\\", "HKLM:\\").replace("HKCU\\", "HKCU:\\")
            return f"Get-ItemPropertyValue -Path {_ps_quote(path)} -Name {_ps_quote(sub.name or '')}"
        if t == "svc":
            # SilentlyContinue so an absent service returns empty rather than erroring
            return f"(Get-Service -Name {_ps_quote(sub.target)} -ErrorAction SilentlyContinue).Status"
    else:  # linux
        if t == "f":
            return f"cat {shlex.quote(sub.target)} 2>/dev/null"
        if t == "svc":
            return f"systemctl is-active {shlex.quote(sub.target)}"
        if t == "perm":
            return f"stat -c '%a' {shlex.quote(sub.target)}"
    raise ValueError(f"sub-rule type {t!r} not supported on platform {platform!r}: {sub.raw}")


def collect(sub: SubRule, platform: str, conn: Connection) -> CommandOutput:
    return conn.run(probe_command(sub, platform))
