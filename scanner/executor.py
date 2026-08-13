"""Turn a sub-rule into the concrete command that collects its evidence, run it
over the connection, and hand back the raw output. No pass/fail logic lives here."""
from __future__ import annotations

from .connection.base import CommandOutput, Connection
from .model import SubRule


def probe_command(sub: SubRule, platform: str) -> str:
    """The exact command a backend runs to collect evidence for a sub-rule.
    Also the lookup key for fixture scenarios, so it must be stable."""
    t = sub.type
    if t == "cmd":
        return sub.target
    if platform == "windows":
        if t == "r":
            path = sub.target.replace("HKLM\\", "HKLM:\\").replace("HKCU\\", "HKCU:\\")
            return f"Get-ItemPropertyValue -Path '{path}' -Name '{sub.name}'"
        if t == "svc":
            # SilentlyContinue so an absent service returns empty rather than erroring
            return f"(Get-Service -Name '{sub.target}' -ErrorAction SilentlyContinue).Status"
    else:  # linux
        if t == "f":
            return f"cat '{sub.target}' 2>/dev/null"
        if t == "svc":
            return f"systemctl is-active '{sub.target}'"
        if t == "perm":
            return f"stat -c '%a' '{sub.target}'"
    raise ValueError(f"sub-rule type {t!r} not supported on platform {platform!r}: {sub.raw}")


def collect(sub: SubRule, platform: str, conn: Connection) -> CommandOutput:
    return conn.run(probe_command(sub, platform))
