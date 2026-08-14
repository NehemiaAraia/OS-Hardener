"""Windows remediation: PowerShell run in-process over the existing WinRM
connection. Each fix maps to exactly one control the scanner checks, so a
re-scan verifies the fix rather than taking its word for it."""
from __future__ import annotations

from .base import Fix

# check id -> fix. Controls absent from this catalog are reported but never
# touched; a fix with command=None is declared unfixable rather than ignored.
CATALOG = {
    "WIN-18.3.3": Fix(
        check_id="WIN-18.3.3",
        title="SMBv1 disabled",
        command="Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart",
        requires_reboot=True,
    ),
    "WIN-9.1": Fix(
        check_id="WIN-9.1",
        title="Windows Firewall on all profiles",
        command="Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True",
    ),
    "WIN-1.1.1": Fix(
        check_id="WIN-1.1.1",
        title="Minimum password length (14+)",
        command="net accounts /minpwlen:14",
    ),
    "WIN-17.1": Fix(
        check_id="WIN-17.1",
        title="Audit logging for logon events",
        command='auditpol /set /subcategory:"Logon" /success:enable /failure:enable',
    ),
    "WIN-5.1": Fix(
        check_id="WIN-5.1",
        title="Legacy services disabled",
        command=(
            "Stop-Service -Name RemoteRegistry -Force -ErrorAction SilentlyContinue; "
            "Set-Service -Name RemoteRegistry -StartupType Disabled"
        ),
    ),
    "WIN-18.9.10": Fix(
        check_id="WIN-18.9.10",
        title="BitLocker enabled on the OS volume",
        command=None,
        reason_no_fix="no safe auto-fix defined, flagged for manual action",
    ),
}


def make_runner(conn):
    """Run one fix over the live connection and report whether it took."""
    def run(fix: Fix) -> tuple[bool, str]:
        out = conn.run(fix.command)
        if not out.ok:
            return False, "connection lost during remediation"
        if out.exit_status != 0:
            return False, (out.stdout or "command returned non-zero").strip()[:200]
        return True, "done"

    return run
