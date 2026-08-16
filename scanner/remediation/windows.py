"""Windows remediation catalog.

Remediation runs through the ansible.windows collection over WinRM, matching
ansible-lockdown's Windows-2022-CIS approach. Each entry's check_id is the
playbook tag, so a run is scoped to exactly the controls a scan found failing.
"""
from __future__ import annotations

from .base import Fix

# check id -> fix. Controls absent from this catalog are reported by the CLI as
# "no automated fix defined" rather than being silently dropped.
CATALOG = {
    "WIN-SMB1": Fix(
        check_id="WIN-SMB1",
        title="SMBv1 disabled",
        command="ansible tag WIN-SMB1 (win_regedit SMB1=0 + remove SMB1Protocol feature)",
        requires_reboot=True,
    ),
    "WIN-FIREWALL": Fix(
        check_id="WIN-FIREWALL",
        title="Windows Firewall on all profiles",
        command="ansible tag WIN-FIREWALL (Set-NetFirewallProfile -Enabled True)",
    ),
    "WIN-PW-MINLEN": Fix(
        check_id="WIN-PW-MINLEN",
        title="Minimum password length (14+)",
        command="ansible tag WIN-PW-MINLEN (net accounts /minpwlen:14)",
    ),
    "WIN-AUDIT-LOGON": Fix(
        check_id="WIN-AUDIT-LOGON",
        title="Audit logging for logon events",
        command="ansible tag WIN-AUDIT-LOGON (auditpol /set Logon success+failure)",
    ),
    "WIN-LEGACY-SVC": Fix(
        check_id="WIN-LEGACY-SVC",
        title="Legacy services disabled",
        command="ansible tag WIN-LEGACY-SVC (win_service RemoteRegistry stopped + disabled)",
    ),
    "WIN-GUEST": Fix(
        check_id="WIN-GUEST",
        title="Guest account disabled",
        command="ansible tag WIN-GUEST (win_user Guest account_disabled)",
    ),
    "WIN-RDP-NLA": Fix(
        check_id="WIN-RDP-NLA",
        title="RDP requires Network Level Authentication",
        command="ansible tag WIN-RDP-NLA (win_regedit UserAuthentication=1)",
    ),
    "WIN-BITLOCKER": Fix(
        check_id="WIN-BITLOCKER",
        title="BitLocker enabled on the OS volume",
        command=None,
        reason_no_fix="no safe auto-fix defined, flagged for manual action",
    ),
}
