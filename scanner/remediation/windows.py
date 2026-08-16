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
    "WIN-18.3.3": Fix(
        check_id="WIN-18.3.3",
        title="SMBv1 disabled",
        command="ansible tag WIN-18.3.3 (win_regedit SMB1=0 + remove SMB1Protocol feature)",
        requires_reboot=True,
    ),
    "WIN-9.1": Fix(
        check_id="WIN-9.1",
        title="Windows Firewall on all profiles",
        command="ansible tag WIN-9.1 (Set-NetFirewallProfile -Enabled True)",
    ),
    "WIN-1.1.1": Fix(
        check_id="WIN-1.1.1",
        title="Minimum password length (14+)",
        command="ansible tag WIN-1.1.1 (net accounts /minpwlen:14)",
    ),
    "WIN-17.1": Fix(
        check_id="WIN-17.1",
        title="Audit logging for logon events",
        command="ansible tag WIN-17.1 (auditpol /set Logon success+failure)",
    ),
    "WIN-5.1": Fix(
        check_id="WIN-5.1",
        title="Legacy services disabled",
        command="ansible tag WIN-5.1 (win_service RemoteRegistry stopped + disabled)",
    ),
    "WIN-2.3.1.1": Fix(
        check_id="WIN-2.3.1.1",
        title="Guest account disabled",
        command="ansible tag WIN-2.3.1.1 (win_user Guest account_disabled)",
    ),
    "WIN-2.3.7.4": Fix(
        check_id="WIN-2.3.7.4",
        title="RDP requires Network Level Authentication",
        command="ansible tag WIN-2.3.7.4 (win_regedit UserAuthentication=1)",
    ),
    "WIN-18.9.10": Fix(
        check_id="WIN-18.9.10",
        title="BitLocker enabled on the OS volume",
        command=None,
        reason_no_fix="no safe auto-fix defined, flagged for manual action",
    ),
}
