"""Linux remediation catalog. Fixes run through playbooks/linux_remediate.yml."""
from __future__ import annotations

from .base import Fix

# check id -> fix; the id is also the playbook tag
CATALOG = {
    "LNX-SSH-ROOT": Fix(
        check_id="LNX-SSH-ROOT",
        title="root SSH login disabled",
        command="ansible tag LNX-SSH-ROOT (PermitRootLogin no, validated, reload sshd)",
    ),
    "LNX-SSH-PASSAUTH": Fix(
        check_id="LNX-SSH-PASSAUTH",
        title="SSH password authentication disabled",
        command="ansible tag LNX-SSH-PASSAUTH (PasswordAuthentication no, validated, reload sshd)",
    ),
    "LNX-FIREWALL": Fix(
        check_id="LNX-FIREWALL",
        title="host firewall active",
        command="ansible tag LNX-FIREWALL (install + enable firewalld)",
    ),
    "LNX-AUDIT-LOG": Fix(
        check_id="LNX-AUDIT-LOG",
        title="auditd and rsyslog running",
        command="ansible tag LNX-AUDIT-LOG (enable + start auditd and rsyslog)",
    ),
    "LNX-PW-MINLEN": Fix(
        check_id="LNX-PW-MINLEN",
        title="password policy (minlen 14+)",
        command="ansible tag LNX-PW-MINLEN (set minlen = 14 in pwquality.conf)",
    ),
    "LNX-PASSWD-PERMS": Fix(
        check_id="LNX-PASSWD-PERMS",
        title="/etc/passwd permissions",
        command="ansible tag LNX-PASSWD-PERMS (chmod 0644 root:root)",
    ),
    "LNX-SHADOW-PERMS": Fix(
        check_id="LNX-SHADOW-PERMS",
        title="/etc/shadow permissions",
        command="ansible tag LNX-SHADOW-PERMS (chmod 0000 root:root)",
    ),
    # LNX-SUDO-NOPASSWD is deliberately absent: removing the admin account's
    # passwordless sudo can lock an operator out of the host being hardened.
}
