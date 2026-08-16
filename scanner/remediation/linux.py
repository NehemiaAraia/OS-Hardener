"""Linux remediation: shells out to an Ansible playbook.

Ansible owns this side because idempotency, check-mode and config-file editing
are already solved there; Python keeps detection and reporting. One
ansible-playbook invocation covers the whole plan, scoped by tag to the controls
that actually failed.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from ..validate import check_host
from .base import Fix

PLAYBOOK = "playbooks/linux_remediate.yml"

# check id -> fix. The tag is what scopes the playbook to this control.
CATALOG = {
    "LNX-SSH-ROOT": Fix(
        check_id="LNX-SSH-ROOT",
        title="root SSH login disabled",
        command="ansible tag LNX-SSH-ROOT (lineinfile PermitRootLogin no, validated, reload sshd)",
    ),
    "LNX-SSH-PASSAUTH": Fix(
        check_id="LNX-SSH-PASSAUTH",
        title="SSH password authentication disabled",
        command="ansible tag LNX-SSH-PASSAUTH (lineinfile PasswordAuthentication no, validated, reload sshd)",
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
    # LNX-SUDO-NOPASSWD (sudoers NOPASSWD:ALL) is deliberately absent. Removing the
    # admin account's passwordless sudo is the change most likely to lock an
    # operator out of the machine being hardened, so it stays a reported finding.
}


def run_playbook(host, user, key, tags, check, playbook=PLAYBOOK, stream=True):
    """Invoke ansible-playbook once for the whole plan. `check` maps to Ansible's
    own --check, so dry-run is Ansible's dry-run rather than a Python imitation."""
    # tags first: an empty set would silently run every task in the playbook,
    # which is a worse outcome than any missing-dependency error
    if not tags:
        return False, "no tags to run"
    try:
        check_host(host)
    except ValueError as e:
        return False, str(e)
    if shutil.which("ansible-playbook") is None:
        return False, "ansible-playbook not found on PATH"
    if not Path(playbook).exists():
        return False, f"playbook not found: {playbook}"

    cmd = [
        "ansible-playbook",
        "-i", f"{host},",
        playbook,
        "-u", user,
        "--private-key", key,
        "--tags", ",".join(sorted(tags)),
        "--ssh-common-args=-o StrictHostKeyChecking=accept-new",
    ]
    if check:
        cmd.append("--check")

    try:
        # argument list, never shell=True; host is validated above and tags are
        # rule-file check IDs
        proc = subprocess.run(cmd, capture_output=not stream, text=True, timeout=600)  # nosec B603
    except subprocess.TimeoutExpired:
        return False, "ansible-playbook timed out after 600s"

    output = "" if stream else (proc.stdout or "") + (proc.stderr or "")
    return proc.returncode == 0, output.strip() or f"ansible exited {proc.returncode}"
