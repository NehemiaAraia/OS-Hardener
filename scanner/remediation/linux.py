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
    "LNX-5.2.8": Fix(
        check_id="LNX-5.2.8",
        title="root SSH login disabled",
        command="ansible tag LNX-5.2.8 (lineinfile PermitRootLogin no, validated, reload sshd)",
    ),
    "LNX-5.2.9": Fix(
        check_id="LNX-5.2.9",
        title="SSH password authentication disabled",
        command="ansible tag LNX-5.2.9 (lineinfile PasswordAuthentication no, validated, reload sshd)",
    ),
    "LNX-3.5.1": Fix(
        check_id="LNX-3.5.1",
        title="host firewall active",
        command="ansible tag LNX-3.5.1 (install + enable firewalld)",
    ),
    "LNX-4.1.1": Fix(
        check_id="LNX-4.1.1",
        title="auditd and rsyslog running",
        command="ansible tag LNX-4.1.1 (enable + start auditd and rsyslog)",
    ),
    "LNX-5.4.1": Fix(
        check_id="LNX-5.4.1",
        title="password policy (minlen 14+)",
        command="ansible tag LNX-5.4.1 (set minlen = 14 in pwquality.conf)",
    ),
    "LNX-6.1.1": Fix(
        check_id="LNX-6.1.1",
        title="/etc/passwd permissions",
        command="ansible tag LNX-6.1.1 (chmod 0644 root:root)",
    ),
    "LNX-6.1.2": Fix(
        check_id="LNX-6.1.2",
        title="/etc/shadow permissions",
        command="ansible tag LNX-6.1.2 (chmod 0000 root:root)",
    ),
    # LNX-5.3.4 (sudoers NOPASSWD:ALL) is deliberately absent. Removing the
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
