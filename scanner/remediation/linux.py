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
}


def run_playbook(host, user, key, tags, check, playbook=PLAYBOOK, stream=True):
    """Invoke ansible-playbook once for the whole plan. `check` maps to Ansible's
    own --check, so dry-run is Ansible's dry-run rather than a Python imitation."""
    # tags first: an empty set would silently run every task in the playbook,
    # which is a worse outcome than any missing-dependency error
    if not tags:
        return False, "no tags to run"
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
        proc = subprocess.run(cmd, capture_output=not stream, text=True, timeout=600)
    except subprocess.TimeoutExpired:
        return False, "ansible-playbook timed out after 600s"

    output = "" if stream else (proc.stdout or "") + (proc.stderr or "")
    return proc.returncode == 0, output.strip() or f"ansible exited {proc.returncode}"
