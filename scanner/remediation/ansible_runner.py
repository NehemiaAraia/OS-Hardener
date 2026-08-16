"""Invoke ansible-playbook for either platform.

Remediation runs through Ansible on both Windows and Linux: idempotency,
check-mode and inventory handling are already solved there, so Python keeps
detection and reporting and Ansible owns the changes. Only the connection
variables differ per platform.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from ..validate import check_host

PLAYBOOKS = {
    "linux": "playbooks/linux_remediate.yml",
    "windows": "playbooks/windows_remediate.yml",
}


def connection_args(platform: str, user: str, secret: str, insecure: bool = True) -> list[str]:
    """Per-platform connection settings. Secrets are passed as extra-vars rather
    than written to an inventory file, so nothing lands on disk."""
    if platform == "windows":
        validation = "ignore" if insecure else "validate"
        return [
            "-e", f"ansible_user={user}",
            "-e", f"ansible_password={secret}",
            "-e", (
                "ansible_connection=winrm ansible_port=5986 "
                "ansible_winrm_transport=ntlm "
                f"ansible_winrm_server_cert_validation={validation}"
            ),
        ]
    return [
        "-u", user,
        "--private-key", secret,
        "--ssh-common-args=-o StrictHostKeyChecking=accept-new",
    ]


def run_playbook(platform, host, user, secret, tags, check, insecure=True, stream=True):
    """One invocation for the whole plan. `check` maps to Ansible's own --check,
    so dry-run is Ansible's dry-run rather than a Python imitation."""
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

    playbook = PLAYBOOKS.get(platform)
    if not playbook or not Path(playbook).exists():
        return False, f"playbook not found for {platform}: {playbook}"

    cmd = [
        "ansible-playbook",
        "-i", f"{host},",
        playbook,
        "--tags", ",".join(sorted(tags)),
        *connection_args(platform, user, secret, insecure),
    ]
    if check:
        cmd.append("--check")

    env = dict(os.environ)
    env.setdefault("ANSIBLE_HOST_KEY_CHECKING", "False")
    # macOS refuses to fork after certain libraries initialise; the WinRM
    # connection plugin trips this and the run dies as "a worker in a dead state"
    env.setdefault("OBJC_DISABLE_INITIALIZE_FORK_SAFETY", "YES")

    try:
        # argument list, never shell=True; host is validated above and tags are
        # rule-file check IDs
        proc = subprocess.run(  # nosec B603
            cmd, capture_output=not stream, text=True, timeout=900, env=env
        )
    except subprocess.TimeoutExpired:
        return False, "ansible-playbook timed out after 900s"

    output = "" if stream else (proc.stdout or "") + (proc.stderr or "")
    return proc.returncode == 0, output.strip() or f"ansible exited {proc.returncode}"
