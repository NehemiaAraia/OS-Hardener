from __future__ import annotations

from .base import CommandOutput, Connection


class SSHConnection(Connection):
    """SSH with key-based auth (paramiko). No password auth, no agent forwarding."""

    def __init__(self, host, username, key_filename, port=22, timeout=15, command_timeout=120):
        import paramiko  # imported lazily

        self._timeout = command_timeout

        self._client = paramiko.SSHClient()
        self._client.set_missing_host_key_policy(paramiko.RejectPolicy())
        self._client.load_system_host_keys()
        self._client.connect(
            hostname=host,
            port=port,
            username=username,
            key_filename=key_filename,
            timeout=timeout,
            allow_agent=False,
            look_for_keys=False,
        )

    def run(self, command: str) -> CommandOutput:
        try:
            _, stdout, _ = self._client.exec_command(command, timeout=self._timeout)
            # drain the channel before waiting on the exit status — the remote
            # side blocks once it fills the window, and 'find /' will fill it
            out = stdout.read().decode("utf-8", "replace")
            status = stdout.channel.recv_exit_status()
        except Exception:
            return CommandOutput(stdout="", exit_status=255, ok=False)
        return CommandOutput(stdout=out.strip(), exit_status=status, ok=True)

    def close(self) -> None:
        try:
            self._client.close()
        except Exception:
            pass
