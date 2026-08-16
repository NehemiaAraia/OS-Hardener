from __future__ import annotations

import base64
import sys

from .base import CommandOutput, Connection


class WinRMConnection(Connection):
    """WinRM over HTTPS/5986. Credentials come from the caller (env vars),
    never hardcoded.

    Holds one remote shell open for the whole scan. pywinrm's Session helper
    opens and tears down a shell per command, which costs roughly three round
    trips each — across a full rule set that tripled the scan time for no
    benefit.
    """

    def __init__(self, host, username, password, port=5986, ca_trust_path=None, insecure=False):
        from winrm.protocol import Protocol

        # validation stays on unless explicitly waived — defaulting to 'ignore'
        # would put NTLM credentials on a channel anyone can intercept, which is
        # exactly the weakness this tool reports on
        if insecure:
            validation = "ignore"
            print(
                "[!] WARNING: TLS certificate validation disabled for this scan.\n"
                "    Only acceptable against a lab host with a self-signed cert.",
                file=sys.stderr,
            )
        else:
            validation = "validate"

        self._protocol = Protocol(
            endpoint=f"https://{host}:{port}/wsman",
            transport="ntlm",
            username=username,
            password=password,
            server_cert_validation=validation,
            ca_trust_path=ca_trust_path,
        )
        self._shell_id = self._protocol.open_shell()

    def run(self, command: str) -> CommandOutput:
        if self._shell_id is None:
            return CommandOutput(stdout="", exit_status=255, ok=False)
        command_id = None
        try:
            encoded = base64.b64encode(command.encode("utf_16_le")).decode()
            command_id = self._protocol.run_command(
                self._shell_id, "powershell", ["-encodedcommand", encoded]
            )
            stdout, _stderr, code = self._protocol.get_command_output(
                self._shell_id, command_id
            )
        except Exception:
            return CommandOutput(stdout="", exit_status=255, ok=False)
        finally:
            if command_id is not None:
                try:
                    self._protocol.cleanup_command(self._shell_id, command_id)
                except Exception:  # nosec B110  # noqa: S110
                    pass

        text = stdout.decode("utf-8", "replace") if isinstance(stdout, bytes) else stdout
        return CommandOutput(stdout=text.strip(), exit_status=code, ok=True)

    def close(self) -> None:
        if self._shell_id:
            try:
                self._protocol.close_shell(self._shell_id)
            except Exception:  # nosec B110  # noqa: S110
                pass
            self._shell_id = None
