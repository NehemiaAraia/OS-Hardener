from __future__ import annotations

import sys

from .base import CommandOutput, Connection


class WinRMConnection(Connection):
    """WinRM over HTTPS/5986. Credentials come from the caller (env vars),
    never hardcoded."""

    def __init__(self, host, username, password, port=5986, ca_trust_path=None, insecure=False):
        import winrm  # imported lazily

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

        endpoint = f"https://{host}:{port}/wsman"
        self._session = winrm.Session(
            endpoint,
            auth=(username, password),
            transport="ntlm",
            server_cert_validation=validation,
            ca_trust_path=ca_trust_path,
        )

    def run(self, command: str) -> CommandOutput:
        try:
            r = self._session.run_ps(command)
        except Exception:
            return CommandOutput(stdout="", exit_status=255, ok=False)
        stdout = r.std_out.decode("utf-8", "replace") if isinstance(r.std_out, bytes) else r.std_out
        return CommandOutput(stdout=stdout.strip(), exit_status=r.status_code, ok=True)
