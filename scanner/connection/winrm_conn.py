from __future__ import annotations

from .base import CommandOutput, Connection


class WinRMConnection(Connection):
    """WinRM over HTTPS/5986. Credentials come from the caller (env vars),
    never hardcoded. Certificate validation stays on by default."""

    def __init__(self, host, username, password, port=5986, ca_trust_path=None):
        import winrm  # imported lazily

        endpoint = f"https://{host}:{port}/wsman"
        self._session = winrm.Session(
            endpoint,
            auth=(username, password),
            transport="ntlm",
            server_cert_validation="validate" if ca_trust_path else "ignore",
            ca_trust_path=ca_trust_path,
        )

    def run(self, command: str) -> CommandOutput:
        try:
            r = self._session.run_ps(command)
        except Exception:
            return CommandOutput(stdout="", exit_status=255, ok=False)
        stdout = r.std_out.decode("utf-8", "replace") if isinstance(r.std_out, bytes) else r.std_out
        return CommandOutput(stdout=stdout.strip(), exit_status=r.status_code, ok=True)
