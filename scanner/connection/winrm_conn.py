from __future__ import annotations

import base64
import sys

from .base import CommandOutput, Connection


class WinRMConnection(Connection):
    """WinRM over HTTPS/5986. Credentials come from the caller (env vars),
    never hardcoded.

    Holds one remote shell open for the whole scan.
    """

    def __init__(self, host, username, password, port=5986, ca_trust_path=None, insecure=False):
        from winrm.protocol import Protocol

        # validation stays on unless explicitly waived
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
        self._cache: dict[str, CommandOutput] = {}

    # base64 per probe so rule-file quoting can't break the wrapper
    BATCH = 5

    def prefetch(self, commands) -> None:
        """Run several probes in one PowerShell process instead of one each."""
        todo = [c for c in dict.fromkeys(commands) if c not in self._cache]
        for start in range(0, len(todo), self.BATCH):
            chunk = todo[start : start + self.BATCH]
            encoded = ",".join(
                "'" + base64.b64encode(c.encode("utf-8")).decode() + "'" for c in chunk
            )
            script = (
                f"$cmds = @({encoded})\n"
                "for ($i = 0; $i -lt $cmds.Count; $i++) {\n"
                "  $c = [Text.Encoding]::UTF8.GetString("
                "[Convert]::FromBase64String($cmds[$i]))\n"
                "  $Error.Clear(); $global:LASTEXITCODE = 0; $out = ''\n"
                "  try { $out = Invoke-Expression $c 2>$null | Out-String } catch { }\n"
                "  $code = 0\n"
                "  if ($Error.Count -gt 0) { $code = 1 }\n"
                "  if ($LASTEXITCODE) { $code = $LASTEXITCODE }\n"
                "  Write-Output \"###P$i|$code\"\n"
                "  Write-Output $out.TrimEnd()\n"
                "  Write-Output \"###E$i\"\n"
                "}"
            )
            out = self._exec(script)
            if not out.ok:
                return  # fall back to per-probe execution
            self._cache.update(_parse_batch(out.stdout, chunk))

    def run(self, command: str) -> CommandOutput:
        cached = self._cache.pop(command, None)
        if cached is not None:
            return cached
        return self._exec(command)

    def _exec(self, command: str) -> CommandOutput:
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


def _parse_batch(text: str, commands) -> dict:
    """Split a batched run into per-probe results; a missing probe is left out
    so it falls back to an individual run."""
    import re

    results = {}
    for i, cmd in enumerate(commands):
        m = re.search(rf"^###P{i}\|(-?\d+)\r?\n(.*?)^###E{i}\s*$",
                      text, re.S | re.M)
        if not m:
            continue
        code = int(m.group(1))
        results[cmd] = CommandOutput(stdout=m.group(2).strip(), exit_status=code, ok=True)
    return results
