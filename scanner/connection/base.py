from __future__ import annotations

from dataclasses import dataclass


@dataclass
class CommandOutput:
    stdout: str
    exit_status: int
    ok: bool  # False means the command could not run at all (host unreachable / no output source)


class Connection:
    """ok=False means the command could not run at all; a command that ran and
    found nothing returns ok=True with a non-zero exit status."""

    def run(self, command: str) -> CommandOutput:
        raise NotImplementedError

    def prefetch(self, commands) -> None:
        """Optionally collect several probes in one round trip."""
        return None

    def close(self) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
