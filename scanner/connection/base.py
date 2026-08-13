from __future__ import annotations

from dataclasses import dataclass


@dataclass
class CommandOutput:
    stdout: str
    exit_status: int
    ok: bool  # False means the command could not run at all (host unreachable / no output source)


class Connection:
    """Backend interface. `ok=False` is reserved for 'could not execute' —
    a command that ran and simply found nothing returns ok=True with a
    non-zero exit_status. The evaluator relies on that distinction to tell
    'unreachable' (-> WARN) apart from 'absent' (a real signal)."""

    def run(self, command: str) -> CommandOutput:
        raise NotImplementedError

    def close(self) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
