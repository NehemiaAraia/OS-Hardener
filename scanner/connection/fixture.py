from __future__ import annotations

from pathlib import Path

import yaml

from .base import CommandOutput, Connection


class FixtureConnection(Connection):
    """Replays recorded command output for offline dev and CI. A scenario file
    is a YAML mapping of exact command string -> {stdout, exit_status}. A command
    not present in the scenario returns ok=False, i.e. 'host unreachable' — which
    keeps the fail-safe honest: a missing fixture never silently passes a check."""

    def __init__(self, scenario: str, base_dir: str | None = None):
        root = Path(base_dir) if base_dir else Path(__file__).resolve().parents[2] / "tests" / "fixtures"
        path = Path(scenario)
        if not path.is_absolute():
            path = root / scenario
        if path.is_dir() or not path.suffix:
            path = path.with_suffix(".yml")
        data = yaml.safe_load(path.read_text()) or {}
        self._map = {k: v for k, v in data.items()}
        self.scenario = str(path)

    def run(self, command: str) -> CommandOutput:
        entry = self._map.get(command)
        if entry is None:
            return CommandOutput(stdout="", exit_status=255, ok=False)
        if isinstance(entry, str):
            entry = {"stdout": entry, "exit_status": 0}
        return CommandOutput(
            stdout=str(entry.get("stdout", "")),
            exit_status=int(entry.get("exit_status", 0)),
            ok=True,
        )
