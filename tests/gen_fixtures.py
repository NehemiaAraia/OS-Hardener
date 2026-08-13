"""Generate fixture scenarios keyed on the exact probe commands the executor
emits, so recorded output can never drift from what the scanner actually runs.
Run from repo root: python tests/gen_fixtures.py"""
from __future__ import annotations

import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scanner.executor import probe_command  # noqa: E402
from scanner.parser import load_policies  # noqa: E402

# per-scenario output for each (check_id, subrule_index) -> {stdout, exit_status}
SCENARIOS = {
    "windows/baseline": {
        ("WIN-18.3.3", 0): ("1", 0),          # SMBv1 present -> FAIL (critical)
        ("WIN-9.1", 0): ("1", 0),             # firewall on, all profiles -> PASS
        ("WIN-9.1", 1): ("1", 0),
        ("WIN-9.1", 2): ("1", 0),
    },
    "windows/hardened": {
        ("WIN-18.3.3", 0): ("0", 0),          # SMBv1 disabled -> PASS
        ("WIN-9.1", 0): ("1", 0),
        ("WIN-9.1", 1): ("1", 0),
        ("WIN-9.1", 2): ("1", 0),
    },
    "linux/baseline": {
        ("LNX-5.2.8", 0): ("PermitRootLogin yes\nPort 22\n", 0),   # FAIL
        ("LNX-3.5.1", 0): ("inactive", 3),                          # firewalld off
        ("LNX-3.5.1", 1): ("inactive", 3),                          # nftables off -> FAIL
        ("LNX-6.1.2", 0): ("640", 0),                               # PASS
    },
    "linux/hardened": {
        ("LNX-5.2.8", 0): ("PermitRootLogin no\nPort 22\n", 0),    # PASS
        ("LNX-3.5.1", 0): ("active", 0),                            # firewalld on -> PASS
        ("LNX-3.5.1", 1): ("inactive", 3),
        ("LNX-6.1.2", 0): ("0", 0),                                 # PASS
    },
    # nothing recorded -> every probe is 'unreachable' -> every check WARN
    "linux/unreachable": {},
}

OUT = Path(__file__).parent / "fixtures"


def build(platform: str, spec: dict) -> dict:
    scenario = {}
    for pol in load_policies("rules", platform):
        for check in pol.checks:
            for i, sub in enumerate(check.rules):
                if (check.id, i) in spec:
                    stdout, code = spec[(check.id, i)]
                    scenario[probe_command(sub, platform)] = {"stdout": stdout, "exit_status": code}
    return scenario


def main() -> None:
    for name, spec in SCENARIOS.items():
        platform = name.split("/")[0]
        scenario = build(platform, spec)
        path = OUT / f"{name}.yml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(yaml.safe_dump(scenario, default_flow_style=False, sort_keys=True))
        print(f"wrote {path}  ({len(scenario)} probes)")


if __name__ == "__main__":
    main()
