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

SUID_LIST = "/usr/bin/sudo\n/usr/bin/passwd\n/usr/bin/su"

# checks that read the same file share one probe command, so the recorded content
# has to be the whole file, not just the line one check cares about
SSHD_BASELINE = "PermitRootLogin yes\nPasswordAuthentication yes\nPort 22\n"
SSHD_HARDENED = "PermitRootLogin no\nPasswordAuthentication no\nPort 22\n"

# per-scenario output for each (check_id, subrule_index) -> (stdout, exit_status)
SCENARIOS = {
    # stock Windows Server 2022 AMI, pre-hardening
    "windows/baseline": {
        ("WIN-18.3.3", 0): ("1", 0),                        # SMBv1 present -> FAIL
        ("WIN-9.1", 0): ("1", 0),
        ("WIN-9.1", 1): ("1", 0),
        ("WIN-9.1", 2): ("1", 0),                           # firewall on -> PASS
        ("WIN-2.3.1", 0): ("Administrator\nsvc-deploy", 0),  # manual -> WARN + list
        ("WIN-2.3.1.1", 0): ("False", 0),                   # guest disabled -> PASS
        ("WIN-1.1.1", 0): ("7", 0),                         # too short -> FAIL
        ("WIN-1.1.5", 0): ("1", 0),                         # complexity on -> PASS
        ("WIN-2.3.7.4", 0): ("1", 0),                       # NLA on -> PASS
        ("WIN-17.1", 0): ("  Logon                    Success", 0),  # no failure auditing -> FAIL
        ("WIN-18.9.10", 0): ("Off", 0),                     # notscored -> FAIL, no auto-fix
        ("WIN-5.1", 0): ("", 0),                            # telnet absent -> ok
        ("WIN-5.1", 1): ("Running", 0),                     # RemoteRegistry up -> FAIL
        ("WIN-18.10.42", 0): ("12", 0),                     # patched 12d ago -> PASS
    },
    # after remediation
    "windows/hardened": {
        ("WIN-18.3.3", 0): ("0", 0),
        ("WIN-9.1", 0): ("1", 0),
        ("WIN-9.1", 1): ("1", 0),
        ("WIN-9.1", 2): ("1", 0),
        ("WIN-2.3.1", 0): ("Administrator", 0),
        ("WIN-2.3.1.1", 0): ("False", 0),
        ("WIN-1.1.1", 0): ("14", 0),
        ("WIN-1.1.5", 0): ("1", 0),
        ("WIN-2.3.7.4", 0): ("1", 0),
        ("WIN-17.1", 0): ("  Logon                    Success and Failure", 0),
        ("WIN-18.9.10", 0): ("Off", 0),                     # unchanged, still manual
        ("WIN-5.1", 0): ("", 0),
        ("WIN-5.1", 1): ("Stopped", 0),
        ("WIN-18.10.42", 0): ("12", 0),
    },
    # stock RHEL 9 AMI, pre-hardening
    "linux/baseline": {
        ("LNX-5.2.8", 0): (SSHD_BASELINE, 0),
        ("LNX-5.2.9", 0): (SSHD_BASELINE, 0),
        ("LNX-3.5.1", 0): ("inactive", 3),
        ("LNX-3.5.1", 1): ("inactive", 3),                  # no firewall -> FAIL
        ("LNX-6.1.1", 0): ("644", 0),
        ("LNX-6.1.2", 0): ("0", 0),
        ("LNX-6.1.10", 0): ("/opt/app/shared/scratch.sh", 0),   # world-writable -> FAIL
        ("LNX-6.1.13", 0): (SUID_LIST, 0),                  # manual -> WARN + list
        ("LNX-2.2.1", 0): ("1", 0),                         # vsftpd installed -> FAIL
        ("LNX-5.4.1", 0): ("", 1),                          # minlen unset -> WARN, not PASS
        ("LNX-5.3.4", 0): ("1", 0),                         # a NOPASSWD:ALL grant -> FAIL
        ("LNX-4.1.1", 0): ("active", 0),
        ("LNX-4.1.1", 1): ("inactive", 3),                  # rsyslog down -> FAIL
        ("LNX-1.9", 0): ("3", 0),
    },
    # after remediation
    "linux/hardened": {
        ("LNX-5.2.8", 0): (SSHD_HARDENED, 0),
        ("LNX-5.2.9", 0): (SSHD_HARDENED, 0),
        ("LNX-3.5.1", 0): ("active", 0),
        ("LNX-3.5.1", 1): ("inactive", 3),                  # firewalld alone satisfies 'any'
        ("LNX-6.1.1", 0): ("644", 0),
        ("LNX-6.1.2", 0): ("0", 0),
        ("LNX-6.1.10", 0): ("", 0),
        ("LNX-6.1.13", 0): (SUID_LIST, 0),
        ("LNX-2.2.1", 0): ("0", 0),
        ("LNX-5.4.1", 0): ("14", 0),
        ("LNX-5.3.4", 0): ("0", 0),
        ("LNX-4.1.1", 0): ("active", 0),
        ("LNX-4.1.1", 1): ("active", 0),
        ("LNX-1.9", 0): ("3", 0),
    },
    # nothing recorded -> every probe is 'unreachable' -> every check WARN
    "linux/unreachable": {},
}

OUT = Path(__file__).parent / "fixtures"


def build(platform: str, spec: dict) -> dict:
    scenario = {}
    owner = {}
    for pol in load_policies("rules", platform):
        for check in pol.checks:
            for i, sub in enumerate(check.rules):
                if (check.id, i) not in spec:
                    continue
                stdout, code = spec[(check.id, i)]
                cmd = probe_command(sub, platform)
                entry = {"stdout": stdout, "exit_status": code}
                # two checks reading the same thing must agree, or one would
                # silently overwrite the other's recorded output
                if cmd in scenario and scenario[cmd] != entry:
                    raise ValueError(
                        f"{check.id} and {owner[cmd]} share probe {cmd!r} "
                        f"but record different output"
                    )
                scenario[cmd] = entry
                owner[cmd] = check.id
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
