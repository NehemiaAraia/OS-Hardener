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
        ("WIN-SMB1", 0): ("1", 0),                        # SMBv1 present -> FAIL
        ("WIN-FIREWALL", 0): ("0", 0),                           # 0 profiles disabled -> PASS
        ("WIN-LOCAL-ADMINS", 0): ("Administrator\nsvc-deploy", 0),  # manual -> WARN + list
        ("WIN-GUEST", 0): ("False", 0),                   # guest disabled -> PASS
        ("WIN-PW-MINLEN", 0): ("7", 0),                         # too short -> FAIL
        ("WIN-PW-COMPLEX", 0): ("1", 0),                         # complexity on -> PASS
        ("WIN-RDP-NLA", 0): ("1", 0),                       # NLA on -> PASS
        ("WIN-AUDIT-LOGON", 0): ("  Logon                    Success", 0),  # no failure auditing -> FAIL
        ("WIN-BITLOCKER", 0): ("Off", 0),                     # notscored -> FAIL, no auto-fix
        ("WIN-LEGACY-SVC", 0): ("1", 0),                           # 1 legacy service enabled -> FAIL
        ("WIN-PATCH-AGE", 0): ("12", 0),                     # patched 12d ago -> PASS
    },
    # after remediation
    "windows/hardened": {
        ("WIN-SMB1", 0): ("0", 0),
        ("WIN-FIREWALL", 0): ("0", 0),
        ("WIN-LOCAL-ADMINS", 0): ("Administrator", 0),
        ("WIN-GUEST", 0): ("False", 0),
        ("WIN-PW-MINLEN", 0): ("14", 0),
        ("WIN-PW-COMPLEX", 0): ("1", 0),
        ("WIN-RDP-NLA", 0): ("1", 0),
        ("WIN-AUDIT-LOGON", 0): ("  Logon                    Success and Failure", 0),
        ("WIN-BITLOCKER", 0): ("Off", 0),                     # unchanged, still manual
        ("WIN-LEGACY-SVC", 0): ("0", 0),
        ("WIN-PATCH-AGE", 0): ("12", 0),
    },
    # stock RHEL 9 AMI, pre-hardening
    "linux/baseline": {
        ("LNX-SSH-ROOT", 0): (SSHD_BASELINE, 0),
        ("LNX-SSH-PASSAUTH", 0): (SSHD_BASELINE, 0),
        ("LNX-FIREWALL", 0): ("inactive", 3),
        ("LNX-FIREWALL", 1): ("inactive", 3),                  # no firewall -> FAIL
        ("LNX-PASSWD-PERMS", 0): ("644", 0),
        ("LNX-SHADOW-PERMS", 0): ("0", 0),
        ("LNX-WORLD-WRITE", 0): ("3", 0),                        # 3 world-writable files -> FAIL
        ("LNX-SUID-AUDIT", 0): (SUID_LIST, 0),                  # manual -> WARN + list
        ("LNX-LEGACY-PKGS", 0): ("1", 0),                         # vsftpd installed -> FAIL
        ("LNX-PW-MINLEN", 0): ("", 1),                          # minlen unset -> WARN, not PASS
        ("LNX-SUDO-NOPASSWD", 0): ("1", 0),                         # a NOPASSWD:ALL grant -> FAIL
        ("LNX-AUDIT-LOG", 0): ("active", 0),
        ("LNX-AUDIT-LOG", 1): ("inactive", 3),                  # rsyslog down -> FAIL
        ("LNX-PATCH-AGE", 0): ("3", 0),
    },
    # after remediation
    "linux/hardened": {
        ("LNX-SSH-ROOT", 0): (SSHD_HARDENED, 0),
        ("LNX-SSH-PASSAUTH", 0): (SSHD_HARDENED, 0),
        ("LNX-FIREWALL", 0): ("active", 0),
        ("LNX-FIREWALL", 1): ("inactive", 3),                  # firewalld alone satisfies 'any'
        ("LNX-PASSWD-PERMS", 0): ("644", 0),
        ("LNX-SHADOW-PERMS", 0): ("0", 0),
        ("LNX-WORLD-WRITE", 0): ("0", 0),
        ("LNX-SUID-AUDIT", 0): (SUID_LIST, 0),
        ("LNX-LEGACY-PKGS", 0): ("0", 0),
        ("LNX-PW-MINLEN", 0): ("14", 0),
        ("LNX-SUDO-NOPASSWD", 0): ("0", 0),
        ("LNX-AUDIT-LOG", 0): ("active", 0),
        ("LNX-AUDIT-LOG", 1): ("active", 0),
        ("LNX-PATCH-AGE", 0): ("3", 0),
    },
    # the scanner account can reach the host but sudo is refused, so the helper
    # prints nothing, these controls must report WARN, not a fabricated pass
    "linux/sudo_denied": {
        ("LNX-SSH-ROOT", 0): (SSHD_HARDENED, 0),
        ("LNX-SSH-PASSAUTH", 0): (SSHD_HARDENED, 0),
        ("LNX-WORLD-WRITE", 0): ("", 1),
        ("LNX-SUID-AUDIT", 0): ("", 1),
        ("LNX-SUDO-NOPASSWD", 0): ("", 1),
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
