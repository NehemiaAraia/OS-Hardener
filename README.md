# OS Hardening & Compliance Automation Platform

Cross-platform security automation: scans Windows Server 2022 and RHEL 9 against
CIS controls, scores compliance, reports findings tagged to NIST 800-53, and
remediates the failures it finds.

One CLI, one codebase, both platforms:

```
python main.py scan      --target windows|linux --host <ip>
python main.py remediate --target windows|linux --host <ip> --dry-run|--apply
```

Platform only changes which rules load and which connection library is used.
Scanning, scoring, tagging, and reporting run the same code path for both.

```
                    ┌─────────────────────────────────────────────┐
[Windows Server] <--┤ WinRM  →  scanner engine (parser→executor→   │
                    │           evaluator→scoring→reporter)        ├--> reports
[RHEL 9]         <--┤ SSH    →  (same engine, both platforms)      │
                    └─────────────────────────────────────────────┘
```

## Design decisions

**Never default to PASS.** An unreachable host, an unparseable value, or an
unrecognized matcher resolves to WARN, never PASS. The connection layer reserves
a distinct "could not execute" signal so *unreachable* is never confused with
*absent* — a check that can't be verified is reported as unverified, not clean.
This is the failure mode that makes a compliance tool actively harmful, so it's
enforced structurally and covered by tests.

**PASS / FAIL / WARN, not pass/fail.** Some controls (local Administrators
membership, the SUID/SGID inventory) have no correct fixed baseline. They report
WARN and carry their evidence into the report for a human, rather than being
forced into a false pass or fail.

**Scoring excludes what it can't judge.** Only `scored` controls that resolved to
a definite PASS/FAIL count toward the score; WARNs are reported separately rather
than quietly inflating or deflating it. Controls with no safe unattended fix
(BitLocker on a running instance) are `notscored`, mirroring CIS's own model.

**Host-side date math.** Patch recency is computed on the target and returned as
an integer age, so results don't depend on the scanner's clock and recorded test
fixtures don't rot.

**Least privilege on the tool itself.** The scanner authenticates as
`svc-hardening-scanner` — on Windows a member of Remote Management Users, not
Administrators; on Linux an account whose sudoers entry lists the exact read-only
commands it runs, no `NOPASSWD: ALL`. Credentials come from environment
variables, never the repo. In production this would be AWS Secrets Manager.

**WinRM over HTTPS only.** The bootstrap script configures the 5986 listener and
deletes the 5985 cleartext one; the security group never opens 5985.

## Rule format

YAML modeled on Wazuh's SCA schema (`policy` / `requirements` / `checks`), with
typed sub-rules and a `condition` of `all` / `any` / `none`:

```yaml
- id: WIN-18.3.3
  title: SMBv1 disabled
  level: level1
  scored: scored
  severity: critical
  nist: NIST800-53R5_CM-7
  condition: all
  rules:
    - "r:HKLM\\SYSTEM\\...\\LanmanServer\\Parameters -> SMB1 -> equals:0"
```

Sub-rule prefixes: `r:` registry, `f:` file contents, `cmd:` command,
`svc:` service state, `perm:` file mode.
Matchers: `equals`, `regex`, `notregex`, `minint`, `maxint`, `maxmode`,
`running`, `stopped`, `exists`, `absent`.

NIST tags follow the ansible-lockdown conversion convention — `NIST800-53R5`
with a capital R, periods for subsections, underscores for parenthetical
elements, so `IA-5(1)(a)` becomes `NIST800-53R5_IA-5_1_a`.

## Control coverage

### Windows Server 2022 (scope: member server)

| ID | Control | Level | Scored | Severity | NIST 800-53R5 |
|---|---|---|---|---|---|
| `WIN-18.3.3` | SMBv1 disabled | 1 | scored | critical | CM-7 |
| `WIN-9.1` | Firewall on all profiles | 1 | scored | high | SC-7 |
| `WIN-2.3.1` | Local Administrators membership | 1 | notscored | high | AC-6 |
| `WIN-2.3.1.1` | Guest account disabled | 1 | scored | high | AC-2 |
| `WIN-1.1.1` | Minimum password length (14+) | 1 | scored | high | IA-5_1_a |
| `WIN-1.1.5` | Password complexity enabled | 1 | scored | high | IA-5_1_a |
| `WIN-2.3.7.4` | RDP requires NLA | 1 | scored | high | IA-2 |
| `WIN-17.1` | Audit logging, logon events | 1 | scored | medium | AU-2 |
| `WIN-18.9.10` | BitLocker on OS volume | 1 | notscored | medium | SC-28 |
| `WIN-5.1` | Legacy services disabled | 1 | scored | medium | CM-7 |
| `WIN-18.10.42` | Patch recency (≤ 35 days) | 1 | scored | high | SI-2 |

### RHEL 9

| ID | Control | Level | Scored | Severity | NIST 800-53R5 |
|---|---|---|---|---|---|
| `LNX-5.2.8` | root SSH login disabled | 1 | scored | high | AC-6_2 |
| `LNX-5.2.9` | SSH password auth disabled | 1 | scored | high | IA-5_2 |
| `LNX-3.5.1` | Host firewall active | 1 | scored | high | SC-7 |
| `LNX-6.1.1` | `/etc/passwd` perms ≤ 0644 | 1 | scored | medium | AC-3 |
| `LNX-6.1.2` | `/etc/shadow` perms ≤ 0640 | 1 | scored | medium | AC-3 |
| `LNX-6.1.10` | No world-writable files | 2 | scored | medium | AC-3 |
| `LNX-6.1.13` | SUID/SGID audit | 2 | notscored | medium | CM-7 |
| `LNX-2.2.1` | Legacy services not installed | 1 | scored | high | CM-7 |
| `LNX-5.4.1` | Password policy (minlen 14+) | 1 | scored | high | IA-5_1_a |
| `LNX-5.3.4` | Sudoers audit (no NOPASSWD:ALL) | 1 | scored | high | AC-6_5 |
| `LNX-4.1.1` | auditd and rsyslog running | 1 | scored | medium | AU-2 |
| `LNX-1.9` | Patch recency (≤ 35 days) | 1 | scored | high | SI-2 |

## Lab setup

Two EC2 instances in a security group locked to a single operator IP.

```bash
terraform init
terraform apply -var="my_ip=$(curl -s ifconfig.me)/32" -var="key_name=<your-keypair>"
```

AMIs are looked up dynamically by name pattern rather than pinned to IDs, which
go stale. Both instances use IMDSv2 and encrypted root volumes. Stop them when
not in use.

Then, once per instance, logged in with the default admin account:

```powershell
.\bootstrap_windows.ps1 -OperatorCidr 203.0.113.4/32   # on the Windows host
```
```bash
sudo ./bootstrap_linux.sh "$(cat ~/.ssh/id_ed25519.pub)"   # on the RHEL host
```

Each prints the environment variables to export on the scanning machine. Nothing
is written to the repo.

## Running

```bash
export WINRM_USER=svc-hardening-scanner WINRM_PASS=...      # windows
export SSH_USER=svc-hardening-scanner SSH_KEY=~/.ssh/id_ed25519   # linux

python main.py scan --target windows --host 203.0.113.10
python main.py scan --target linux   --host 203.0.113.11
```

Each scan writes `reports/<platform>_<timestamp>.json` and a Bootstrap-styled
HTML report. Report rendering goes through Jinja2 with autoescaping on —
evidence strings come off scanned hosts and are never interpolated raw.

### Development without a live host

The connection layer has a fixture backend that replays recorded command output,
so the full pipeline runs offline:

```bash
python main.py scan --target linux --fixture linux/baseline
pytest
```

Fixtures are generated from the rule files (`python tests/gen_fixtures.py`) and
keyed on the exact probe command the executor emits, so recorded output can't
drift from what the scanner actually runs.

## Sources

Read directly and cited, not copied — none of these combine scanning, scoring,
NIST tagging, reporting, and remediation in one tool.

- **ansible-lockdown** (`RHEL9-CIS`, `Windows-2022-CIS`) — NIST tag convention,
  PASS/FAIL/WARN model, before/after audit delta, check-before-act pattern
- **WinSecureAuditor** — module architecture, Wazuh SCA schema, typed sub-rule
  prefixes, and the default-to-PASS fail-safe bug this tool deliberately avoids
- **atlantsecurity/windows-hardening-scripts** — DISA STIG angle
- **JShielder** — Linux control selection

## Status

Tier 1 complete: scanning, scoring, reporting, IAM, infra.
Tier 2 in progress: SQLite history, Flask dashboard, Windows remediation in
Python, Linux remediation via Ansible, before/after delta.
