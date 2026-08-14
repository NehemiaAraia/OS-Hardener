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

**Scoring excludes what it can't judge, and says so.** Only `scored` controls that
resolved to a definite PASS/FAIL count toward the score. Because that means a
score can be computed from a small subset, **coverage travels with it everywhere**
— `100% (verified 2/11 scored controls)` is a different claim from `100%
(verified 11/11)`, and the CLI and report both flag partial coverage explicitly.
Controls with no safe unattended fix (BitLocker on a running instance) are
`notscored`, mirroring CIS's own model.

**Elevation fails closed.** Controls needing root (`/etc/sudoers`, a full-filesystem
find) run through a root-owned helper granted via three fixed sudo verbs. The
helper prints nothing when it can't run, which reports WARN — an earlier version
piped through `wc -l`, so a permission error produced `0` and the sudoers audit
could never fail.

**Host-side date math.** Patch recency is computed on the target and returned as
an integer age, so results don't depend on the scanner's clock and recorded test
fixtures don't rot.

**Least privilege on the tool itself.** The scanner authenticates as
`svc-hardening-scanner` — on Windows a member of Remote Management Users, not
Administrators; on Linux an account granted sudo on three fixed helper verbs and
nothing else, no `NOPASSWD: ALL`. The sudoers entries carry no wildcards on
purpose: a wildcarded `sudo find` entry accepts `-exec`, which hands out a root
shell and undoes the whole point. Credentials come from environment variables,
never the repo. In production this would be AWS Secrets Manager.

**WinRM over HTTPS, validated.** The bootstrap script configures the 5986 listener
and deletes the 5985 cleartext one; the security group never opens 5985.
Certificate validation is on by default — skipping it requires an explicit
`--insecure` that prints a warning, since a security tool putting NTLM
credentials on an unvalidated channel is the flaw it exists to report.

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
is written to the repo. The Linux script also installs the root-owned scan helper
to `/usr/local/sbin/hardening-scan-helper`.

The Windows bootstrap creates a self-signed certificate, so the first live scan
needs either that cert trusted on the scanning machine or an explicit
`--insecure` flag.

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

## Remediation

```bash
python main.py remediate --target windows --host <ip> --dry-run   # default
python main.py remediate --target windows --host <ip> --apply     # asks first
python main.py scan      --target windows --host <ip>             # verify + delta
```

Remediation scans first and acts only on controls that came back **FAIL**. A WARN
is never remediated: it means the control was not verified, and acting on an
unverified finding is how a hardening tool breaks a working machine. Controls
with no safe unattended fix are reported as `[SKIP]` with a reason rather than
quietly dropped, and reboots are flagged, never forced. Every action is appended
to `reports/remediation.log` — in a real environment that log line carries a
change ticket ID.

**Remediation uses a different identity than scanning.** The scanner account is
read-only by design, so it cannot apply fixes — `WINRM_ADMIN_USER` /
`WINRM_ADMIN_PASS` on Windows and `REMEDIATE_SSH_USER` / `REMEDIATE_SSH_KEY` on
Linux are required for `--apply`. If the scanning identity could also change the
system, the least-privilege claim would be decorative.

| | Windows | Linux |
|---|---|---|
| Backend | Python functions over the existing WinRM session | `ansible-playbook`, one invocation |
| Dry run | prints the exact command per control | Ansible's own `--check` |
| Scoping | per-control fix catalog | playbook tags, one per control |

Linux runs through Ansible because idempotency, check-mode and safe config-file
editing are already solved there — the playbook validates `sshd_config` with
`sshd -t` before reloading. Python keeps detection and reporting.

## Scan history and dashboard

Every scan is stored in SQLite (`reports/scans.db`) through parameterized
queries. A re-scan of the same target automatically prints the delta:

```
[*] compared to previous scan (20260814_023731):
    score: 56% -> 100%  (+44)
    WIN-18.3.3       SMBv1 disabled            FAIL -> PASS
    WIN-18.9.10      BitLocker on OS volume    FAIL -> FAIL  (unchanged)
```

Regressions are listed first and labelled, and a score that moved because
*coverage* moved is called out rather than presented as a real gain.

```bash
export DASHBOARD_USER=admin DASHBOARD_PASS=...
python dashboard.py                 # https://127.0.0.1:8443, self-signed
python dashboard.py --cert c.pem --key k.pem
```

Basic auth over HTTPS (credentials compared with `hmac.compare_digest`), bound to
localhost by default, no raw SQL, autoescaped templates, and `nosniff` /
`DENY` / CSP headers. Host names and evidence come off scanned machines, so the
escaping is load-bearing — there's a test asserting a `<script>` host name
renders inert.

## Status

Tier 1 and Tier 2 complete: scanning, scoring, reporting, IAM, infra, SQLite
history, before/after delta, Windows and Linux remediation, dashboard.
Tier 3 (roadmap): CI with lint + Bandit, AWS SSM as a connection backend,
Windows remediation via `ansible.windows`, suppression/waiver file.
