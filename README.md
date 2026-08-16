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
- id: WIN-SMB1
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

## How controls are identified and sourced

**Control IDs are internal identifiers, not benchmark citations.** `WIN-SMB1`
names the control inside this tool; the benchmark section it implements lives in
`references`. Those are two different jobs, and conflating them is a trap: CIS
renumbers between releases — Windows Server 2022 has gone through five major
benchmark versions since 2022, and RHEL 9 moved its entire file-permissions
block from `6.1.x` to `7.1.x` between v1 and v2. An ID that doubles as a citation
is wrong the next time the benchmark ships.

**Every citation is pinned to a version and was checked against the document**, not
recalled:

- CIS Microsoft Windows Server 2022 Benchmark **v5.1.0**
- CIS Microsoft Windows Server 2022 STIG Benchmark **v2.0.0**
- CIS Red Hat Enterprise Linux 9 Benchmark **v2.0.0**

**Four controls have no CIS equivalent and say so** rather than borrowing a
plausible-looking number. Local Administrators review and Remote Registry are
organizational controls; BitLocker maps to a section CIS ships unmapped; patch
recency is an operational metric answering to `NIST SI-2`, not a benchmark item.
They're real controls worth checking — they're just not CIS's, and the reference
field states that plainly.

**NIST tags are mapped by control intent**, not lifted from a published CIS→NIST
crosswalk. The families (`AC`, `AU`, `CM`, `IA`, `SC`, `SI`) match the ones CIS
uses for the same controls, but treat them as informed mappings rather than
authoritative ones.

## Control coverage

### Windows Server 2022 (scope: member server)

| ID | Control | Level | Scored | Severity | NIST 800-53R5 | Benchmark reference |
|---|---|---|---|---|---|---|
| `WIN-SMB1` | SMBv1 disabled | 1 | scored | critical | CM-7 | CIS Win2022 v5.1.0 §18.4.3 |
| `WIN-FIREWALL` | Windows Firewall on all profiles | 1 | scored | high | SC-7 | CIS Win2022 v5.1.0 §9.1.1, §9.2.1, §9.3.1 |
| `WIN-LOCAL-ADMINS` | Local Administrators membership | 1 | notscored | high | AC-6 | *org-defined* |
| `WIN-GUEST` | Guest account disabled | 1 | scored | high | AC-2 | CIS Win2022 v5.1.0 §2.3.1.1 |
| `WIN-PW-MINLEN` | Minimum password length (14+) | 1 | scored | high | IA-5_1_a | CIS Win2022 v5.1.0 §1.1.4 |
| `WIN-PW-COMPLEX` | Password complexity enabled | 1 | scored | high | IA-5_1_a | CIS Win2022 v5.1.0 §1.1.5 |
| `WIN-RDP-NLA` | RDP requires Network Level Authentication | 1 | scored | high | IA-2 | CIS Win2022 v5.1.0 §18.10.57.3.9.4 |
| `WIN-AUDIT-LOGON` | Audit logging for logon events (success and failure) | 1 | scored | medium | AU-2 | CIS Win2022 v5.1.0 §17.5.4 |
| `WIN-BITLOCKER` | BitLocker enabled on the OS volume | 1 | notscored | medium | SC-28 | *org-defined* |
| `WIN-LEGACY-SVC` | Legacy services disabled (Telnet, Remote Registry) | 1 | scored | medium | CM-7 | CIS Win2022 STIG v2.0.0 §20.62 (Telnet Client) |
| `WIN-PATCH-AGE` | Patch recency (last update within 35 days) | 1 | scored | high | SI-2 | *org-defined* |

### RHEL 9

| ID | Control | Level | Scored | Severity | NIST 800-53R5 | Benchmark reference |
|---|---|---|---|---|---|---|
| `LNX-SSH-ROOT` | root SSH login disabled | 1 | scored | high | AC-6_2 | CIS RHEL9 v2.0.0 §5.1.20 |
| `LNX-SSH-PASSAUTH` | SSH password authentication disabled (key-only) | 1 | scored | high | IA-5_2 | CIS RHEL9 v2.0.0 §5.1.22 |
| `LNX-FIREWALL` | host firewall active | 1 | scored | high | SC-7 | CIS RHEL9 v2.0.0 §4.2 |
| `LNX-PASSWD-PERMS` | /etc/passwd permissions (<= 0644) | 1 | scored | medium | AC-3 | CIS RHEL9 v2.0.0 §7.1.1 |
| `LNX-SHADOW-PERMS` | /etc/shadow permissions (<= 0640) | 1 | scored | medium | AC-3 | CIS RHEL9 v2.0.0 §7.1.5 |
| `LNX-WORLD-WRITE` | No world-writable files | 2 | scored | medium | AC-3 | CIS RHEL9 v2.0.0 §7.1.11 |
| `LNX-SUID-AUDIT` | SUID/SGID binary audit | 2 | notscored | medium | CM-7 | CIS RHEL9 v2.0.0 §7.1.13 |
| `LNX-LEGACY-PKGS` | Legacy services not installed (telnet, rsh, ftp) | 1 | scored | high | CM-7 | CIS RHEL9 v2.0.0 §2.1.15 |
| `LNX-PW-MINLEN` | Password policy (minlen 14+) | 1 | scored | high | IA-5_1_a | CIS RHEL9 v2.0.0 §5.3.3.2.2 |
| `LNX-SUDO-NOPASSWD` | Sudoers audit (no NOPASSWD:ALL) | 1 | scored | high | AC-6_5 | CIS RHEL9 v2.0.0 §5.2.5 |
| `LNX-AUDIT-LOG` | auditd and rsyslog running | 1 | scored | medium | AU-2 | CIS RHEL9 v2.0.0 §6.3.1.4 (auditd) |
| `LNX-PATCH-AGE` | Patch recency (last update within 35 days) | 1 | scored | high | SI-2 | CIS RHEL9 v2.0.0 §1.2.2.1 |

## Lab setup

Two EC2 instances in a security group locked to a single operator IP.

```bash
terraform init
terraform apply -var="my_ip=$(curl -4 -s ifconfig.me)/32" -var="key_name=<your-keypair>"
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

## Waivers (documented risk acceptance)

Without a way to record "known, accepted, not fixing," a compliance tool produces
alert fatigue — the same finding shouts every run until people stop reading the
output. `exceptions.yml` records those decisions:

```yaml
waivers:
  - check_id: WIN-BITLOCKER
    reason: no unattended fix on a running instance; EBS encryption compensates
    owner: a.araia
    ticket: CHG-1042
    expires: 2026-10-31
```

Four rules keep this from becoming a way to hide problems:

- **Expiry is mandatory.** A waiver with no end date is how an accepted risk
  becomes a forgotten one. Entries without a valid `expires` are rejected and
  reported, not silently ignored. When one expires the finding comes back and the
  scan says so by name.
- **Only a FAIL can be waived.** Waiving a WARN would mean accepting a risk
  nobody measured — the control was never verified, so there is nothing to
  accept. Attempts are reported.
- **A waived finding is still reported.** It leaves the score's denominator and
  is counted separately; it never disappears from the output.
- **Waived controls are never remediated**, since silently fixing an accepted
  risk overrules a documented decision.

Waivers naming controls that no longer exist are flagged as stale.

## Scan history and dashboard

Every scan is stored in SQLite (`reports/scans.db`) through parameterized
queries. A re-scan of the same target automatically prints the delta:

```
[*] compared to previous scan (20260814_023731):
    score: 56% -> 100%  (+44)
    WIN-SMB1       SMBv1 disabled            FAIL -> PASS
    WIN-BITLOCKER      BitLocker on OS volume    FAIL -> FAIL  (unchanged)
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
