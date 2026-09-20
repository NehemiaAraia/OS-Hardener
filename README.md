# OS Hardening Platform

A cross-platform compliance scanner that audits Windows Server and RHEL against CIS
benchmarks, scores only what it can actually verify, and remediates the gaps through
Ansible, reporting what it refuses to touch and why.

**What it actually does:**

- Scans Windows Server 2022 over WinRM and RHEL 9 over SSH from one codebase
- Reports PASS, FAIL, or WARN. Never a pass for anything it could not verify
- Tags every control to a CIS benchmark section and a NIST 800-53 control
- Remediates through Ansible on both platforms, dry-run by default, and names the controls it will not fix

**Example:** scans a stock Windows Server 2022 at 17% compliance. SMBv1 enabled, firewall
off, Guest account active. Fixes five of them through Ansible and reaches 100%, then reports
that three others could not be verified at all, because the scanning account deliberately
lacks the rights to read them.

## Live Demo

<!-- recording -->

## Tech stack

| Layer | Tech |
|---|---|
| Language | Python 3.11+ |
| Rule format | YAML, modeled on Wazuh SCA (`policy` / `requirements` / `checks`) |
| Connections | pywinrm (WinRM over HTTPS), paramiko (SSH) |
| Remediation | Ansible, `ansible.windows` collection |
| Storage | SQLite, parameterized queries |
| Reporting | Jinja2 (autoescaped) → HTML + JSON |
| Dashboard | Flask, basic auth over HTTPS |
| Infra | Terraform, AWS EC2 |
| CI | GitHub Actions, ruff, Bandit, gitleaks, pytest |
| Benchmarks | CIS Windows Server 2022 v5.1.0, CIS RHEL 9 v2.0.0, CIS STIG v2.0.0 |

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│              Target hosts (least privilege)              │
│    svc-hardening-scanner: read-only, cannot remediate    │
└──────────────────────────────────────────────────────────┘
                    │                    │
              WinRM │                    │ SSH
                    ▼                    ▼
┌──────────────────────────────────────────────────────────┐
│                      Scanner engine                      │
│    parser → executor → evaluator → scoring → reporter    │
│          identical code path for both platforms          │
└──────────────────────────────────────────────────────────┘
                    │                    │
        ┌───────────┘                    └───────────┐
        ▼                                            ▼
┌────────────────────────┐              ┌──────────────────────────┐
│    SQLite + reports    │              │       Remediation        │
│  history, before/after │              │  Ansible, both platforms │
│    delta, dashboard    │              │    dry-run by default    │
└────────────────────────┘              └──────────────────────────┘
```

## How it works

- **Rules** (`rules/`): YAML per platform, typed sub-rules (`r:` registry, `f:` file,
  `cmd:` command, `svc:` service, `perm:` file mode) combined with `all` / `any` / `none`
- **Engine** (`scanner/`): `parser` loads rules, `executor` turns each sub-rule into a
  probe, `evaluator` applies matchers and resolves status, `scoring` computes score and
  coverage, `reporter` renders HTML and JSON
- **Connections** (`scanner/connection/`): WinRM, SSH, and a fixture backend that replays
  recorded output so the full pipeline runs offline in CI
- **Remediation** (`scanner/remediation/`, `playbooks/`): one Ansible invocation per run,
  scoped by tag to the controls a scan just found failing
- **Waivers** (`exceptions.yml`): documented risk acceptance with mandatory expiry

Design tradeoffs are in [`DECISIONS.md`](DECISIONS.md). Lab setup is in
[`docs/runbook.md`](docs/runbook.md).

## Security model

- The scanning account is read-only and cannot remediate. Remote Management Users on
  Windows, four fixed sudo verbs on Linux, no `NOPASSWD: ALL`. Applying fixes takes
  separate credentials
- Nothing it could not verify is reported as compliant. Unreadable, unreachable, and
  unparseable all resolve to WARN
- Every score carries its coverage: `100% (verified 6/9 scored controls)` is a different
  claim from `100% (verified 9/9)`
- Remediation is dry-run by default, needs explicit confirmation, refuses to run
  non-interactively, and logs every action
- Controls with no safe automated fix are named in the output rather than skipped
- WinRM runs over HTTPS with certificate validation on by default; the cleartext listener
  is removed at bootstrap

## Control coverage

### Windows Server 2022

| ID | Control | Scored | NIST | Benchmark |
|---|---|---|---|---|
| `WIN-SMB1` | SMBv1 disabled | scored | CM-7 | CIS v5.1.0 §18.4.3 |
| `WIN-FIREWALL` | Firewall on all profiles | scored | SC-7 | CIS v5.1.0 §9.1.1 |
| `WIN-GUEST` | Guest account disabled | scored | AC-2 | CIS v5.1.0 §2.3.1.1 |
| `WIN-PW-MINLEN` | Minimum password length | scored | IA-5_1_a | CIS v5.1.0 §1.1.4 |
| `WIN-PW-COMPLEX` | Password complexity | scored | IA-5_1_a | CIS v5.1.0 §1.1.5 |
| `WIN-RDP-NLA` | RDP requires NLA | scored | IA-2 | CIS v5.1.0 §18.10.57.3.9.4 |
| `WIN-AUDIT-LOGON` | Logon auditing | scored | AU-2 | CIS v5.1.0 §17.5.4 |
| `WIN-LEGACY-SVC` | Telnet / Remote Registry | scored | CM-7 | CIS STIG v2.0.0 §20.62 |
| `WIN-PATCH-AGE` | Patch recency | scored | SI-2 | org-defined |
| `WIN-LOCAL-ADMINS` | Local Administrators | notscored | AC-6 | org-defined |
| `WIN-BITLOCKER` | BitLocker on OS volume | notscored | SC-28 | org-defined |

### RHEL 9

| ID | Control | Scored | NIST | Benchmark |
|---|---|---|---|---|
| `LNX-SSH-ROOT` | root SSH login disabled | scored | AC-6_2 | CIS v2.0.0 §5.1.20 |
| `LNX-SSH-PASSAUTH` | Key-only auth | scored | IA-5_2 | CIS v2.0.0 §5.1.22 |
| `LNX-FIREWALL` | Host firewall active | scored | SC-7 | CIS v2.0.0 §4.2 |
| `LNX-PASSWD-PERMS` | `/etc/passwd` permissions | scored | AC-3 | CIS v2.0.0 §7.1.1 |
| `LNX-SHADOW-PERMS` | `/etc/shadow` permissions | scored | AC-3 | CIS v2.0.0 §7.1.5 |
| `LNX-WORLD-WRITE` | No world-writable files | scored | AC-3 | CIS v2.0.0 §7.1.11 |
| `LNX-LEGACY-PKGS` | telnet / rsh / ftp absent | scored | CM-7 | CIS v2.0.0 §2.1.15 |
| `LNX-PW-MINLEN` | Password policy | scored | IA-5_1_a | CIS v2.0.0 §5.3.3.2.2 |
| `LNX-SUDO-NOPASSWD` | No `NOPASSWD: ALL` | scored | AC-6_5 | CIS v2.0.0 §5.2.5 |
| `LNX-AUDIT-LOG` | auditd and rsyslog | scored | AU-2 | CIS v2.0.0 §6.3.1.4 |
| `LNX-PATCH-AGE` | Patch recency | scored | SI-2 | CIS v2.0.0 §1.2.2.1 |
| `LNX-SUID-AUDIT` | SUID/SGID inventory | notscored | CM-7 | CIS v2.0.0 §7.1.13 |

Control IDs are internal identifiers, not citations. CIS renumbers between releases, so
each rule's `references` field carries the section pinned to a benchmark version.

## Installation

```bash
git clone https://github.com/NehemiaAraia/OS-Hardener.git
cd OS-Hardener
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Lab infrastructure is two EC2 instances behind a security group locked to one IP:

```bash
terraform init
terraform apply -var="my_ip=$(curl -4 -s ifconfig.me)/32" \
  -var="key_name=<ed25519-keypair>" -var="windows_key_name=<rsa-keypair>"
```

Then run the bootstrap script once per host to create the scanning account. Full setup in
[`docs/runbook.md`](docs/runbook.md).

## Usage

Scan:

```bash
export SSH_USER=svc-hardening-scanner SSH_KEY=~/.ssh/id_ed25519
python main.py scan --target linux --host <ip>
```

Remediate, dry-run first:

```bash
python main.py remediate --target linux --host <ip> --dry-run
python main.py remediate --target linux --host <ip> --apply
```

Re-scanning a host prints the delta against its previous run. Every scan writes an HTML
report and JSON to `reports/`, and the history is browsable:

```bash
export DASHBOARD_USER=admin DASHBOARD_PASS=<pick one>
python dashboard.py
```

Develop without a live host using recorded fixtures:

```bash
python main.py scan --target linux --fixture linux/baseline
pytest
```
