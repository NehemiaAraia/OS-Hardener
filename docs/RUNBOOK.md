# Live bring-up runbook

Everything in this repo has been tested against recorded fixtures, never against
a real machine. This is the order to bring the lab up, what "working" looks like
at each step, and where it is most likely to break.

Budget 2–3 hours for a first run. Step 4 is the one that will surface bugs.

---

## 0. Prerequisites

```bash
aws sts get-caller-identity          # credentials configured
terraform version                    # >= 1.5
ansible-playbook --version           # only needed for Linux remediation
python3 --version                    # 3.11+
```

An EC2 key pair must already exist in the target region — Terraform references it
by name, it does not create one:

```bash
ssh-keygen -t ed25519 -C "hardening-lab" -f ~/.ssh/hardening_lab -N ""
aws ec2 import-key-pair --key-name hardening-lab \
  --public-key-material fileb://$HOME/.ssh/hardening_lab.pub
```

`curl -4` is not optional in the next step. On an IPv6-capable connection a plain
`curl ifconfig.me` returns an IPv6 address, which `cidr_blocks` rejects — the
apply fails on an invalid CIDR.

---

## 1. Provision

```bash
terraform init
terraform apply \
  -var="my_ip=$(curl -4 -s ifconfig.me)/32" \
  -var="key_name=<your-keypair>"
```

**Expect:** two instances and one security group; `windows_public_ip` and
`linux_public_ip` in the outputs.

**Watch for:**
- *"returned more than one result"* on an AMI lookup → tighten the name filter.
- The Windows instance needs ~4 minutes before its admin password is retrievable.
- `my_ip` changes if you switch networks. Re-apply after moving, or you'll lock
  yourself out.

**Cost:** two `t3.medium` instances. Stop them when not actively working.

---

## 2. Bootstrap the Windows host

RDP in as `Administrator` (decrypt the password with your key pair), copy
`scripts/bootstrap_windows.ps1` over, and run it in an elevated PowerShell:

```powershell
.\bootstrap_windows.ps1 -OperatorCidr <your-ip>/32
```

**Expect:** account created, HTTPS listener on 5986, HTTP listener removed, and
`WINRM_USER` / `WINRM_PASS` printed **once**. Copy them immediately.

**Watch for:**
- `New-SelfSignedCertificate` needs an elevated session.
- The script is re-runnable, but a re-run **rotates the password** — recopy it.
- Verify from the Mac before moving on:
  ```bash
  nc -vz <windows-ip> 5986     # should connect
  nc -vz <windows-ip> 5985     # should NOT connect
  ```

---

## 3. Bootstrap the Linux host

```bash
scp -i ~/.ssh/hardening_lab scripts/bootstrap_linux.sh scripts/hardening_scan_helper.sh ec2-user@<linux-ip>:~
ssh -i ~/.ssh/hardening_lab ec2-user@<linux-ip>
sudo ./bootstrap_linux.sh "$(cat ~/.ssh/hardening_lab.pub)"
```

Both scripts must be copied — the bootstrap installs the helper from its own
directory.

**Expect:** account created, sudoers file validated by `visudo -c`, helper
installed at `/usr/local/sbin/hardening-scan-helper`.

**Verify the least-privilege claim actually holds:**
```bash
sudo -u svc-hardening-scanner sudo -n /usr/local/sbin/hardening-scan-helper sudoers   # works
sudo -u svc-hardening-scanner sudo -n /bin/cat /etc/shadow                            # must be denied
```
The second command failing is the whole point. If it succeeds, the sudoers scope
is wrong.

---

## 4. First live scan — the real milestone

```bash
export SSH_USER=svc-hardening-scanner SSH_KEY=~/.ssh/hardening_lab
python main.py scan --target linux --host <linux-ip>

export WINRM_USER=svc-hardening-scanner WINRM_PASS='<from step 2>'
python main.py scan --target windows --host <windows-ip> --insecure
```

`--insecure` is needed on the first Windows scan because the bootstrap generates
a self-signed certificate. Trust that cert on the Mac to drop the flag.

**Expect:** a mix of PASS/FAIL/WARN and a report in `reports/`.

**Expect breakage here.** Every probe command was written without a live host to
test against. The likely failures, in order:

| Symptom | Cause | Fix |
|---|---|---|
| Everything WARN, `<unreachable>` | auth or firewall | check env vars, `nc -vz` the port |
| One control WARN, others fine | that probe's command is wrong on real output | run the command by hand over RDP/SSH, compare |
| `WIN-PW-COMPLEX` WARN | `secedit` export path or parsing | run the command manually, adjust the rule |
| `WIN-AUDIT-LOGON` WARN | `auditpol` output format differs by locale | adjust the regex |
| `LNX-PW-MINLEN` WARN | `pwquality.conf` has no `minlen` | that is a true finding, not a bug |
| Linux sudo controls WARN | helper not installed or sudoers wrong | re-check step 3 |

**A WARN is the tool working correctly** — it means "I could not verify this,"
not "this is broken." Only investigate WARNs that should have been verifiable.

When a probe needs fixing, change the rule file, then:
```bash
python tests/gen_fixtures.py && pytest -q
```
so the recorded fixtures follow the rules rather than drifting from them.

---

## 5. Remediation loop

Dry run first, on both platforms:

```bash
python main.py remediate --target linux   --host <linux-ip> --dry-run
python main.py remediate --target windows --host <windows-ip> --dry-run
```

Then apply. This needs **different credentials than scanning** — the scanner
account is read-only by design and cannot make changes:

```bash
export REMEDIATE_SSH_USER=ec2-user REMEDIATE_SSH_KEY=~/.ssh/hardening_lab
python main.py remediate --target linux --host <linux-ip> --apply

export WINRM_ADMIN_USER=Administrator WINRM_ADMIN_PASS='<admin password>'
python main.py remediate --target windows --host <windows-ip> --apply --insecure
```

**Danger:** the Linux playbook disables SSH password authentication and root
login. Confirm your key-based login works in a **second terminal** before
applying, and keep that session open until you've verified you can reconnect.

**Watch for:**
- SMBv1 removal flags a reboot. The scanner reports it; it does not reboot.
- If a fix reports APPLY but the re-scan still says FAIL, the fix ran but did not
  achieve the control — that gap is worth understanding, not papering over.

---

## 6. Verify and capture the delta

```bash
python main.py scan --target linux   --host <linux-ip>
python main.py scan --target windows --host <windows-ip> --insecure
```

**Expect** the delta block comparing against the previous scan. This is the
clearest evidence the remediation worked.

```bash
export DASHBOARD_USER=admin DASHBOARD_PASS='<pick one>'
python dashboard.py            # https://127.0.0.1:8443
```

---

## 7. Resetting for another run

- [ ] Both instances running, RDP and SSH already connected
- [ ] Reset to a failing baseline so the before/after is real, not a replay

**Resetting to a failing baseline** (so remediation has something to fix). These
scripts deliberately weaken the host and refuse to run without an explicit
acknowledgement plus a hostname confirmation — they are for disposable lab
instances only:

```bash
sudo I_UNDERSTAND_THIS_WEAKENS_THIS_HOST=yes ./scripts/lab_reset_linux.sh
```
```powershell
.\lab_reset_windows.ps1 -IUnderstandThisWeakensThisHost
```

The Linux script leaves password authentication **on** so your key login keeps
working while the control fails again, and the Windows script leaves the
firewall **enabled** — turning it off on an instance you reach over the network
is how you lose access to the host.

---

## 8. Shut down

```bash
terraform destroy    # or stop the instances from the console to keep state
```

Idle instances are the only part of this that costs real money.
