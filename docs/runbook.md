# Live bring-up runbook

Standing the lab up from scratch: provisioning, bootstrapping both hosts, and the
first live scan. Covers what "working" looks like at each step and where it is most
likely to break.

Budget 2 to 3 hours for a first run.

---

## 0. Prerequisites

```bash
aws sts get-caller-identity          # credentials configured
terraform version                    # >= 1.5
ansible-playbook --version           # only needed for Linux remediation
python3 --version                    # 3.11+
```

An EC2 key pair must already exist in the target region, Terraform references it
by name, it does not create one:

```bash
ssh-keygen -t ed25519 -C "hardening-lab" -f ~/.ssh/hardening_lab -N ""
aws ec2 import-key-pair --key-name hardening-lab \
  --public-key-material fileb://$HOME/.ssh/hardening_lab.pub
```

`curl -4` is not optional in the next step. On an IPv6-capable connection a plain
`curl ifconfig.me` returns an IPv6 address, which `cidr_blocks` rejects, the
apply fails on an invalid CIDR.

---

## 1. Provision

```bash
terraform init
terraform apply \
  -var="my_ip=$(curl -4 -s ifconfig.me)/32" \
  -var="key_name=<ed25519-keypair>" \
  -var="windows_key_name=<rsa-keypair>"
```

Windows AMIs reject ED25519 keys and the admin password is RSA-encrypted, so the
two hosts need separate key pairs.

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

No RDP needed. `user_data` brings up the WinRM listener at first boot, so the
bootstrap runs remotely:

```bash
aws ec2 get-password-data --instance-id <id> --priv-launch-key <rsa-key-in-PEM>
export WINRM_USER=Administrator WINRM_PASS='<decrypted>'
python scripts/push_and_run.py <windows-ip> scripts/bootstrap_windows.ps1 \
  '-OperatorCidr <your-ip>/32'
```

The key must be in PEM format. `ssh-keygen` writes OpenSSH format by default,
which the AWS CLI cannot decrypt with.

**Expect:** account created, HTTPS listener on 5986, HTTP listener removed, and
`WINRM_USER` / `WINRM_PASS` printed **once**. Copy them immediately.

**Watch for:**
- `New-SelfSignedCertificate` needs an elevated session.
- The script is re-runnable, but a re-run **rotates the password**, recopy it.
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

Both scripts must be copied, the bootstrap installs the helper from its own
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

## 4. First live scan, the real milestone

```bash
export SSH_USER=svc-hardening-scanner SSH_KEY=~/.ssh/hardening_lab
python main.py scan --target linux --host <linux-ip>

export WINRM_USER=svc-hardening-scanner WINRM_PASS='<from step 2>'
python main.py scan --target windows --host <windows-ip> --insecure
```

`--insecure` is needed on the first Windows scan because the bootstrap generates
a self-signed certificate. Trust that cert on the Mac to drop the flag.

**Expect:** a mix of PASS/FAIL/WARN and a report in `reports/`.

Both platforms have been verified live, but a different image or locale can still
shift a probe's output. What to look for:

| Symptom | Cause | Fix |
|---|---|---|
| Everything WARN, `<unreachable>` | auth or firewall | check env vars, `nc -vz` the port |
| One control WARN, others fine | that probe's command is wrong on real output | run the command by hand over RDP/SSH, compare |
| `WIN-PW-COMPLEX` WARN | `secedit` export path or parsing | run the command manually, adjust the rule |
| `WIN-AUDIT-LOGON` WARN | `auditpol` output format differs by locale | adjust the regex |
| `LNX-PW-MINLEN` WARN | `pwquality.conf` has no `minlen` | that is a true finding, not a bug |
| Linux sudo controls WARN | helper not installed or sudoers wrong | re-check step 3 |

**A WARN is the tool working correctly**, it means "I could not verify this,"
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

Then apply. This needs **different credentials than scanning**, the scanner
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
  achieve the control, that gap is worth understanding, not papering over.

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

- [ ] Both instances running and reachable
- [ ] Reset to a failing baseline so the before/after is real, not a replay

**Resetting to a failing baseline** (so remediation has something to fix). These
scripts deliberately weaken the host and refuse to run without an explicit
acknowledgement plus a hostname confirmation, they are for disposable lab
instances only:

```bash
sudo I_UNDERSTAND_THIS_WEAKENS_THIS_HOST=yes ./scripts/lab_reset_linux.sh
```
```powershell
.\lab_reset_windows.ps1 -IUnderstandThisWeakensThisHost
```

The Linux script leaves password authentication **on** so your key login keeps
working while the control fails again. The Windows script does disable the
firewall, which is safe because the WinRM allow-rule created at bootstrap
survives it being re-enabled.

---

## 8. Shut down

```bash
terraform destroy    # or stop the instances from the console to keep state
```

Idle instances are the only part of this that costs real money.
