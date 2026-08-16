#!/usr/bin/env bash
# LAB ONLY — this WEAKENS the machine it runs on.
#
# A fresh RHEL AMI already passes several controls, so a before/after demo has
# nothing to show. This reverts a handful of settings to a realistic unhardened
# state so remediation has real work to do.
#
# This must never run anywhere but a throwaway lab instance. It refuses unless
# you both set I_UNDERSTAND_THIS_WEAKENS_THIS_HOST=yes and confirm at the prompt.
#
#   sudo I_UNDERSTAND_THIS_WEAKENS_THIS_HOST=yes ./lab_reset_linux.sh

set -euo pipefail

if [[ "${I_UNDERSTAND_THIS_WEAKENS_THIS_HOST:-}" != "yes" ]]; then
    cat >&2 <<'EOF'
refusing to run.

This script deliberately weakens security settings so the hardening demo has
failing controls to fix. It is only appropriate on a disposable lab VM.

To proceed:
  sudo I_UNDERSTAND_THIS_WEAKENS_THIS_HOST=yes ./lab_reset_linux.sh
EOF
    exit 1
fi

if [[ $EUID -ne 0 ]]; then
    echo "run with sudo" >&2
    exit 1
fi

# a cloud instance is the expected target; refuse if this looks like a real box
if [[ ! -f /sys/hypervisor/uuid && ! -d /sys/class/dmi/id ]]; then
    echo "cannot confirm this is a VM — refusing" >&2
    exit 1
fi

echo "host: $(hostname)  ($(hostname -I 2>/dev/null | awk '{print $1}'))"
read -rp "weaken THIS host for a hardening demo? type the hostname to confirm: " answer
if [[ "$answer" != "$(hostname)" ]]; then
    echo "hostname did not match, aborting" >&2
    exit 1
fi

# --fixable-only reverts just the controls remediation can repair, so a demo
# ends cleanly instead of trailing failures the tool was never going to fix
FIXABLE_ONLY=0
[[ "${2:-}" == "--fixable-only" || "${1:-}" == "--fixable-only" ]] && FIXABLE_ONLY=1

echo "[*] reverting SSH hardening..."
# password auth stays ON so key login still works and the control fails again
sed -i 's/^\s*PermitRootLogin.*/PermitRootLogin yes/'          /etc/ssh/sshd_config
sed -i 's/^\s*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
grep -q '^PermitRootLogin'      /etc/ssh/sshd_config || echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config
grep -q '^PasswordAuthentication' /etc/ssh/sshd_config || echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config
sshd -t && systemctl reload sshd

echo "[*] stopping the firewall..."
systemctl disable --now firewalld 2>/dev/null || true

if [[ $FIXABLE_ONLY -eq 0 ]]; then
    echo "[*] creating a world-writable file..."
    install -d -m 0755 /opt/lab
    touch /opt/lab/scratch.sh && chmod 0666 /opt/lab/scratch.sh

    echo "[*] stopping rsyslog..."
    systemctl disable --now rsyslog 2>/dev/null || true

    echo "[*] clearing the password policy..."
    sed -i '/^\s*minlen/d' /etc/security/pwquality.conf 2>/dev/null || true
else
    echo "[*] --fixable-only: leaving rsyslog, file permissions and password policy alone"
fi

cat <<'EOF'

[*] done. this host is now deliberately non-compliant.

    verify:  python main.py scan --target linux --host <ip>
    restore: python main.py remediate --target linux --host <ip> --apply

    note: LNX-2.2.1 (legacy packages) is left alone on purpose — installing
    telnet-server just to fail a control is not worth the cleanup.
EOF
