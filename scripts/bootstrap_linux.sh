#!/usr/bin/env bash
# Run once on the RHEL host as ec2-user (or root).
# Creates the scanner account with sudo limited to the exact read-only commands
# the scanner runs — no blanket NOPASSWD:ALL.
# Usage:  sudo ./bootstrap_linux.sh "ssh-ed25519 AAAA... operator@mac"

set -euo pipefail

PUBKEY="${1:?usage: bootstrap_linux.sh '<ssh public key>'}"
ACCOUNT="${ACCOUNT:-svc-hardening-scanner}"

if ! id "$ACCOUNT" &>/dev/null; then
    useradd --system --create-home --shell /bin/bash "$ACCOUNT"
fi

# key-based auth only, no password is ever set on this account
install -d -m 0700 -o "$ACCOUNT" -g "$ACCOUNT" "/home/$ACCOUNT/.ssh"
echo "$PUBKEY" > "/home/$ACCOUNT/.ssh/authorized_keys"
chmod 0600 "/home/$ACCOUNT/.ssh/authorized_keys"
chown "$ACCOUNT:$ACCOUNT" "/home/$ACCOUNT/.ssh/authorized_keys"
passwd --lock "$ACCOUNT" >/dev/null

# root-owned helper; the account gets sudo on its fixed verbs, never on find or
# grep directly
HELPER=/usr/local/sbin/hardening-scan-helper
install -m 0755 -o root -g root "$(dirname "$0")/hardening_scan_helper.sh" "$HELPER"

# no wildcards: each entry is an exact command line, so no extra arguments
# (-exec, -o, a different path) can be smuggled in
cat > "/etc/sudoers.d/$ACCOUNT" <<EOF
Cmnd_Alias SCAN_READ = $HELPER world-writable, \\
                       $HELPER suid, \\
                       $HELPER sudoers

$ACCOUNT ALL=(root) NOPASSWD: SCAN_READ
EOF
chmod 0440 "/etc/sudoers.d/$ACCOUNT"
visudo -cf "/etc/sudoers.d/$ACCOUNT"

echo "[*] account $ACCOUNT created, sudo scoped to read-only scan commands"
echo ""
echo "set these on the scanning machine:"
echo "  export SSH_USER='$ACCOUNT'"
echo "  export SSH_KEY=~/.ssh/<the matching private key>"
