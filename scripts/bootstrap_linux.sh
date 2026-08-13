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

# only the commands the scanner actually needs, all read-only
cat > "/etc/sudoers.d/$ACCOUNT" <<EOF
Cmnd_Alias SCAN_READ = /usr/bin/stat -c %a /etc/shadow, \\
                       /usr/bin/stat -c %a /etc/passwd, \\
                       /usr/bin/find / -xdev -type f -perm -0002 *, \\
                       /usr/bin/find / -xdev -type f -perm /6000 *, \\
                       /usr/bin/grep -rEc * /etc/sudoers /etc/sudoers.d/

$ACCOUNT ALL=(root) NOPASSWD: SCAN_READ
EOF
chmod 0440 "/etc/sudoers.d/$ACCOUNT"
visudo -cf "/etc/sudoers.d/$ACCOUNT"

echo "[*] account $ACCOUNT created, sudo scoped to read-only scan commands"
echo ""
echo "set these on the scanning machine:"
echo "  export SSH_USER='$ACCOUNT'"
echo "  export SSH_KEY=~/.ssh/<the matching private key>"
