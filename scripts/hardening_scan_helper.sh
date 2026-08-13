#!/usr/bin/env bash
# Installed to /usr/local/sbin/hardening-scan-helper, root-owned, 0755.
# The scanner account is granted sudo on this script's fixed verbs only, so it
# never gets sudo on find/grep directly — a wildcarded 'sudo find' entry would
# allow -exec and hand out a root shell.
# Each verb prints a count or a list, and nothing at all on failure, so a
# permission problem surfaces as WARN rather than a fabricated zero.

set -uo pipefail

case "${1:-}" in
    world-writable)
        find / -xdev -type f -perm -0002 2>/dev/null | wc -l
        ;;
    suid)
        find / -xdev -type f -perm /6000 2>/dev/null | head -20
        ;;
    sudoers)
        grep -rhE '^[^#]*NOPASSWD:[[:space:]]*ALL' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | wc -l
        ;;
    *)
        echo "usage: $(basename "$0") world-writable|suid|sudoers" >&2
        exit 2
        ;;
esac
