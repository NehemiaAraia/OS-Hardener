"""Input validation for values that reach a connection or a subprocess."""
from __future__ import annotations

import re

# hostnames, IPv4, or bracketed IPv6 — deliberately strict
_HOST_RE = re.compile(r"^(?:\[[0-9a-fA-F:]+\]|[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?)$")


def valid_host(host: str) -> bool:
    return bool(host) and bool(_HOST_RE.match(host))


def check_host(host: str) -> str:
    """Reject anything that isn't a plain host. A comma matters more than it
    looks: Ansible's inline inventory is '<host>,' so an unchecked comma would
    quietly extend remediation to machines that were never named."""
    if not valid_host(host):
        raise ValueError(
            f"invalid host {host!r} — expected a hostname or IP with no separators"
        )
    return host
