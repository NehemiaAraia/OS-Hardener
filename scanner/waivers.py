"""Documented risk acceptance. Expiry is mandatory, only a FAIL can be waived,
and a waived finding still appears in the report."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Optional

import yaml

DEFAULT_WAIVERS = "exceptions.yml"


@dataclass
class Waiver:
    check_id: str
    reason: str
    owner: str
    expires: date
    ticket: str = ""
    hosts: tuple[str, ...] = ("*",)

    def covers(self, host: str) -> bool:
        return "*" in self.hosts or host in self.hosts

    def active_on(self, today: date) -> bool:
        return today <= self.expires


@dataclass
class WaiverLoad:
    waivers: list[Waiver]
    problems: list[str]  # malformed entries, surfaced rather than swallowed


def load_waivers(path: str | Path = DEFAULT_WAIVERS) -> WaiverLoad:
    path = Path(path)
    if not path.exists():
        return WaiverLoad([], [])

    data = yaml.safe_load(path.read_text()) or {}
    entries = data.get("waivers") or []
    waivers, problems = [], []

    for i, e in enumerate(entries):
        label = e.get("check_id", f"entry {i + 1}")
        missing = [f for f in ("check_id", "reason", "owner", "expires") if not e.get(f)]
        if missing:
            problems.append(f"{label}: missing required field(s): {', '.join(missing)}")
            continue
        raw_expiry = e["expires"]
        expires = raw_expiry if isinstance(raw_expiry, date) else _parse_date(raw_expiry)
        if expires is None:
            problems.append(f"{label}: 'expires' is not a YYYY-MM-DD date: {raw_expiry!r}")
            continue
        hosts = e.get("hosts") or ["*"]
        waivers.append(
            Waiver(
                check_id=e["check_id"],
                reason=e["reason"],
                owner=e["owner"],
                expires=expires,
                ticket=e.get("ticket", ""),
                hosts=tuple(hosts),
            )
        )
    return WaiverLoad(waivers, problems)


def _parse_date(value) -> Optional[date]:
    try:
        return date.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None


def find(waivers: list[Waiver], check_id: str, host: str, today: date) -> Optional[Waiver]:
    """The applicable, unexpired waiver for a control on a host, if any."""
    for w in waivers:
        if w.check_id == check_id and w.covers(host) and w.active_on(today):
            return w
    return None


def expired_for(waivers: list[Waiver], check_id: str, host: str, today: date) -> Optional[Waiver]:
    """An expired waiver that would otherwise have matched — worth saying out
    loud, since the finding is about to come back and surprise someone."""
    for w in waivers:
        if w.check_id == check_id and w.covers(host) and not w.active_on(today):
            return w
    return None
