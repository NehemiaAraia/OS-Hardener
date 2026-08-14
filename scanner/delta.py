"""Compare a scan against the previous scan of the same target.

This is what turns a static report into evidence that remediation worked, so it
reports honestly in both directions: controls that regressed are listed the same
as controls that improved, and a score that moved only because coverage changed
is called out rather than presented as a real gain."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Change:
    check_id: str
    title: str
    before: str
    after: str

    @property
    def improved(self) -> bool:
        return self.after == "PASS" and self.before != "PASS"

    @property
    def regressed(self) -> bool:
        return self.before == "PASS" and self.after != "PASS"


@dataclass
class Delta:
    previous_timestamp: str
    score_before: int
    score_after: int
    coverage_before: int
    coverage_after: int
    changes: list[Change]
    unchanged_failures: list[Change]

    @property
    def score_change(self) -> int:
        return self.score_after - self.score_before

    @property
    def coverage_changed(self) -> bool:
        return self.coverage_before != self.coverage_after


def compute(store, scan_id: int, platform: str, host: str) -> Delta | None:
    """None when there's no earlier scan of this target to compare against."""
    previous = store.previous_scan(platform, host, scan_id)
    if previous is None:
        return None

    before = store.results_for(previous["id"])
    after = store.results_for(scan_id)

    changes, unchanged_failures = [], []
    for check_id, now in after.items():
        was = before.get(check_id)
        if was is None:
            continue  # new control, nothing to compare it to
        change = Change(check_id, now["title"], was["status"], now["status"])
        if was["status"] != now["status"]:
            changes.append(change)
        elif now["status"] != "PASS":
            unchanged_failures.append(change)

    changes.sort(key=lambda c: (not c.regressed, c.check_id))
    unchanged_failures.sort(key=lambda c: c.check_id)

    return Delta(
        previous_timestamp=previous["timestamp"],
        score_before=previous["score"],
        score_after=store.scan(scan_id)["score"],
        coverage_before=previous["coverage"],
        coverage_after=store.scan(scan_id)["coverage"],
        changes=changes,
        unchanged_failures=unchanged_failures,
    )
