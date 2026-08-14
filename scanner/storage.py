"""SQLite store for scan history. Every query is parameterized — no string
interpolation reaches SQL, including the values that come off scanned hosts."""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Optional

from .model import CheckResult

DEFAULT_DB = "reports/scans.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    platform        TEXT NOT NULL,
    host            TEXT NOT NULL,
    timestamp       TEXT NOT NULL,
    score           INTEGER NOT NULL,
    coverage        INTEGER NOT NULL,
    pass_count      INTEGER NOT NULL,
    fail_count      INTEGER NOT NULL,
    warn_count      INTEGER NOT NULL,
    scored_total    INTEGER NOT NULL,
    scored_defined  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS results (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id   INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    check_id  TEXT NOT NULL,
    title     TEXT NOT NULL,
    status    TEXT NOT NULL,
    severity  TEXT NOT NULL,
    level     TEXT NOT NULL,
    scored    TEXT NOT NULL,
    nist      TEXT NOT NULL,
    message   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_results_scan ON results(scan_id);
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(platform, host, id);
"""


class Store:
    def __init__(self, path: str | Path = DEFAULT_DB):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.executescript(_SCHEMA)

    def close(self) -> None:
        self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def save_scan(self, results: list[CheckResult], summary: dict, meta: dict) -> int:
        cur = self._conn.execute(
            """INSERT INTO scans
               (platform, host, timestamp, score, coverage, pass_count, fail_count,
                warn_count, scored_total, scored_defined)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                meta["platform"], meta["host"], meta["timestamp"],
                summary["score"], summary["coverage"], summary["pass"],
                summary["fail"], summary["warn"], summary["scored_total"],
                summary["scored_defined"],
            ),
        )
        scan_id = cur.lastrowid
        self._conn.executemany(
            """INSERT INTO results
               (scan_id, check_id, title, status, severity, level, scored, nist, message)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                (scan_id, r.check.id, r.check.title, r.status.value, r.check.severity,
                 r.check.level, r.check.scored, r.check.nist, self.message_of(r))
                for r in results
            ],
        )
        self._conn.commit()
        return scan_id

    @staticmethod
    def message_of(result: CheckResult) -> str:
        return result.message

    def previous_scan(self, platform: str, host: str, before_id: int) -> Optional[sqlite3.Row]:
        """Most recent scan of the same target before the given one."""
        cur = self._conn.execute(
            """SELECT * FROM scans
               WHERE platform = ? AND host = ? AND id < ?
               ORDER BY id DESC LIMIT 1""",
            (platform, host, before_id),
        )
        return cur.fetchone()

    def results_for(self, scan_id: int) -> dict[str, sqlite3.Row]:
        cur = self._conn.execute(
            "SELECT * FROM results WHERE scan_id = ?", (scan_id,)
        )
        return {row["check_id"]: row for row in cur.fetchall()}

    def recent_scans(self, limit: int = 50) -> list[sqlite3.Row]:
        cur = self._conn.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
        )
        return cur.fetchall()

    def scan(self, scan_id: int) -> Optional[sqlite3.Row]:
        cur = self._conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        return cur.fetchone()
