from __future__ import annotations

import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner import waivers as w  # noqa: E402
from scanner.connection import make_connection  # noqa: E402
from scanner.model import Status  # noqa: E402
from scanner.remediation import base as rem  # noqa: E402
from scanner.remediation import windows as rem_win  # noqa: E402
from scanner.scanner import run_scan  # noqa: E402

TODAY = date(2026, 8, 14)
LATER = date(2027, 1, 1)


def write_waivers(tmp_path, body: str) -> Path:
    p = tmp_path / "exceptions.yml"
    p.write_text(body)
    return p


def scan_with(waiver_list, scenario="windows/baseline", today=TODAY, host="10.0.0.5"):
    conn = make_connection("fixture", scenario=scenario)
    platform = scenario.split("/")[0]
    results, summary, notes = run_scan(
        platform, conn, ROOT / "rules", waiver_list=waiver_list, host=host, today=today
    )
    return {r.check.id: r for r in results}, summary, notes


VALID = """
waivers:
  - check_id: WIN-SMB1
    reason: legacy line control system needs SMBv1 until Q4 replacement
    owner: a.araia
    ticket: CHG-1042
    expires: 2026-12-31
"""


# --- loading -----------------------------------------------------------------

def test_loads_a_valid_waiver(tmp_path):
    load = w.load_waivers(write_waivers(tmp_path, VALID))
    assert not load.problems
    assert load.waivers[0].check_id == "WIN-SMB1"


def test_missing_file_is_not_an_error(tmp_path):
    load = w.load_waivers(tmp_path / "nope.yml")
    assert load.waivers == [] and load.problems == []


def test_waiver_without_expiry_is_rejected(tmp_path):
    """A permanent waiver is how an accepted risk becomes a forgotten one."""
    load = w.load_waivers(write_waivers(tmp_path, """
waivers:
  - check_id: WIN-SMB1
    reason: because
    owner: a.araia
"""))
    assert load.waivers == []
    assert "expires" in load.problems[0]


def test_waiver_without_owner_or_reason_is_rejected(tmp_path):
    load = w.load_waivers(write_waivers(tmp_path, """
waivers:
  - check_id: WIN-SMB1
    expires: 2026-12-31
"""))
    assert load.waivers == []
    assert "reason" in load.problems[0] and "owner" in load.problems[0]


def test_unparseable_expiry_is_rejected_not_assumed(tmp_path):
    load = w.load_waivers(write_waivers(tmp_path, """
waivers:
  - check_id: WIN-SMB1
    reason: because
    owner: a.araia
    expires: "whenever"
"""))
    assert load.waivers == []
    assert "not a YYYY-MM-DD date" in load.problems[0]


# --- application -------------------------------------------------------------

def test_waiver_marks_the_finding_without_hiding_it(tmp_path):
    waivers = w.load_waivers(write_waivers(tmp_path, VALID)).waivers
    r, summary, _ = scan_with(waivers)
    smb = r["WIN-SMB1"]
    assert smb.status is Status.FAIL       # still reported as failing
    assert smb.waived is True
    assert summary["waived"] == 1


def test_waiver_removes_the_control_from_the_score(tmp_path):
    waivers = w.load_waivers(write_waivers(tmp_path, VALID)).waivers
    _, before, _ = scan_with([])
    _, after, _ = scan_with(waivers)
    assert after["scored_defined"] == before["scored_defined"] - 1
    assert after["score"] > before["score"]


def test_expired_waiver_stops_applying(tmp_path):
    waivers = w.load_waivers(write_waivers(tmp_path, VALID)).waivers
    r, summary, notes = scan_with(waivers, today=LATER)
    assert r["WIN-SMB1"].waived is False
    assert summary["waived"] == 0
    assert any("expired" in n for n in notes)


def test_waiver_scoped_to_another_host_does_not_apply(tmp_path):
    waivers = w.load_waivers(write_waivers(tmp_path, """
waivers:
  - check_id: WIN-SMB1
    reason: scoped to one machine only
    owner: a.araia
    expires: 2026-12-31
    hosts: ["10.0.0.99"]
""")).waivers
    r, _, _ = scan_with(waivers, host="10.0.0.5")
    assert r["WIN-SMB1"].waived is False


def test_warn_cannot_be_waived(tmp_path):
    """Accepting a risk nobody measured is not risk acceptance."""
    waivers = w.load_waivers(write_waivers(tmp_path, """
waivers:
  - check_id: WIN-LOCAL-ADMINS
    reason: trying to silence a control that was never verified
    owner: a.araia
    expires: 2026-12-31
""")).waivers
    r, summary, notes = scan_with(waivers)
    assert r["WIN-LOCAL-ADMINS"].status is Status.WARN
    assert r["WIN-LOCAL-ADMINS"].waived is False
    assert summary["waived"] == 0
    assert any("does not apply" in n for n in notes)


def test_stale_waiver_for_a_removed_control_is_reported(tmp_path):
    waivers = w.load_waivers(write_waivers(tmp_path, """
waivers:
  - check_id: WIN-REMOVED-CONTROL
    reason: control was removed from the benchmark
    owner: a.araia
    expires: 2026-12-31
""")).waivers
    _, _, notes = scan_with(waivers)
    assert any("no longer exists" in n for n in notes)


def test_waived_control_is_not_remediated(tmp_path):
    """Silently 'fixing' an accepted risk overrules a documented decision."""
    waivers = w.load_waivers(write_waivers(tmp_path, VALID)).waivers
    conn = make_connection("fixture", scenario="windows/baseline")
    results, _, _ = run_scan(
        "windows", conn, ROOT / "rules", waiver_list=waivers, host="10.0.0.5", today=TODAY
    )
    plan = rem.build_plan(results, rem_win.CATALOG, "windows", "10.0.0.5")
    assert "WIN-SMB1" not in {f.check_id for f in plan.fixes}


def test_shipped_exceptions_file_is_valid():
    """The committed example must parse, a broken one teaches the wrong format."""
    load = w.load_waivers(ROOT / "exceptions.yml")
    assert not load.problems
    assert load.waivers
