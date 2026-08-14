from __future__ import annotations

import io
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner import delta as delta_mod  # noqa: E402
from scanner.connection import make_connection  # noqa: E402
from scanner.model import Status  # noqa: E402
from scanner.remediation import base as rem  # noqa: E402
from scanner.remediation import linux as rem_linux  # noqa: E402
from scanner.remediation import windows as rem_win  # noqa: E402
from scanner.scanner import run_scan  # noqa: E402
from scanner.storage import Store  # noqa: E402


def scan_of(platform, scenario):
    conn = make_connection("fixture", scenario=f"{platform}/{scenario}")
    return run_scan(platform, conn, ROOT / "rules")


def store_scan(store, platform, scenario, host="10.0.0.5", ts="20260101_000000"):
    results, summary = scan_of(platform, scenario)
    meta = {"platform": platform, "host": host, "timestamp": ts}
    return store.save_scan(results, summary, meta), results, summary


# --- storage -----------------------------------------------------------------

def test_scan_round_trips(tmp_path):
    with Store(tmp_path / "s.db") as store:
        scan_id, results, summary = store_scan(store, "linux", "baseline")
        saved = store.scan(scan_id)
        assert saved["score"] == summary["score"]
        assert saved["coverage"] == summary["coverage"]
        assert len(store.results_for(scan_id)) == len(results)


def test_hostile_values_are_stored_not_executed(tmp_path):
    """Host names come off the command line; the store must parameterize them."""
    nasty = "'; DROP TABLE scans; --"
    with Store(tmp_path / "s.db") as store:
        store_scan(store, "linux", "baseline", host=nasty)
        assert store.recent_scans()[0]["host"] == nasty
        assert len(store.recent_scans()) == 1  # table still there


# --- delta -------------------------------------------------------------------

def test_no_delta_without_a_previous_scan(tmp_path):
    with Store(tmp_path / "s.db") as store:
        scan_id, _, _ = store_scan(store, "linux", "baseline")
        assert delta_mod.compute(store, scan_id, "linux", "10.0.0.5") is None


def test_delta_reports_improvements(tmp_path):
    with Store(tmp_path / "s.db") as store:
        store_scan(store, "linux", "baseline", ts="20260101_000000")
        after_id, _, _ = store_scan(store, "linux", "hardened", ts="20260101_010000")
        d = delta_mod.compute(store, after_id, "linux", "10.0.0.5")
    assert d.score_before == 30 and d.score_after == 100
    assert d.score_change == 70
    improved = {c.check_id for c in d.changes if c.improved}
    assert "LNX-5.2.8" in improved and "LNX-3.5.1" in improved


def test_delta_reports_regressions(tmp_path):
    with Store(tmp_path / "s.db") as store:
        store_scan(store, "windows", "hardened", ts="20260101_000000")
        after_id, _, _ = store_scan(store, "windows", "baseline", ts="20260101_010000")
        d = delta_mod.compute(store, after_id, "windows", "10.0.0.5")
    assert d.score_change < 0
    assert any(c.regressed for c in d.changes)
    assert d.changes[0].regressed  # regressions sort first


def test_delta_flags_coverage_change(tmp_path):
    """A score that moved because coverage moved is not a like-for-like gain."""
    with Store(tmp_path / "s.db") as store:
        store_scan(store, "linux", "sudo_denied", ts="20260101_000000")
        after_id, _, _ = store_scan(store, "linux", "hardened", ts="20260101_010000")
        d = delta_mod.compute(store, after_id, "linux", "10.0.0.5")
    assert d.coverage_changed


def test_delta_only_compares_the_same_host(tmp_path):
    with Store(tmp_path / "s.db") as store:
        store_scan(store, "linux", "baseline", host="10.0.0.5")
        other_id, _, _ = store_scan(store, "linux", "hardened", host="10.0.0.6")
        assert delta_mod.compute(store, other_id, "linux", "10.0.0.6") is None


# --- remediation planning ----------------------------------------------------

def test_plan_only_targets_failing_controls(tmp_path):
    results, _ = scan_of("windows", "baseline")
    plan = rem.build_plan(results, rem_win.CATALOG, "windows", "10.0.0.5")
    planned = {f.check_id for f in plan.fixes}
    assert "WIN-18.3.3" in planned          # failing, fixable
    assert "WIN-9.1" not in planned          # already passing, left alone


def test_plan_never_touches_warn_controls():
    """WARN means unverified; acting on it is how a tool breaks a working box."""
    results, _ = scan_of("linux", "sudo_denied")
    warned = {r.check.id for r in results if r.status is Status.WARN}
    plan = rem.build_plan(results, rem_linux.CATALOG, "linux", "10.0.0.5")
    assert warned  # the scenario really does produce WARNs
    assert not {f.check_id for f in plan.fixes} & warned


def test_control_without_safe_fix_is_skipped_not_silently_dropped():
    results, _ = scan_of("windows", "baseline")
    plan = rem.build_plan(results, rem_win.CATALOG, "windows", "10.0.0.5")
    assert "WIN-18.9.10" in {f.check_id for f in plan.skipped}
    assert "WIN-18.9.10" not in {f.check_id for f in plan.fixes}


# --- remediation execution ---------------------------------------------------

def test_dry_run_never_invokes_the_runner(tmp_path):
    results, _ = scan_of("windows", "baseline")
    plan = rem.build_plan(results, rem_win.CATALOG, "windows", "10.0.0.5")
    calls = []

    def runner(fix):
        calls.append(fix.check_id)
        return True, "done"

    outcomes = rem.execute(plan, runner, apply=False, log_path=tmp_path / "r.log")
    assert calls == []
    assert all(o.action in ("DRY-RUN", "SKIP") for o in outcomes)


def test_apply_invokes_runner_and_logs(tmp_path):
    results, _ = scan_of("windows", "baseline")
    plan = rem.build_plan(results, rem_win.CATALOG, "windows", "10.0.0.5")
    log = tmp_path / "r.log"
    outcomes = rem.execute(plan, lambda f: (True, "done"), apply=True, log_path=log)
    assert all(o.action == "APPLY" for o in outcomes if o.fix.command)
    assert "APPLY" in log.read_text()


def test_failed_fix_is_reported_not_swallowed(tmp_path):
    results, _ = scan_of("windows", "baseline")
    plan = rem.build_plan(results, rem_win.CATALOG, "windows", "10.0.0.5")
    outcomes = rem.execute(
        plan, lambda f: (False, "access denied"), apply=True, log_path=tmp_path / "r.log"
    )
    assert any(o.action == "FAIL" for o in outcomes)


def test_confirm_declines_on_anything_but_y():
    for answer in ("n", "", "yes please", "Y3s", "no"):
        stream = io.StringIO(answer + "\n")
        stream.isatty = lambda: True
        assert rem.confirm("10.0.0.5", 3, stream) is (answer.strip().lower() == "y")


def test_confirm_accepts_y():
    stream = io.StringIO("y\n")
    stream.isatty = lambda: True
    assert rem.confirm("10.0.0.5", 3, stream) is True


def test_confirm_refuses_when_not_interactive():
    stream = io.StringIO("y\n")
    stream.isatty = lambda: False
    assert rem.confirm("10.0.0.5", 3, stream) is False


def test_windows_runner_reports_nonzero_exit_as_failure():
    class FakeConn:
        def run(self, cmd):
            from scanner.connection.base import CommandOutput
            return CommandOutput(stdout="Access is denied.", exit_status=1, ok=True)

    runner = rem_win.make_runner(FakeConn())
    ok, detail = runner(rem_win.CATALOG["WIN-18.3.3"])
    assert ok is False and "denied" in detail


def test_windows_runner_reports_lost_connection():
    class DeadConn:
        def run(self, cmd):
            from scanner.connection.base import CommandOutput
            return CommandOutput(stdout="", exit_status=255, ok=False)

    ok, detail = rem_win.make_runner(DeadConn())(rem_win.CATALOG["WIN-9.1"])
    assert ok is False and "connection" in detail.lower()


def test_playbook_missing_ansible_is_reported(monkeypatch):
    monkeypatch.setattr(rem_linux.shutil, "which", lambda _: None)
    ok, detail = rem_linux.run_playbook("h", "u", "k", ["LNX-5.2.8"], check=True)
    assert ok is False and "ansible-playbook" in detail


def test_playbook_refuses_empty_tag_set():
    """An empty tag list would run every task in the playbook."""
    ok, detail = rem_linux.run_playbook("h", "u", "k", [], check=True)
    assert ok is False and "no tags" in detail


def test_every_catalog_fix_maps_to_a_real_control():
    """A fix for a control that doesn't exist can never be verified by a re-scan."""
    from scanner.parser import load_policies

    for platform, catalog in (("windows", rem_win.CATALOG), ("linux", rem_linux.CATALOG)):
        known = {
            c.id for pol in load_policies(ROOT / "rules", platform) for c in pol.checks
        }
        assert set(catalog) <= known, f"{platform}: {set(catalog) - known}"


# --- input validation --------------------------------------------------------

def test_host_validation_rejects_inventory_injection():
    """Ansible's inline inventory is '<host>,' — an unchecked comma would extend
    remediation to machines that were never named."""
    from scanner.validate import valid_host

    assert valid_host("10.0.0.5")
    assert valid_host("ec2-1-2-3-4.compute.amazonaws.com")
    for bad in ("10.0.0.5,10.0.0.99", "host with space", "a;rm -rf /", "$(whoami)", ""):
        assert not valid_host(bad), bad


def test_playbook_refuses_a_host_with_a_comma():
    ok, detail = rem_linux.run_playbook(
        "10.0.0.5,10.0.0.99", "u", "k", ["LNX-5.2.8"], check=True
    )
    assert ok is False and "invalid host" in detail


def test_probe_commands_quote_their_targets():
    """A rule file is trusted like code, but quoting keeps a typo from becoming
    a shell escape."""
    from scanner.executor import probe_command
    from scanner.parser import parse_subrule

    linux_cmd = probe_command(parse_subrule("f:/etc/foo;rm -rf / -> exists:"), "linux")
    assert "'/etc/foo;rm -rf /'" in linux_cmd

    win_cmd = probe_command(parse_subrule("svc:it's -> stopped:"), "windows")
    assert "'it''s'" in win_cmd
