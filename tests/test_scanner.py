from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner.connection import make_connection  # noqa: E402
from scanner.connection.base import CommandOutput  # noqa: E402
from scanner.evaluator import _match, evaluate  # noqa: E402
from scanner.model import Check, Status  # noqa: E402
from scanner.parser import load_policies, parse_subrule  # noqa: E402
from scanner.scanner import run_scan  # noqa: E402


def scan(platform, scenario):
    conn = make_connection("fixture", scenario=f"{platform}/{scenario}")
    results, summary, _ = run_scan(platform, conn, ROOT / "rules")
    return {r.check.id: r for r in results}, summary


# --- sub-rule grammar --------------------------------------------------------

def test_parse_registry_subrule():
    s = parse_subrule("r:HKLM\\Foo -> Bar -> equals:0")
    assert (s.type, s.target, s.name, s.matcher) == ("r", "HKLM\\Foo", "Bar", "equals:0")


def test_parse_rejects_unknown_prefix():
    with pytest.raises(ValueError):
        parse_subrule("zzz:whatever -> equals:1")


def test_every_check_has_nist_tag_and_level():
    for platform in ("windows", "linux"):
        for pol in load_policies(ROOT / "rules", platform):
            for c in pol.checks:
                assert c.nist.startswith("NIST800-53"), c.id
                assert c.level in ("level1", "level2"), c.id
                assert c.scored in ("scored", "notscored"), c.id


# --- windows scan ------------------------------------------------------------

def test_windows_baseline_statuses():
    r, summary = scan("windows", "baseline")
    assert r["WIN-SMB1"].status is Status.FAIL     # SMBv1 enabled
    assert r["WIN-FIREWALL"].status is Status.PASS         # firewall on all profiles
    assert r["WIN-PW-MINLEN"].status is Status.FAIL       # minlen 7
    assert r["WIN-AUDIT-LOGON"].status is Status.FAIL        # success-only auditing
    assert r["WIN-LEGACY-SVC"].status is Status.FAIL         # RemoteRegistry running
    assert r["WIN-LOCAL-ADMINS"].status is Status.WARN       # manual review
    assert summary["score"] == 56


def test_windows_hardened_statuses():
    r, summary = scan("windows", "hardened")
    assert r["WIN-SMB1"].status is Status.PASS
    assert r["WIN-PW-MINLEN"].status is Status.PASS
    assert r["WIN-LEGACY-SVC"].status is Status.PASS
    assert summary["score"] == 100


def test_legacy_services_detected_via_registry_not_get_service():
    """A non-admin Get-Service returns nothing for a service it cannot see,
    which is indistinguishable from the service being absent, that reported a
    running Remote Registry as compliant. The Start value is readable instead."""
    r, _ = scan("windows", "baseline")
    assert r["WIN-LEGACY-SVC"].status is Status.FAIL
    assert "Services" in r["WIN-LEGACY-SVC"].evidence[0].subrule


def test_notscored_control_stays_out_of_the_score():
    r, summary = scan("windows", "hardened")
    assert r["WIN-BITLOCKER"].status is Status.FAIL  # BitLocker still off
    assert summary["score"] == 100                  # but notscored, so no drag
    assert summary["scored_total"] == 9


# --- linux scan --------------------------------------------------------------

def test_linux_baseline_statuses():
    r, summary = scan("linux", "baseline")
    assert r["LNX-SSH-ROOT"].status is Status.FAIL     # root login permitted
    assert r["LNX-SSH-PASSAUTH"].status is Status.FAIL     # password auth on
    assert r["LNX-FIREWALL"].status is Status.FAIL     # no firewall (any-condition)
    assert r["LNX-WORLD-WRITE"].status is Status.FAIL    # world-writable file found
    assert r["LNX-AUDIT-LOG"].status is Status.FAIL     # rsyslog down (all-condition)
    assert summary["score"] == 30


def test_linux_hardened_statuses():
    r, summary = scan("linux", "hardened")
    assert r["LNX-SSH-ROOT"].status is Status.PASS
    assert r["LNX-SSH-PASSAUTH"].status is Status.PASS
    assert r["LNX-FIREWALL"].status is Status.PASS     # firewalld alone satisfies 'any'
    assert summary["score"] == 100


def test_shared_probe_returns_same_evidence():
    """5.2.8 and 5.2.9 read the same file, they must see identical content."""
    r, _ = scan("linux", "hardened")
    assert r["LNX-SSH-ROOT"].evidence[0].output == r["LNX-SSH-PASSAUTH"].evidence[0].output


# --- the load-bearing fail-safe ---------------------------------------------

def test_unreachable_host_never_passes():
    r, summary = scan("linux", "unreachable")
    for check in r.values():
        assert check.status is not Status.PASS
    assert summary["pass"] == 0
    assert summary["warn"] == len(r)


def test_unset_policy_value_warns_rather_than_passes():
    """minlen absent from pwquality.conf -> unknown, not a pass."""
    r, _ = scan("linux", "baseline")
    assert r["LNX-PW-MINLEN"].status is Status.WARN


def test_manual_control_is_warn_but_still_collects_evidence():
    r, _ = scan("linux", "baseline")
    suid = r["LNX-SUID-AUDIT"]
    assert suid.status is Status.WARN
    assert "/usr/bin/sudo" in suid.evidence[0].output


# --- regressions: each of these passed a control it should not have -----------

@pytest.mark.parametrize(
    "mode,allowed,expected",
    [
        ("640", "0640", True),
        ("600", "0640", True),
        ("644", "0640", False),   # group+other read
        ("007", "0640", False),   # world rwx, numerically small, wildly permissive
        ("466", "0640", False),
        ("777", "0640", False),
    ],
)
def test_maxmode_compares_bits_not_magnitude(mode, allowed, expected):
    out = CommandOutput(stdout=mode, exit_status=0, ok=True)
    assert _match(f"maxmode:{allowed}", out) is expected


def test_service_state_unknown_when_probe_fails():
    """An errored service probe is unknown, not 'not running'."""
    failed = CommandOutput(stdout="", exit_status=1, ok=True)
    assert _match("stopped:", failed) is None
    assert _match("running:", failed) is None


def test_service_state_reads_the_state_word_not_the_exit_code():
    """systemctl is-active exits 3 for an inactive unit, still a definite answer."""
    inactive = CommandOutput(stdout="inactive", exit_status=3, ok=True)
    assert _match("stopped:", inactive) is True
    assert _match("running:", inactive) is False


def test_absent_service_satisfies_stopped_only_on_clean_exit():
    absent = CommandOutput(stdout="", exit_status=0, ok=True)
    assert _match("stopped:", absent) is True


def test_check_with_no_subrules_warns_instead_of_passing():
    empty = Check(
        id="X-1", title="nothing to verify", level="level1", scored="scored",
        nist="NIST800-53R5_XX-1", scope="server", severity="high",
        condition="all", rules=[],
    )
    conn = make_connection("fixture", scenario="linux/baseline")
    assert evaluate(empty, "linux", conn).status is Status.WARN


def test_unsupported_subrule_warns_instead_of_killing_the_scan():
    bad = Check(
        id="X-2", title="registry rule on linux", level="level1", scored="scored",
        nist="NIST800-53R5_XX-2", scope="server", severity="high", condition="all",
        rules=[parse_subrule("r:HKLM\\Foo -> Bar -> equals:1")],
    )
    conn = make_connection("fixture", scenario="linux/baseline")
    result = evaluate(bad, "linux", conn)  # must not raise
    assert result.status is Status.WARN


def test_sudo_denied_never_fabricates_a_pass():
    """The helper prints nothing when sudo is refused; these must not pass."""
    r, summary = scan("linux", "sudo_denied")
    for cid in ("LNX-SUDO-NOPASSWD", "LNX-WORLD-WRITE", "LNX-SUID-AUDIT"):
        assert r[cid].status is Status.WARN, cid
    assert summary["coverage"] < 100


def test_score_carries_coverage():
    """A high score off a handful of verified controls must not read as complete."""
    _, denied = scan("linux", "sudo_denied")
    _, full = scan("linux", "hardened")
    assert denied["score"] == 100 and denied["coverage"] < 30
    assert full["score"] == 100 and full["coverage"] == 100


def test_empty_output_is_never_a_verdict():
    """A pattern can be neither present nor absent in output that was never
    produced, most often the probe lacked privilege to read what it asked for.
    This reported 'auditpol requires admin' as a failing audit policy."""
    empty_clean = CommandOutput(stdout="", exit_status=0, ok=True)
    assert _match("regex:Success and Failure", empty_clean) is None
    assert _match("notregex:NOPASSWD", empty_clean) is None
    assert _match("equals:1", empty_clean) is None
