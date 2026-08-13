from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner.connection import make_connection  # noqa: E402
from scanner.model import Status  # noqa: E402
from scanner.parser import load_policies, parse_subrule  # noqa: E402
from scanner.scanner import run_scan  # noqa: E402


def scan(platform, scenario):
    conn = make_connection("fixture", scenario=f"{platform}/{scenario}")
    results, summary = run_scan(platform, conn, ROOT / "rules")
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
    assert r["WIN-18.3.3"].status is Status.FAIL     # SMBv1 enabled
    assert r["WIN-9.1"].status is Status.PASS         # firewall on all profiles
    assert r["WIN-1.1.1"].status is Status.FAIL       # minlen 7
    assert r["WIN-17.1"].status is Status.FAIL        # success-only auditing
    assert r["WIN-5.1"].status is Status.FAIL         # RemoteRegistry running
    assert r["WIN-2.3.1"].status is Status.WARN       # manual review
    assert summary["score"] == 56


def test_windows_hardened_statuses():
    r, summary = scan("windows", "hardened")
    assert r["WIN-18.3.3"].status is Status.PASS
    assert r["WIN-1.1.1"].status is Status.PASS
    assert r["WIN-5.1"].status is Status.PASS
    assert summary["score"] == 100


def test_absent_service_counts_as_not_running():
    r, _ = scan("windows", "baseline")
    telnet = r["WIN-5.1"].evidence[0]
    assert telnet.satisfied is True  # empty output = service not installed


def test_notscored_control_stays_out_of_the_score():
    r, summary = scan("windows", "hardened")
    assert r["WIN-18.9.10"].status is Status.FAIL  # BitLocker still off
    assert summary["score"] == 100                  # but notscored, so no drag
    assert summary["scored_total"] == 9


# --- linux scan --------------------------------------------------------------

def test_linux_baseline_statuses():
    r, summary = scan("linux", "baseline")
    assert r["LNX-5.2.8"].status is Status.FAIL     # root login permitted
    assert r["LNX-5.2.9"].status is Status.FAIL     # password auth on
    assert r["LNX-3.5.1"].status is Status.FAIL     # no firewall (any-condition)
    assert r["LNX-6.1.10"].status is Status.FAIL    # world-writable file found
    assert r["LNX-4.1.1"].status is Status.FAIL     # rsyslog down (all-condition)
    assert summary["score"] == 30


def test_linux_hardened_statuses():
    r, summary = scan("linux", "hardened")
    assert r["LNX-5.2.8"].status is Status.PASS
    assert r["LNX-5.2.9"].status is Status.PASS
    assert r["LNX-3.5.1"].status is Status.PASS     # firewalld alone satisfies 'any'
    assert summary["score"] == 100


def test_shared_probe_returns_same_evidence():
    """5.2.8 and 5.2.9 read the same file — they must see identical content."""
    r, _ = scan("linux", "hardened")
    assert r["LNX-5.2.8"].evidence[0].output == r["LNX-5.2.9"].evidence[0].output


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
    assert r["LNX-5.4.1"].status is Status.WARN


def test_manual_control_is_warn_but_still_collects_evidence():
    r, _ = scan("linux", "baseline")
    suid = r["LNX-6.1.13"]
    assert suid.status is Status.WARN
    assert "/usr/bin/sudo" in suid.evidence[0].output
