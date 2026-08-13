from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner.connection import make_connection  # noqa: E402
from scanner.model import Status  # noqa: E402
from scanner.parser import parse_subrule  # noqa: E402
from scanner.scanner import run_scan  # noqa: E402


def scan(platform, scenario):
    conn = make_connection("fixture", scenario=f"{platform}/{scenario}")
    results, summary = run_scan(platform, conn, ROOT / "rules")
    by_id = {r.check.id: r for r in results}
    return by_id, summary


# --- sub-rule grammar --------------------------------------------------------

def test_parse_registry_subrule():
    s = parse_subrule("r:HKLM\\Foo -> Bar -> equals:0")
    assert (s.type, s.target, s.name, s.matcher) == ("r", "HKLM\\Foo", "Bar", "equals:0")


def test_parse_rejects_unknown_prefix():
    with pytest.raises(ValueError):
        parse_subrule("zzz:whatever -> equals:1")


# --- windows scan ------------------------------------------------------------

def test_windows_baseline_statuses():
    r, summary = scan("windows", "baseline")
    assert r["WIN-18.3.3"].status is Status.FAIL   # SMBv1 enabled
    assert r["WIN-9.1"].status is Status.PASS       # firewall on all profiles
    assert r["WIN-2.3.1"].status is Status.WARN      # manual review
    assert summary["score"] == 50                    # 1 of 2 scored controls pass


def test_windows_hardened_statuses():
    r, summary = scan("windows", "hardened")
    assert r["WIN-18.3.3"].status is Status.PASS
    assert summary["score"] == 100


# --- linux scan --------------------------------------------------------------

def test_linux_baseline_statuses():
    r, summary = scan("linux", "baseline")
    assert r["LNX-5.2.8"].status is Status.FAIL    # root login permitted
    assert r["LNX-3.5.1"].status is Status.FAIL    # no firewall active (any-condition)
    assert r["LNX-6.1.2"].status is Status.PASS    # shadow perms ok


def test_linux_hardened_statuses():
    r, summary = scan("linux", "hardened")
    assert r["LNX-5.2.8"].status is Status.PASS
    assert r["LNX-3.5.1"].status is Status.PASS    # firewalld active satisfies 'any'
    assert summary["score"] == 100


# --- the load-bearing fail-safe ---------------------------------------------

def test_unreachable_host_never_passes():
    r, summary = scan("linux", "unreachable")
    for check in r.values():
        assert check.status is not Status.PASS
    # every check is unknown -> WARN, and the score has no false PASS in it
    assert summary["pass"] == 0
    assert summary["warn"] == len(r)


def test_manual_control_is_warn_not_pass():
    r, _ = scan("windows", "baseline")
    assert r["WIN-2.3.1"].status is Status.WARN
