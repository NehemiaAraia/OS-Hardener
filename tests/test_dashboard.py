from __future__ import annotations

import base64
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import dashboard as dash  # noqa: E402
from scanner.connection import make_connection  # noqa: E402
from scanner.scanner import run_scan  # noqa: E402
from scanner.storage import Store  # noqa: E402


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DASHBOARD_USER", "admin")
    monkeypatch.setenv("DASHBOARD_PASS", "correct-horse")
    db = tmp_path / "scans.db"
    conn = make_connection("fixture", scenario="linux/baseline")
    results, summary = run_scan("linux", conn, ROOT / "rules")
    with Store(db) as store:
        store.save_scan(results, summary,
                        {"platform": "linux", "host": "10.0.0.9", "timestamp": "20260101_000000"})
    dash.app.config["DB_PATH"] = str(db)
    dash.app.config["TESTING"] = True
    return dash.app.test_client()


def _auth(user="admin", password="correct-horse"):
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


def test_requires_auth():
    dash.app.config["TESTING"] = True
    resp = dash.app.test_client().get("/")
    assert resp.status_code == 401


def test_wrong_password_rejected(client):
    assert client.get("/", headers=_auth(password="wrong")).status_code == 401


def test_index_lists_scans(client):
    resp = client.get("/", headers=_auth())
    assert resp.status_code == 200
    assert b"10.0.0.9" in resp.data


def test_detail_shows_controls_and_coverage(client):
    resp = client.get("/scan/1", headers=_auth())
    assert resp.status_code == 200
    assert b"LNX-5.2.8" in resp.data
    assert b"coverage" in resp.data.lower()


def test_missing_scan_is_404(client):
    assert client.get("/scan/9999", headers=_auth()).status_code == 404


def test_non_integer_scan_id_is_rejected(client):
    """The int converter keeps anything non-numeric away from the query."""
    assert client.get("/scan/1%20OR%201=1", headers=_auth()).status_code == 404
    assert client.get("/scan/abc", headers=_auth()).status_code == 404


def test_host_field_is_escaped(tmp_path, monkeypatch):
    """Host and evidence come off scanned targets, so they must never render raw."""
    monkeypatch.setenv("DASHBOARD_USER", "admin")
    monkeypatch.setenv("DASHBOARD_PASS", "correct-horse")
    db = tmp_path / "x.db"
    conn = make_connection("fixture", scenario="linux/baseline")
    results, summary = run_scan("linux", conn, ROOT / "rules")
    with Store(db) as store:
        store.save_scan(results, summary, {
            "platform": "linux",
            "host": "<script>alert(1)</script>",
            "timestamp": "20260101_000000",
        })
    dash.app.config["DB_PATH"] = str(db)
    dash.app.config["TESTING"] = True
    resp = dash.app.test_client().get("/", headers=_auth())
    assert b"<script>alert(1)</script>" not in resp.data
    assert b"&lt;script&gt;" in resp.data


def test_security_headers_present(client):
    resp = client.get("/", headers=_auth())
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
