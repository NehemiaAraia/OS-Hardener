#!/usr/bin/env python3
"""Small Flask dashboard over the scan history.

An upgrade over the static HTML report, not a replacement: browsable history and
score trend per target. Basic auth over HTTPS, credentials from the environment,
every query parameterized through the storage layer.

    export DASHBOARD_USER=admin DASHBOARD_PASS=...
    python dashboard.py --cert cert.pem --key key.pem
"""
from __future__ import annotations

import argparse
import hmac
import os
import sys
from functools import wraps

from flask import Flask, Response, abort, render_template, request
from jinja2 import DictLoader

from scanner.storage import DEFAULT_DB, Store

app = Flask(__name__)
app.config["DB_PATH"] = os.environ.get("HARDENING_DB", DEFAULT_DB)


def _check_auth(user: str, password: str) -> bool:
    expected_user = os.environ.get("DASHBOARD_USER", "")
    expected_pass = os.environ.get("DASHBOARD_PASS", "")
    if not expected_user or not expected_pass:
        return False
    # compare_digest on both halves so neither is short-circuited
    return hmac.compare_digest(user, expected_user) and hmac.compare_digest(password, expected_pass)


def requires_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.authorization
        if not auth or not _check_auth(auth.username or "", auth.password or ""):
            return Response(
                "authentication required", 401,
                {"WWW-Authenticate": 'Basic realm="hardening dashboard"'},
            )
        return f(*args, **kwargs)

    return wrapper


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'"
    return resp


_LAYOUT = """
<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>{{ title }}</title>
<style>
 body { font-family: system-ui, sans-serif; margin: 2rem; color: #222; }
 table { border-collapse: collapse; width: 100%; margin-top: 1rem; }
 th, td { text-align: left; padding: .5rem .6rem; border-bottom: 1px solid #ddd; }
 th { background: #f5f5f5; }
 .PASS { color: #157347; font-weight: 600; }
 .FAIL { color: #b02a37; font-weight: 600; }
 .WARN { color: #997404; font-weight: 600; }
 .muted { color: #666; font-size: .9rem; }
 a { color: #0d6efd; }
</style></head><body>
{% block body %}{% endblock %}
</body></html>
"""

_INDEX = """
{% extends "layout.html" %}
{% block body %}
<h1>Scan history</h1>
<p class="muted">{{ scans|length }} scan(s). Coverage is shown alongside every score,
a score computed from a subset is not the same claim as a full one.</p>
<table>
  <tr><th>#</th><th>Platform</th><th>Host</th><th>When (UTC)</th><th>Score</th>
      <th>Coverage</th><th>Pass</th><th>Fail</th><th>Warn</th></tr>
  {% for s in scans %}
  <tr>
    <td><a href="/scan/{{ s['id'] }}">{{ s['id'] }}</a></td>
    <td>{{ s['platform'] }}</td>
    <td>{{ s['host'] }}</td>
    <td>{{ s['timestamp'] }}</td>
    <td>{{ s['score'] }}%</td>
    <td>{{ s['coverage'] }}%{% if s['coverage'] < 100 %} <span class="muted">(partial)</span>{% endif %}</td>
    <td class="PASS">{{ s['pass_count'] }}</td>
    <td class="FAIL">{{ s['fail_count'] }}</td>
    <td class="WARN">{{ s['warn_count'] }}</td>
  </tr>
  {% endfor %}
</table>
{% endblock %}
"""

_DETAIL = """
{% extends "layout.html" %}
{% block body %}
<p><a href="/">&larr; all scans</a></p>
<h1>Scan {{ scan['id'] }}, {{ scan['platform'] }} @ {{ scan['host'] }}</h1>
<p class="muted">{{ scan['timestamp'] }} UTC</p>
<p><strong>Score {{ scan['score'] }}%</strong>
   from {{ scan['scored_total'] }}/{{ scan['scored_defined'] }} scored controls
   (coverage {{ scan['coverage'] }}%)</p>
{% if scan['coverage'] < 100 %}
<p class="WARN">Partial coverage, {{ scan['scored_defined'] - scan['scored_total'] }}
   scored control(s) could not be verified and are excluded from the score.</p>
{% endif %}
<table>
  <tr><th>ID</th><th>Control</th><th>Status</th><th>Severity</th><th>NIST</th><th>Detail</th></tr>
  {% for r in results %}
  <tr>
    <td>{{ r['check_id'] }}</td>
    <td>{{ r['title'] }}</td>
    <td class="{{ r['status'] }}">{{ r['status'] }}</td>
    <td>{{ r['severity'] }}</td>
    <td>{{ r['nist'] }}</td>
    <td class="muted">{{ r['message'] }}</td>
  </tr>
  {% endfor %}
</table>
{% endblock %}
"""


# .html names keep Flask's autoescaping on, values here come off scanned hosts
app.jinja_loader = DictLoader(
    {"layout.html": _LAYOUT, "index.html": _INDEX, "detail.html": _DETAIL}
)


@app.route("/")
@requires_auth
def index():
    with Store(app.config["DB_PATH"]) as store:
        scans = store.recent_scans()
    return render_template("index.html", title="Scan history", scans=scans)


@app.route("/scan/<int:scan_id>")
@requires_auth
def scan_detail(scan_id: int):
    with Store(app.config["DB_PATH"]) as store:
        scan = store.scan(scan_id)
        if scan is None:
            abort(404)
        results = list(store.results_for(scan_id).values())
    results.sort(key=lambda r: r["check_id"])
    return render_template("detail.html", title=f"Scan {scan_id}", scan=scan, results=results)


def main() -> int:
    p = argparse.ArgumentParser(description="hardening scan dashboard")
    p.add_argument("--host", default="127.0.0.1", help="bind address (localhost by default)")
    p.add_argument("--port", type=int, default=8443)
    p.add_argument("--cert", help="TLS certificate; omit to generate a self-signed one")
    p.add_argument("--key", help="TLS private key")
    p.add_argument("--db", default=app.config["DB_PATH"])
    args = p.parse_args()

    if not os.environ.get("DASHBOARD_USER") or not os.environ.get("DASHBOARD_PASS"):
        sys.exit("set DASHBOARD_USER and DASHBOARD_PASS before starting the dashboard")

    app.config["DB_PATH"] = args.db
    # HTTPS is not optional here: basic auth sends credentials on every request
    ssl_context = (args.cert, args.key) if args.cert and args.key else "adhoc"
    if ssl_context == "adhoc":
        print("[!] using a generated self-signed certificate (lab only)", file=sys.stderr)
    app.run(host=args.host, port=args.port, ssl_context=ssl_context)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
