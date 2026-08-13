"""Render scan results to JSON and a Bootstrap-styled HTML report.

HTML goes through Jinja2 with autoescape ON — evidence output comes off scanned
hosts and must never land unescaped in the page (the XSS smell avoided from
WinSecureAuditor's raw f-string reporter)."""
from __future__ import annotations

import json
from pathlib import Path

from jinja2 import Environment, select_autoescape

from .model import CheckResult

_ENV = Environment(autoescape=select_autoescape(default=True, default_for_string=True))

_TEMPLATE = _ENV.from_string(
    """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Hardening report — {{ meta.platform }} — {{ meta.host }}</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
<style>
  body { padding: 2rem; }
  .score-ring { font-size: 3rem; font-weight: 700; }
  details > summary { cursor: pointer; }
  code { white-space: pre-wrap; word-break: break-all; }
</style>
</head>
<body>
<div class="container">
  <h1 class="mb-1">Compliance report</h1>
  <p class="text-muted">{{ meta.platform }} · {{ meta.host }} · {{ meta.timestamp }}</p>

  <div class="row g-3 my-3">
    <div class="col"><div class="card text-center p-3"><div class="score-ring">{{ summary.score }}%</div><div>compliance score</div></div></div>
    <div class="col"><div class="card text-center p-3"><div class="score-ring text-success">{{ summary.pass }}</div><div>PASS</div></div></div>
    <div class="col"><div class="card text-center p-3"><div class="score-ring text-danger">{{ summary.fail }}</div><div>FAIL</div></div></div>
    <div class="col"><div class="card text-center p-3"><div class="score-ring text-warning">{{ summary.warn }}</div><div>WARN</div></div></div>
  </div>

  <table class="table table-hover align-middle">
    <thead><tr><th>ID</th><th>Control</th><th>Status</th><th>Severity</th><th>NIST 800-53</th></tr></thead>
    <tbody>
    {% for r in results %}
      <tr>
        <td><code>{{ r.id }}</code></td>
        <td>
          <details>
            <summary>{{ r.title }}</summary>
            <div class="mt-2 small">
              <div><strong>Level:</strong> {{ r.level }} · <strong>Scored:</strong> {{ r.scored }} · <strong>Scope:</strong> {{ r.scope }}</div>
              <div><strong>Message:</strong> {{ r.message }}</div>
              {% if r.remediation %}<div><strong>Remediation:</strong> {{ r.remediation }}</div>{% endif %}
              {% for e in r.evidence %}
                <div class="mt-1"><code>{{ e.rule }}</code> → satisfied={{ e.satisfied }}<br><code>{{ e.output }}</code></div>
              {% endfor %}
            </div>
          </details>
        </td>
        <td>
          {% if r.status == 'PASS' %}<span class="badge text-bg-success">PASS</span>
          {% elif r.status == 'FAIL' %}<span class="badge text-bg-danger">FAIL</span>
          {% else %}<span class="badge text-bg-warning">WARN</span>{% endif %}
        </td>
        <td>{{ r.severity }}</td>
        <td><code>{{ r.nist }}</code></td>
      </tr>
    {% endfor %}
    </tbody>
  </table>
</div>
</body>
</html>
"""
)


def build_document(results: list[CheckResult], summary: dict, meta: dict) -> dict:
    return {"meta": meta, "summary": summary, "results": [r.to_dict() for r in results]}


def write_json(doc: dict, path: str | Path) -> Path:
    path = Path(path)
    path.write_text(json.dumps(doc, indent=2))
    return path


def write_html(doc: dict, path: str | Path) -> Path:
    path = Path(path)
    html = _TEMPLATE.render(meta=doc["meta"], summary=doc["summary"], results=doc["results"])
    path.write_text(html)
    return path
