from __future__ import annotations

import html
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from secscan.models import Finding
from secscan.normalize import summarize


def build_report(image: str, findings: list[Finding], scanner: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "generated_at": datetime.now(UTC).isoformat(),
        "target": {"type": "container_image", "name": image},
        "scanner": scanner,
        "summary": summarize(findings),
        "findings": [finding.to_dict() for finding in findings],
    }


def write_json(report: dict[str, Any], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_raw_json(raw: dict[str, Any], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(raw, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _cell(value: object) -> str:
    return html.escape("" if value is None else str(value))


def write_html(report: dict[str, Any], output: Path) -> None:
    summary = report.get("summary", {})
    findings = report.get("findings", [])
    rows: list[str] = []
    for finding in findings:
        url = finding.get("primary_url")
        vulnerability = _cell(finding.get("vulnerability_id"))
        vulnerability_html = (
            f'<a href="{html.escape(str(url), quote=True)}" rel="noreferrer">{vulnerability}</a>'
            if url
            else vulnerability
        )
        fixed = finding.get("fixed_version") or "No fix listed"
        rows.append(
            "<tr>"
            f"<td>{_cell(finding.get('severity'))}</td>"
            f"<td>{vulnerability_html}</td>"
            f"<td>{_cell(finding.get('package_name'))}</td>"
            f"<td>{_cell(finding.get('installed_version'))}</td>"
            f"<td>{_cell(fixed)}</td>"
            f"<td>{_cell(finding.get('title'))}</td>"
            "</tr>"
        )

    summary_cards = "".join(
        f'<div class="card"><strong>{_cell(level)}</strong><span>{_cell(summary.get(level, 0))}</span></div>'
        for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN", "total")
    )
    table_body = "".join(rows) or '<tr><td colspan="6">No vulnerabilities found.</td></tr>'
    document = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>secscan report</title>
<style>
body{{font-family:system-ui,sans-serif;margin:2rem;color:#1f2937}}h1{{margin-bottom:.25rem}}.muted{{color:#6b7280}}.cards{{display:flex;flex-wrap:wrap;gap:.75rem;margin:1.5rem 0}}.card{{border:1px solid #d1d5db;border-radius:.5rem;padding:.75rem 1rem;min-width:7rem;display:flex;justify-content:space-between;gap:1rem}}table{{border-collapse:collapse;width:100%;font-size:.92rem}}th,td{{border:1px solid #d1d5db;padding:.55rem;text-align:left;vertical-align:top}}th{{background:#f3f4f6}}a{{color:#1d4ed8}}code{{background:#f3f4f6;padding:.1rem .25rem;border-radius:.2rem}}
</style>
</head>
<body>
<h1>secscan vulnerability report</h1>
<p class="muted">Target: <code>{_cell(report.get('target', {}).get('name'))}</code><br>Generated: {_cell(report.get('generated_at'))}<br>Scanner: {_cell(report.get('scanner', {}).get('version'))}</p>
<div class="cards">{summary_cards}</div>
<table>
<thead><tr><th>Severity</th><th>Vulnerability</th><th>Package</th><th>Installed</th><th>Fixed</th><th>Title</th></tr></thead>
<tbody>{table_body}</tbody>
</table>
</body>
</html>
"""
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(document, encoding="utf-8")
