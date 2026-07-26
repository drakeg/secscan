from __future__ import annotations

from datetime import date, datetime
from typing import Any

from secscan.models import Finding

SEVERITIES = ("UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL")


def _published_date(value: object) -> date | None:
    if not value:
        return None
    text = str(value).strip()
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).date()
    except ValueError:
        try:
            return date.fromisoformat(text[:10])
        except ValueError:
            return None


def normalize_trivy(payload: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for result in payload.get("Results") or []:
        target = str(result.get("Target") or "unknown")
        package_type = result.get("Type")
        for item in result.get("Vulnerabilities") or []:
            severity = str(item.get("Severity") or "UNKNOWN").upper()
            if severity not in SEVERITIES:
                severity = "UNKNOWN"
            findings.append(
                Finding(
                    vulnerability_id=str(item.get("VulnerabilityID") or "UNKNOWN"),
                    package_name=str(item.get("PkgName") or "unknown"),
                    installed_version=str(item.get("InstalledVersion") or "unknown"),
                    fixed_version=item.get("FixedVersion") or None,
                    severity=severity,
                    title=str(item.get("Title") or item.get("Description") or "No title provided"),
                    target=target,
                    package_type=str(package_type) if package_type else None,
                    primary_url=item.get("PrimaryURL") or None,
                    published_date=_published_date(item.get("PublishedDate")),
                )
            )
    return findings


def summarize(findings: list[Finding]) -> dict[str, int]:
    totals = {severity.lower(): 0 for severity in SEVERITIES}
    for finding in findings:
        totals[finding.severity.lower()] += 1
    totals["total"] = len(findings)
    return totals
