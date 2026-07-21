from __future__ import annotations

from typing import Any

from secscan.models import Finding


SEVERITIES = ("UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL")


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
                )
            )
    return findings


def summarize(findings: list[Finding]) -> dict[str, int]:
    totals = {severity.lower(): 0 for severity in SEVERITIES}
    for finding in findings:
        totals[finding.severity.lower()] += 1
    totals["total"] = len(findings)
    return totals
