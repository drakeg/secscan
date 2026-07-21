from __future__ import annotations

from secscan.models import Finding


SEVERITY_RANK = {
    "UNKNOWN": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def policy_failed(findings: list[Finding], fail_on: str) -> bool:
    threshold = fail_on.upper()
    if threshold == "NONE":
        return False
    if threshold not in SEVERITY_RANK:
        raise ValueError(f"Unsupported severity threshold: {fail_on}")
    minimum = SEVERITY_RANK[threshold]
    return any(SEVERITY_RANK.get(finding.severity, 0) >= minimum for finding in findings)
