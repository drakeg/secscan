"""Evidence-only priority assessment for normalized vulnerability findings.

This module is deliberately independent of tenant/asset lookups. It never asserts
internet exposure, effective IAM privileges, or a verified attack path.
"""

from __future__ import annotations

from collections.abc import Mapping
from math import isfinite
from typing import Any


def assess_finding_priority(finding: Mapping[str, Any]) -> dict[str, object]:
    """Return a deterministic priority tier and the evidence behind it.

    This is advisory triage, not a substitute for scanner severity or an
    exploitability determination. Unknown inputs are never treated as proof of
    safety or exposure.
    """
    raw_severity = finding.get("severity")
    severity = raw_severity.upper() if isinstance(raw_severity, str) else "UNKNOWN"
    if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
        severity = "UNKNOWN"

    known_exploited = finding.get("known_exploited") is True
    epss = finding.get("epss")
    score: float | None = None
    if isinstance(epss, Mapping):
        candidate = epss.get("score")
        if isinstance(candidate, (int, float)) and not isinstance(candidate, bool):
            value = float(candidate)
            if isfinite(value) and 0.0 <= value <= 1.0:
                score = value

    reasons: list[str] = []
    if severity == "UNKNOWN":
        reasons.append("Scanner severity unavailable")
    else:
        reasons.append(f"Scanner severity: {severity}")
    if known_exploited:
        reasons.append("Listed in configured CISA KEV catalog")
    if score is not None:
        reasons.append(f"EPSS probability: {score:.4f}")

    if known_exploited:
        tier = "urgent"
    elif severity == "CRITICAL" or (score is not None and score >= 0.5):
        tier = "high"
    elif severity in {"HIGH", "MEDIUM"}:
        tier = "medium"
    elif severity == "LOW":
        tier = "low"
    else:
        tier = "unassessed"

    return {
        "tier": tier,
        "reasons": reasons,
        "evidence": {
            "scanner_severity": severity if severity != "UNKNOWN" else None,
            "known_exploited": True if known_exploited else None,
            "epss_probability": score,
            "internet_exposure": None,
            "identity_privilege": None,
            "asset_criticality": None,
        },
    }
