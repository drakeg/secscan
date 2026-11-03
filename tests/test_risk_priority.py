from __future__ import annotations

import pytest

from secscan.risk_priority import assess_finding_priority


@pytest.mark.parametrize(
    ("finding", "expected"),
    [
        ({"severity": "CRITICAL"}, "high"),
        ({"severity": "HIGH"}, "medium"),
        ({"severity": "MEDIUM"}, "medium"),
        ({"severity": "LOW"}, "low"),
        ({"severity": "UNKNOWN"}, "unassessed"),
        ({"severity": "HIGH", "known_exploited": True}, "urgent"),
        ({"severity": "LOW", "epss": {"score": 0.5}}, "high"),
        ({"severity": "HIGH", "epss": {"score": 0.4999}}, "medium"),
    ],
)
def test_priority_tiers_use_only_explicit_evidence(
    finding: dict[str, object], expected: str
) -> None:
    assessment = assess_finding_priority(finding)
    assert assessment["tier"] == expected
    evidence = assessment["evidence"]
    assert isinstance(evidence, dict)
    assert evidence["internet_exposure"] is None
    assert evidence["identity_privilege"] is None
    assert evidence["asset_criticality"] is None


@pytest.mark.parametrize("invalid", [float("nan"), float("inf"), -0.1, 1.1, True, "0.9"])
def test_untrusted_epss_values_cannot_inflate_priority(invalid: object) -> None:
    finding = {"severity": "LOW", "epss": {"score": invalid}}
    result = assess_finding_priority(finding)
    assert result["tier"] == "low"
    assert result["evidence"]["epss_probability"] is None


def test_missing_data_is_unassessed_not_low_risk() -> None:
    result = assess_finding_priority({})
    assert result["tier"] == "unassessed"
    assert result["evidence"]["known_exploited"] is None
    assert result["evidence"]["scanner_severity"] is None


def test_kev_evidence_takes_priority_without_claiming_reachability() -> None:
    result = assess_finding_priority(
        {"severity": "LOW", "known_exploited": True, "epss": {"score": 0.001}}
    )
    assert result["tier"] == "urgent"
    assert "Listed in configured CISA KEV catalog" in result["reasons"]
    assert result["evidence"]["internet_exposure"] is None
    assert result["evidence"]["epss_probability"] == 0.001


def test_false_kev_and_missing_epss_do_not_imply_negative_evidence() -> None:
    result = assess_finding_priority({"severity": "HIGH", "known_exploited": False})
    assert result["tier"] == "medium"
    assert result["evidence"]["known_exploited"] is None
    assert result["evidence"]["epss_probability"] is None
