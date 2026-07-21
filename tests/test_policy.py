import pytest

from secscan.models import Finding
from secscan.policy import policy_failed


def finding(severity: str) -> Finding:
    return Finding("CVE-test", "pkg", "1", None, severity, "title", "target", None, None)


def test_policy_fails_at_or_above_threshold() -> None:
    assert policy_failed([finding("HIGH")], "HIGH") is True
    assert policy_failed([finding("CRITICAL")], "HIGH") is True
    assert policy_failed([finding("MEDIUM")], "HIGH") is False


def test_none_disables_policy_failure() -> None:
    assert policy_failed([finding("CRITICAL")], "NONE") is False


def test_invalid_threshold_is_rejected() -> None:
    with pytest.raises(ValueError):
        policy_failed([], "urgent")
