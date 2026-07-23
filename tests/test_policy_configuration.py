from datetime import date
from pathlib import Path

import pytest

from secscan.models import Finding
from secscan.policy import Policy, Suppression, evaluate_policy, load_policy


def finding(vulnerability_id: str = "CVE-2026-1234", package: str = "openssl") -> Finding:
    return Finding(
        vulnerability_id,
        package,
        "1.0",
        "1.1",
        "HIGH",
        "test vulnerability",
        "target",
        "apk",
        None,
    )


def test_load_policy_parses_threshold_and_suppression(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """policy:\n  fail_on: HIGH\nsuppressions:\n  - vulnerability: CVE-2026-1234\n    package: openssl\n    reason: Vendor patch scheduled\n    expires: 2026-09-30\n""",
        encoding="utf-8",
    )

    policy = load_policy(policy_path)

    assert policy.fail_on == "HIGH"
    assert policy.suppressions[0].reason == "Vendor patch scheduled"
    assert policy.suppressions[0].expires == date(2026, 9, 30)


def test_active_suppression_removes_matching_finding() -> None:
    policy = Policy(
        suppressions=(
            Suppression(
                vulnerability_id="CVE-2026-1234",
                package_name="openssl",
                reason="Vendor patch scheduled",
                expires=date(2026, 9, 30),
            ),
        )
    )

    result = evaluate_policy([finding()], policy, today=date(2026, 7, 23))

    assert result.active_findings == ()
    assert len(result.suppressed_findings) == 1


def test_expired_suppression_does_not_hide_finding() -> None:
    policy = Policy(
        suppressions=(
            Suppression(
                vulnerability_id="CVE-2026-1234",
                reason="Temporary exception",
                expires=date(2026, 7, 22),
            ),
        )
    )

    result = evaluate_policy([finding()], policy, today=date(2026, 7, 23))

    assert result.active_findings == (finding(),)
    assert result.suppressed_findings == ()


def test_suppression_requires_reason_and_expiration(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        "suppressions:\n  - vulnerability: CVE-2026-1234\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="requires reason"):
        load_policy(policy_path)
