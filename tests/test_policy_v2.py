from datetime import date
from pathlib import Path

import pytest

from secscan.models import Finding
from secscan.policy import (
    Policy,
    PolicyRule,
    Suppression,
    evaluate_policy,
    load_policy,
    policy_failed,
)


def finding(
    *,
    vulnerability: str = "CVE-2026-1000",
    package: str = "openssl",
    severity: str = "HIGH",
    fixed_version: str | None = "3.0.1",
    published: date | None = date(2026, 1, 1),
) -> Finding:
    return Finding(
        vulnerability_id=vulnerability,
        package_name=package,
        installed_version="3.0.0",
        fixed_version=fixed_version,
        severity=severity,
        title="test",
        target="target",
        package_type="apk",
        primary_url=None,
        published_date=published,
    )


def test_load_policy_v2_rules(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text(
        """policy:
  fail_on: CRITICAL
rules:
  - package: openssl
    fix_available: true
    fail_on: HIGH
    reason: Patchable OpenSSL finding
  - severity: MEDIUM
    max_age_days: 30
    fail_on: MEDIUM
""",
        encoding="utf-8",
    )

    policy = load_policy(path)

    assert len(policy.rules) == 2
    assert policy.rules[0].package_name == "openssl"
    assert policy.rules[0].fix_available is True
    assert policy.rules[1].max_age_days == 30


def test_package_and_fix_rule_causes_failure() -> None:
    policy = Policy(
        fail_on="CRITICAL",
        rules=(
            PolicyRule(
                package_name="openssl",
                fix_available=True,
                fail_on="HIGH",
                reason="Patchable OpenSSL finding",
            ),
        ),
    )

    item = finding()
    evaluation = evaluate_policy([item], policy, today=date(2026, 7, 24))

    assert len(evaluation.rule_matches) == 1
    assert evaluation.rule_matches[0].reason == "Patchable OpenSSL finding"
    assert policy_failed([item], policy.fail_on, policy=policy, today=date(2026, 7, 24))


def test_age_rule_skips_findings_without_publication_date() -> None:
    policy = Policy(
        rules=(
            PolicyRule(
                max_age_days=30,
                fail_on="HIGH",
                reason="Old vulnerability",
            ),
        )
    )

    item = finding(published=None)

    assert evaluate_policy([item], policy, today=date(2026, 7, 24)).rule_matches == ()


def test_suppression_precedes_policy_v2_rules() -> None:
    policy = Policy(
        suppressions=(
            Suppression(
                vulnerability_id="CVE-2026-1000",
                reason="Temporary exception",
                expires=date(2026, 8, 1),
            ),
        ),
        rules=(
            PolicyRule(
                vulnerability_id="CVE-2026-1000",
                fail_on="HIGH",
                reason="Blocked CVE",
            ),
        ),
    )

    evaluation = evaluate_policy([finding()], policy, today=date(2026, 7, 24))

    assert len(evaluation.suppressed_findings) == 1
    assert evaluation.rule_matches == ()


def test_unknown_rule_keys_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text(
        "rules:\n  - package: openssl\n    magic: true\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="unknown keys: magic"):
        load_policy(path)


def test_conflicting_duplicate_rules_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text(
        """rules:
  - package: openssl
    fail_on: HIGH
  - package: openssl
    fail_on: MEDIUM
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="conflicts"):
        load_policy(path)
