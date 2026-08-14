from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pytest

from secscan.license_policy import evaluate_license_policy, load_license_policy


def _write_inventory(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "packages": [
                    {"name": "allowed", "version": "1", "purl": None, "declared_licenses": ["MIT"]},
                    {"name": "denied", "version": "1", "purl": None, "declared_licenses": ["GPL-3.0-only"]},
                    {"name": "missing", "version": "1", "purl": None, "declared_licenses": []},
                ],
            }
        ),
        encoding="utf-8",
    )


def test_policy_reports_denied_not_allowed_and_missing(tmp_path: Path) -> None:
    inventory = tmp_path / "inventory.json"
    policy_path = tmp_path / "policy.yaml"
    _write_inventory(inventory)
    policy_path.write_text(
        """license_policy:
  allow: [MIT]
  deny: [GPL-3.0-only]
  require_declared: true
""",
        encoding="utf-8",
    )

    result = evaluate_license_policy(inventory, load_license_policy(policy_path))

    assert result["summary"] == {
        "package_count": 3,
        "violation_count": 2,
        "suppressed_count": 0,
        "passed": False,
    }
    assert [item["package"]["name"] for item in result["violations"]] == ["denied", "missing"]
    assert result["violations"][0]["reasons"] == ["declared license is denied: GPL-3.0-only"]
    assert result["violations"][1]["reasons"] == ["declared license is required"]


def test_allow_values_are_exact_opaque_strings(tmp_path: Path) -> None:
    inventory = tmp_path / "inventory.json"
    inventory.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "packages": [
                    {
                        "name": "expression",
                        "version": None,
                        "purl": None,
                        "declared_licenses": ["MIT OR Apache-2.0"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text("license_policy:\n  allow: [MIT, Apache-2.0]\n", encoding="utf-8")

    result = evaluate_license_policy(inventory, load_license_policy(policy_path))

    assert result["summary"]["violation_count"] == 1
    assert "MIT OR Apache-2.0" in result["violations"][0]["reasons"][0]


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("license_policy:\n  unknown: true\n", "unknown keys"),
        ("license_policy:\n  allow: [MIT, MIT]\n", "duplicate values"),
        ("license_policy:\n  allow: [MIT]\n  deny: [MIT]\n", "both allowed and denied"),
        ("license_policy:\n  require_declared: 'yes'\n", "true or false"),
        ("license_policy:\n  deny: GPL-3.0-only\n", "must be a list"),
    ],
)
def test_policy_rejects_invalid_configuration(tmp_path: Path, content: str, message: str) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text(content, encoding="utf-8")

    with pytest.raises(ValueError, match=message):
        load_license_policy(path)


def test_empty_allow_list_rejects_all_declared_values(tmp_path: Path) -> None:
    inventory = tmp_path / "inventory.json"
    _write_inventory(inventory)
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text("license_policy:\n  allow: []\n", encoding="utf-8")

    result = evaluate_license_policy(inventory, load_license_policy(policy_path))

    assert result["summary"]["violation_count"] == 2


def test_active_purl_exception_suppresses_exact_license_violation(tmp_path: Path) -> None:
    inventory = tmp_path / "inventory.json"
    inventory.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "packages": [
                    {
                        "name": "example",
                        "version": "1",
                        "purl": "pkg:pypi/example@1",
                        "declared_licenses": ["GPL-3.0-only"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """license_policy:
  deny: [GPL-3.0-only]
  exceptions:
    - package:
        purl: pkg:pypi/example@1
      license: GPL-3.0-only
      reason: Replacement is scheduled
      expires: 2026-08-13
""",
        encoding="utf-8",
    )

    result = evaluate_license_policy(
        inventory, load_license_policy(policy_path), today=date(2026, 8, 13)
    )

    assert result["summary"] == {
        "package_count": 1,
        "violation_count": 0,
        "suppressed_count": 1,
        "passed": True,
    }
    assert result["violations"] == []
    assert result["suppressed"][0]["reason"] == "Replacement is scheduled"
    assert result["suppressed"][0]["expires"] == "2026-08-13"


def test_expired_exception_and_wrong_license_do_not_suppress(tmp_path: Path) -> None:
    inventory = tmp_path / "inventory.json"
    _write_inventory(inventory)
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """license_policy:
  deny: [GPL-3.0-only]
  exceptions:
    - package:
        name: denied
        version: '1'
      license: MIT
      reason: Wrong license
      expires: 2026-09-30
    - package:
        name: denied
        version: '1'
      license: GPL-3.0-only
      reason: Expired approval
      expires: 2026-08-12
""",
        encoding="utf-8",
    )

    result = evaluate_license_policy(
        inventory, load_license_policy(policy_path), today=date(2026, 8, 13)
    )

    assert result["summary"]["violation_count"] == 1
    assert result["summary"]["suppressed_count"] == 0


def test_name_version_exception_cannot_shadow_package_with_purl(tmp_path: Path) -> None:
    inventory = tmp_path / "inventory.json"
    inventory.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "packages": [
                    {
                        "name": "example",
                        "version": "1",
                        "purl": "pkg:pypi/example@1",
                        "declared_licenses": ["GPL-3.0-only"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """license_policy:
  deny: [GPL-3.0-only]
  exceptions:
    - package:
        name: example
        version: '1'
      license: GPL-3.0-only
      reason: Fallback must not shadow PURL
      expires: 2026-09-30
""",
        encoding="utf-8",
    )

    result = evaluate_license_policy(
        inventory, load_license_policy(policy_path), today=date(2026, 8, 13)
    )

    assert result["summary"]["violation_count"] == 1
    assert result["summary"]["suppressed_count"] == 0


@pytest.mark.parametrize(
    ("exception", "message"),
    [
        ("{}", "package must be a mapping"),
        ("package: {purl: ''}\n      license: MIT\n      reason: Test\n      expires: 2026-09-30", "purl"),
        ("package: {name: example}\n      license: MIT\n      reason: Test\n      expires: 2026-09-30", "name and version"),
        ("package: {purl: pkg:pypi/example@1}\n      license: ''\n      reason: Test\n      expires: 2026-09-30", "requires license"),
        ("package: {purl: pkg:pypi/example@1}\n      license: MIT\n      reason: ''\n      expires: 2026-09-30", "requires reason"),
        ("package: {purl: pkg:pypi/example@1}\n      license: MIT\n      reason: Test\n      expires: soon", "YYYY-MM-DD"),
    ],
)
def test_policy_rejects_invalid_exception(
    tmp_path: Path, exception: str, message: str
) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text(
        f"license_policy:\n  exceptions:\n    - {exception}\n", encoding="utf-8"
    )

    with pytest.raises(ValueError, match=message):
        load_license_policy(path)


def test_policy_rejects_duplicate_exception_match(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text(
        """license_policy:
  exceptions:
    - package: {purl: pkg:pypi/example@1}
      license: MIT
      reason: First approval
      expires: 2026-09-30
    - package: {purl: pkg:pypi/example@1}
      license: MIT
      reason: Duplicate approval
      expires: 2026-10-31
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="duplicate package and license"):
        load_license_policy(path)
