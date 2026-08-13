from __future__ import annotations

import json
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

    assert result["summary"] == {"package_count": 3, "violation_count": 2, "passed": False}
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
