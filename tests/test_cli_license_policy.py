from __future__ import annotations

import json
from pathlib import Path

from secscan.cli import main


def _write_inventory(path: Path, license_value: str) -> None:
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "packages": [
                    {"name": "example", "version": "1", "purl": None, "declared_licenses": [license_value]}
                ],
            }
        ),
        encoding="utf-8",
    )


def test_check_inventory_returns_two_and_writes_evidence(tmp_path: Path, capsys: object) -> None:
    inventory = tmp_path / "inventory.json"
    policy = tmp_path / "policy.yaml"
    output = tmp_path / "evidence.json"
    _write_inventory(inventory, "GPL-3.0-only")
    policy.write_text("license_policy:\n  deny: [GPL-3.0-only]\n", encoding="utf-8")

    exit_code = main(
        ["check", "inventory", str(inventory), "--policy", str(policy), "--output", str(output)]
    )

    assert exit_code == 2
    assert json.loads(output.read_text(encoding="utf-8"))["summary"]["violation_count"] == 1
    assert '"passed": false' in capsys.readouterr().out  # type: ignore[attr-defined]


def test_check_inventory_returns_zero_when_policy_passes(tmp_path: Path) -> None:
    inventory = tmp_path / "inventory.json"
    policy = tmp_path / "policy.yaml"
    output = tmp_path / "evidence.json"
    _write_inventory(inventory, "MIT")
    policy.write_text("license_policy:\n  allow: [MIT]\n", encoding="utf-8")

    assert main(
        ["check", "inventory", str(inventory), "--policy", str(policy), "--output", str(output)]
    ) == 0


def test_check_inventory_returns_one_for_invalid_policy(tmp_path: Path, capsys: object) -> None:
    inventory = tmp_path / "inventory.json"
    policy = tmp_path / "policy.yaml"
    _write_inventory(inventory, "MIT")
    policy.write_text("license_policy:\n  require_declared: maybe\n", encoding="utf-8")

    assert main(["check", "inventory", str(inventory), "--policy", str(policy)]) == 1
    assert "true or false" in capsys.readouterr().err  # type: ignore[attr-defined]
