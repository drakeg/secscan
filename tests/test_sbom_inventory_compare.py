from __future__ import annotations

import json
from pathlib import Path

import pytest

from secscan.sbom_inventory_compare import compare_sbom_inventories


def _write_inventory(path: Path, packages: list[dict[str, object]]) -> None:
    path.write_text(json.dumps({"schema_version": 1, "packages": packages}), encoding="utf-8")


def _package(
    name: str,
    version: str | None,
    licenses: list[str],
    purl: str | None = None,
) -> dict[str, object]:
    return {
        "name": name,
        "version": version,
        "purl": purl,
        "declared_licenses": licenses,
    }


def test_compare_classifies_added_removed_changed_and_unchanged(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline.json"
    current = tmp_path / "current.json"
    _write_inventory(
        baseline,
        [
            _package("removed", "1", []),
            _package("changed", "1", ["MIT"], "pkg:pypi/changed@1"),
            _package("same", "1", ["Apache-2.0"]),
        ],
    )
    _write_inventory(
        current,
        [
            _package("added", "1", []),
            _package("changed", "1", ["BSD-3-Clause"], "pkg:pypi/changed@1"),
            _package("same", "1", ["Apache-2.0"]),
        ],
    )

    result = compare_sbom_inventories(baseline, current)

    assert result["summary"] == {"added": 1, "removed": 1, "changed": 1, "unchanged": 1}
    assert result["added"][0]["name"] == "added"
    assert result["removed"][0]["name"] == "removed"
    assert result["changed"][0]["identity"] == {
        "type": "purl",
        "value": "pkg:pypi/changed@1",
    }
    assert result["changed"][0]["before"]["declared_licenses"] == ["MIT"]
    assert result["changed"][0]["after"]["declared_licenses"] == ["BSD-3-Clause"]


def test_purl_identity_takes_precedence_over_name_and_version(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline.json"
    current = tmp_path / "current.json"
    purl = "pkg:generic/example@1"
    _write_inventory(baseline, [_package("old-name", "old", ["MIT"], purl)])
    _write_inventory(current, [_package("new-name", "new", ["Apache-2.0"], purl)])

    result = compare_sbom_inventories(baseline, current)

    assert result["summary"]["changed"] == 1
    assert result["summary"]["added"] == 0
    assert result["summary"]["removed"] == 0


def test_compare_rejects_duplicate_identity_and_invalid_schema(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline.json"
    current = tmp_path / "current.json"
    duplicate = _package("same", "1", [])
    _write_inventory(baseline, [duplicate, duplicate])
    _write_inventory(current, [])
    with pytest.raises(ValueError, match="duplicate package identity"):
        compare_sbom_inventories(baseline, current)

    baseline.write_text(json.dumps({"schema_version": 2, "packages": []}), encoding="utf-8")
    with pytest.raises(ValueError, match="schema_version 1"):
        compare_sbom_inventories(baseline, current)


def test_compare_normalizes_license_order_deterministically(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline.json"
    current = tmp_path / "current.json"
    _write_inventory(baseline, [_package("same", "1", ["MIT", "Apache-2.0", "MIT"])])
    _write_inventory(current, [_package("same", "1", ["Apache-2.0", "MIT"])])

    result = compare_sbom_inventories(baseline, current)

    assert result["summary"]["unchanged"] == 1
    assert result["unchanged"][0]["declared_licenses"] == ["Apache-2.0", "MIT"]
