from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from secscan.sbom_inventory import InventoryPackage

PackageIdentity = tuple[str, ...]


def _optional_string(value: object, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string or null")
    return value.strip()


def _package_identity(package: InventoryPackage) -> PackageIdentity:
    if package["purl"] is not None:
        return ("purl", package["purl"])
    return ("name_version", package["name"], package["version"] or "")


def _identity_document(identity: PackageIdentity) -> dict[str, object]:
    if identity[0] == "purl":
        return {"type": "purl", "value": identity[1]}
    return {
        "type": "name_version",
        "name": identity[1],
        "version": identity[2] or None,
    }


def load_sbom_inventory(path: Path) -> dict[PackageIdentity, InventoryPackage]:
    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        raise ValueError(f"inventory is not a file: {resolved}")
    try:
        payload: Any = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"inventory is not valid JSON: {resolved}") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise ValueError("inventory must use schema_version 1")
    raw_packages = payload.get("packages")
    if not isinstance(raw_packages, list):
        raise ValueError("inventory packages must be a list")

    packages: dict[PackageIdentity, InventoryPackage] = {}
    for index, raw_package in enumerate(raw_packages):
        if not isinstance(raw_package, dict):
            raise ValueError(f"inventory package {index} must be an object")
        name = _optional_string(raw_package.get("name"), f"inventory package {index} name")
        if name is None:
            raise ValueError(f"inventory package {index} name is required")
        version = _optional_string(
            raw_package.get("version"), f"inventory package {index} version"
        )
        purl = _optional_string(raw_package.get("purl"), f"inventory package {index} purl")
        raw_licenses = raw_package.get("declared_licenses")
        if not isinstance(raw_licenses, list) or any(
            not isinstance(value, str) or not value.strip() for value in raw_licenses
        ):
            raise ValueError(
                f"inventory package {index} declared_licenses must be a list of non-empty strings"
            )
        licenses = sorted({value.strip() for value in raw_licenses})
        package: InventoryPackage = {
            "name": name,
            "version": version,
            "purl": purl,
            "declared_licenses": licenses,
        }
        identity = _package_identity(package)
        if identity in packages:
            raise ValueError(
                f"inventory contains duplicate package identity: {_identity_document(identity)}"
            )
        packages[identity] = package
    return packages


def compare_sbom_inventories(baseline: Path, current: Path) -> dict[str, object]:
    baseline_path = baseline.expanduser().resolve()
    current_path = current.expanduser().resolve()
    baseline_packages = load_sbom_inventory(baseline_path)
    current_packages = load_sbom_inventory(current_path)
    baseline_ids = set(baseline_packages)
    current_ids = set(current_packages)

    added_ids = sorted(current_ids - baseline_ids)
    removed_ids = sorted(baseline_ids - current_ids)
    changed_ids: list[PackageIdentity] = []
    unchanged_ids: list[PackageIdentity] = []
    for identity in sorted(baseline_ids & current_ids):
        if (
            baseline_packages[identity]["declared_licenses"]
            != current_packages[identity]["declared_licenses"]
        ):
            changed_ids.append(identity)
        else:
            unchanged_ids.append(identity)

    return {
        "schema_version": 1,
        "baseline": str(baseline_path),
        "current": str(current_path),
        "summary": {
            "added": len(added_ids),
            "removed": len(removed_ids),
            "changed": len(changed_ids),
            "unchanged": len(unchanged_ids),
        },
        "added": [current_packages[identity] for identity in added_ids],
        "removed": [baseline_packages[identity] for identity in removed_ids],
        "changed": [
            {
                "identity": _identity_document(identity),
                "before": baseline_packages[identity],
                "after": current_packages[identity],
            }
            for identity in changed_ids
        ],
        "unchanged": [current_packages[identity] for identity in unchanged_ids],
    }
