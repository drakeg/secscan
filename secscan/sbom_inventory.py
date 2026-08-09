from __future__ import annotations

from collections import Counter
import json
import os
from pathlib import Path
from typing import Any, TypedDict

from secscan.scanners.sbom import SBOMScanner


class InventoryPackage(TypedDict):
    name: str
    version: str | None
    purl: str | None
    declared_licenses: list[str]


def _optional_string(value: object, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    text = value.strip()
    return text or None


def _cyclonedx_licenses(component: dict[str, Any], index: str) -> list[str]:
    raw_licenses = component.get("licenses", [])
    if not isinstance(raw_licenses, list):
        raise ValueError(f"CycloneDX component {index} licenses must be a list")
    licenses: set[str] = set()
    for license_index, entry in enumerate(raw_licenses):
        if not isinstance(entry, dict):
            raise ValueError(
                f"CycloneDX component {index} license {license_index} must be an object"
            )
        expression = _optional_string(
            entry.get("expression"),
            f"CycloneDX component {index} license {license_index} expression",
        )
        license_value = entry.get("license")
        if expression is not None and license_value is not None:
            raise ValueError(
                f"CycloneDX component {index} license {license_index} is ambiguous"
            )
        if expression is not None:
            licenses.add(expression)
            continue
        if not isinstance(license_value, dict):
            raise ValueError(
                f"CycloneDX component {index} license {license_index} must define license or expression"
            )
        identifier = _optional_string(
            license_value.get("id"),
            f"CycloneDX component {index} license {license_index} id",
        )
        name = _optional_string(
            license_value.get("name"),
            f"CycloneDX component {index} license {license_index} name",
        )
        if identifier is not None and name is not None:
            raise ValueError(
                f"CycloneDX component {index} license {license_index} has both id and name"
            )
        if identifier is None and name is None:
            raise ValueError(
                f"CycloneDX component {index} license {license_index} has no id or name"
            )
        licenses.add(identifier or name or "")
    return sorted(licenses)


def _cyclonedx_packages(payload: dict[str, Any]) -> list[InventoryPackage]:
    packages: list[InventoryPackage] = []
    top_level = payload.get("components", [])
    pending: list[tuple[str, object]] = [
        (str(index), component) for index, component in reversed(list(enumerate(top_level)))
    ]
    while pending:
        index, component = pending.pop()
        if not isinstance(component, dict):
            raise ValueError(f"CycloneDX component {index} must be an object")
        name = _optional_string(component.get("name"), f"CycloneDX component {index} name")
        if name is None:
            raise ValueError(f"CycloneDX component {index} name is required")
        packages.append(
            {
                "name": name,
                "version": _optional_string(
                    component.get("version"), f"CycloneDX component {index} version"
                ),
                "purl": _optional_string(
                    component.get("purl"), f"CycloneDX component {index} purl"
                ),
                "declared_licenses": _cyclonedx_licenses(component, index),
            }
        )
        nested = component.get("components", [])
        if not isinstance(nested, list):
            raise ValueError(f"CycloneDX component {index} components must be a list")
        pending.extend(
            (f"{index}.{nested_index}", child)
            for nested_index, child in reversed(list(enumerate(nested)))
        )
    return packages


def _spdx_purl(package: dict[str, Any], index: int) -> str | None:
    references = package.get("externalRefs", [])
    if not isinstance(references, list):
        raise ValueError(f"SPDX package {index} externalRefs must be a list")
    purls: set[str] = set()
    for reference_index, reference in enumerate(references):
        if not isinstance(reference, dict):
            raise ValueError(f"SPDX package {index} external reference {reference_index} must be an object")
        reference_type = _optional_string(
            reference.get("referenceType"),
            f"SPDX package {index} external reference {reference_index} type",
        )
        locator = _optional_string(
            reference.get("referenceLocator"),
            f"SPDX package {index} external reference {reference_index} locator",
        )
        if reference_type is None or locator is None:
            raise ValueError(
                f"SPDX package {index} external reference {reference_index} requires type and locator"
            )
        if reference_type.casefold() == "purl":
            purls.add(locator)
    if len(purls) > 1:
        raise ValueError(f"SPDX package {index} has multiple distinct PURLs")
    return next(iter(purls), None)


def _spdx_packages(payload: dict[str, Any]) -> list[InventoryPackage]:
    packages: list[InventoryPackage] = []
    for index, package in enumerate(payload.get("packages", [])):
        if not isinstance(package, dict):
            raise ValueError(f"SPDX package {index} must be an object")
        name = _optional_string(package.get("name"), f"SPDX package {index} name")
        if name is None:
            raise ValueError(f"SPDX package {index} name is required")
        declared = _optional_string(
            package.get("licenseDeclared"), f"SPDX package {index} licenseDeclared"
        )
        declared_licenses = (
            [] if declared is None or declared.upper() in {"NONE", "NOASSERTION"} else [declared]
        )
        packages.append(
            {
                "name": name,
                "version": _optional_string(
                    package.get("versionInfo"), f"SPDX package {index} versionInfo"
                ),
                "purl": _spdx_purl(package, index),
                "declared_licenses": declared_licenses,
            }
        )
    return packages


def build_sbom_inventory(target: Path) -> dict[str, object]:
    source, sbom_format = SBOMScanner._validated_target(str(target))
    payload = json.loads(source.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    packages = (
        _cyclonedx_packages(payload) if sbom_format == "cyclonedx" else _spdx_packages(payload)
    )
    packages.sort(
        key=lambda package: (
            str(package["name"]).casefold(),
            str(package["version"] or ""),
            str(package["purl"] or ""),
            tuple(package["declared_licenses"]),
        )
    )
    license_counts: Counter[str] = Counter()
    for package in packages:
        license_counts.update(set(package["declared_licenses"]))
    licensed_packages = sum(bool(package["declared_licenses"]) for package in packages)
    source_version = (
        payload.get("specVersion") if sbom_format == "cyclonedx" else payload.get("spdxVersion")
    )
    return {
        "schema_version": 1,
        "source": {
            "path": str(source),
            "format": sbom_format,
            "version": str(source_version) if source_version is not None else None,
        },
        "summary": {
            "package_count": len(packages),
            "packages_with_declared_license": licensed_packages,
            "packages_without_declared_license": len(packages) - licensed_packages,
            "unique_declared_license_count": len(license_counts),
        },
        "licenses": [
            {"value": value, "package_count": license_counts[value]}
            for value in sorted(license_counts)
        ],
        "packages": packages,
    }


def write_json_atomic(document: dict[str, object], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.{os.getpid()}.tmp")
    try:
        temporary.write_text(
            json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        temporary.replace(output)
    finally:
        temporary.unlink(missing_ok=True)


def write_sbom_inventory(inventory: dict[str, object], output: Path) -> None:
    write_json_atomic(inventory, output)
