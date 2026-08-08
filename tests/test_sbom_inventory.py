from __future__ import annotations

import json
from pathlib import Path

import pytest

from secscan.sbom_inventory import build_sbom_inventory, write_sbom_inventory


def test_cyclonedx_inventory_normalizes_sorts_and_counts_licenses(tmp_path: Path) -> None:
    source = tmp_path / "input.cdx.json"
    source.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": [
                    {
                        "name": "zlib",
                        "version": "1.3",
                        "purl": "pkg:generic/zlib@1.3",
                        "licenses": [
                            {"license": {"id": "Zlib"}},
                            {"license": {"id": "Zlib"}},
                        ],
                        "components": [{"name": "nested", "licenses": []}],
                    },
                    {
                        "name": "alpha",
                        "licenses": [{"expression": "MIT OR Apache-2.0"}],
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    inventory = build_sbom_inventory(source)

    assert inventory["source"] == {
        "path": str(source.resolve()),
        "format": "cyclonedx",
        "version": "1.6",
    }
    assert [package["name"] for package in inventory["packages"]] == [
        "alpha",
        "nested",
        "zlib",
    ]
    assert inventory["packages"][2]["declared_licenses"] == ["Zlib"]
    assert inventory["summary"] == {
        "package_count": 3,
        "packages_with_declared_license": 2,
        "packages_without_declared_license": 1,
        "unique_declared_license_count": 2,
    }
    assert inventory["licenses"] == [
        {"value": "MIT OR Apache-2.0", "package_count": 1},
        {"value": "Zlib", "package_count": 1},
    ]


def test_spdx_inventory_reads_purl_and_treats_noassertion_as_unlicensed(tmp_path: Path) -> None:
    source = tmp_path / "input.spdx.json"
    source.write_text(
        json.dumps(
            {
                "spdxVersion": "SPDX-2.3",
                "packages": [
                    {
                        "name": "example",
                        "versionInfo": "1.0",
                        "licenseDeclared": "MIT",
                        "externalRefs": [
                            {
                                "referenceType": "purl",
                                "referenceLocator": "pkg:pypi/example@1.0",
                            }
                        ],
                    },
                    {"name": "unknown-license", "licenseDeclared": "NOASSERTION"},
                ],
            }
        ),
        encoding="utf-8",
    )

    inventory = build_sbom_inventory(source)

    assert inventory["source"]["format"] == "spdx"
    assert inventory["packages"][0]["purl"] == "pkg:pypi/example@1.0"
    assert inventory["packages"][1]["declared_licenses"] == []
    assert inventory["summary"]["packages_without_declared_license"] == 1


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ({"bomFormat": "CycloneDX", "components": ["bad"]}, "must be an object"),
        ({"bomFormat": "CycloneDX", "components": [{}]}, "name is required"),
        (
            {
                "bomFormat": "CycloneDX",
                "components": [{"name": "x", "licenses": [{"expression": "MIT", "license": {"id": "MIT"}}]}],
            },
            "ambiguous",
        ),
        ({"spdxVersion": "SPDX-2.3", "packages": [{"name": "x", "externalRefs": {}}]}, "must be a list"),
    ],
)
def test_inventory_rejects_malformed_package_metadata(
    tmp_path: Path, payload: dict[str, object], message: str
) -> None:
    source = tmp_path / "bad.json"
    source.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match=message):
        build_sbom_inventory(source)


def test_inventory_output_is_deterministic_and_atomic(tmp_path: Path) -> None:
    source = tmp_path / "input.spdx.json"
    source.write_text(
        json.dumps({"spdxVersion": "SPDX-2.2", "packages": [{"name": "example"}]}),
        encoding="utf-8",
    )
    output = tmp_path / "nested" / "inventory.json"
    inventory = build_sbom_inventory(source)

    write_sbom_inventory(inventory, output)
    first = output.read_bytes()
    write_sbom_inventory(inventory, output)

    assert output.read_bytes() == first
    assert not list(output.parent.glob("*.tmp"))
