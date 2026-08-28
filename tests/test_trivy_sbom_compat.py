from __future__ import annotations

import json
from pathlib import Path

from secscan.trivy import _trivy_compatible_sbom


def test_trivy_compatible_sbom_rewrites_device_root_only_in_temp_copy(tmp_path: Path) -> None:
    original = tmp_path / "linux-host.cdx.json"
    payload = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "type": "device",
                "name": "linux-host-fixture",
                "version": "12",
            }
        },
        "components": [
            {
                "type": "library",
                "name": "openssl",
                "version": "3.0.0",
            }
        ],
    }
    original.write_text(json.dumps(payload), encoding="utf-8")
    compatibility_dir = tmp_path / "compat"
    compatibility_dir.mkdir()

    compatible = _trivy_compatible_sbom(original, compatibility_dir)

    assert compatible != original
    assert json.loads(original.read_text(encoding="utf-8"))["metadata"]["component"]["type"] == "device"
    compatible_payload = json.loads(compatible.read_text(encoding="utf-8"))
    assert compatible_payload["metadata"]["component"]["type"] == "application"
    assert compatible_payload["metadata"]["component"]["name"] == "linux-host-fixture"
    assert compatible_payload["components"] == payload["components"]


def test_trivy_compatible_sbom_leaves_supported_component_type_unchanged(tmp_path: Path) -> None:
    original = tmp_path / "application.cdx.json"
    original.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "metadata": {"component": {"type": "application", "name": "fixture"}},
            }
        ),
        encoding="utf-8",
    )

    assert _trivy_compatible_sbom(original, tmp_path) == original
