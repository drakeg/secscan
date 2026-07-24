from __future__ import annotations

import json
from pathlib import Path

import pytest

from secscan.scanners.base import ScanRequest
from secscan.scanners.registry import build_default_registry
from secscan.scanners.sbom import SBOMScanner


def _write_sbom(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "version": 1,
                "components": [],
            }
        ),
        encoding="utf-8",
    )


def test_default_registry_contains_sbom_scanner() -> None:
    assert build_default_registry().get("sbom").capability.name == "sbom"


def test_sbom_scanner_rejects_missing_file(tmp_path: Path) -> None:
    request = ScanRequest(scanner_name="sbom", target=str(tmp_path / "missing.json"))
    with pytest.raises(ValueError, match="not a file"):
        SBOMScanner().scan(request)


def test_sbom_scanner_rejects_non_cyclonedx_json(tmp_path: Path) -> None:
    path = tmp_path / "sbom.json"
    path.write_text(json.dumps({"components": []}), encoding="utf-8")
    request = ScanRequest(scanner_name="sbom", target=str(path))
    with pytest.raises(ValueError, match="CycloneDX"):
        SBOMScanner().scan(request)


def test_sbom_scanner_normalizes_results(monkeypatch, tmp_path: Path) -> None:
    path = tmp_path / "sbom.cdx.json"
    _write_sbom(path)
    payload = {
        "Results": [
            {
                "Target": str(path),
                "Type": "cyclonedx",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-TEST-1",
                        "PkgName": "example",
                        "InstalledVersion": "1.0",
                        "FixedVersion": "1.1",
                        "Severity": "HIGH",
                        "Title": "Example vulnerability",
                    }
                ],
            }
        ]
    }
    monkeypatch.setattr("secscan.scanners.sbom.scan_sbom", lambda *_args, **_kwargs: payload)
    monkeypatch.setattr(SBOMScanner, "_engine_version", staticmethod(lambda: "Trivy test"))

    result = SBOMScanner().scan(ScanRequest(scanner_name="sbom", target=str(path)))

    assert len(result.findings) == 1
    assert result.findings[0].vulnerability_id == "CVE-TEST-1"


def test_sbom_artifact_copies_input(monkeypatch, tmp_path: Path) -> None:
    source = tmp_path / "input.cdx.json"
    output = tmp_path / "reports" / "secscan.cdx.json"
    _write_sbom(source)

    SBOMScanner().generate_sbom(ScanRequest(scanner_name="sbom", target=str(source)), output)

    assert json.loads(output.read_text(encoding="utf-8"))["bomFormat"] == "CycloneDX"
