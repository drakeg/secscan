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


def _write_spdx(path: Path, version: str = "SPDX-2.3") -> None:
    path.write_text(
        json.dumps(
            {
                "spdxVersion": version,
                "dataLicense": "CC0-1.0",
                "SPDXID": "SPDXRef-DOCUMENT",
                "name": "example",
                "documentNamespace": "https://example.test/spdx/example",
                "creationInfo": {"created": "2026-08-07T00:00:00Z", "creators": ["Tool: test"]},
                "packages": [],
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


def test_sbom_scanner_rejects_unknown_json_format(tmp_path: Path) -> None:
    path = tmp_path / "sbom.json"
    path.write_text(json.dumps({"components": []}), encoding="utf-8")
    request = ScanRequest(scanner_name="sbom", target=str(path))
    with pytest.raises(ValueError, match="CycloneDX JSON or SPDX"):
        SBOMScanner().scan(request)


@pytest.mark.parametrize("version", ["SPDX-2.2", "SPDX-2.3"])
def test_sbom_scanner_accepts_supported_spdx(monkeypatch, tmp_path: Path, version: str) -> None:
    path = tmp_path / "sbom.spdx.json"
    _write_spdx(path, version)
    monkeypatch.setattr("secscan.scanners.sbom.scan_sbom", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(SBOMScanner, "_engine_version", staticmethod(lambda: "Trivy test"))

    result = SBOMScanner().scan(ScanRequest(scanner_name="sbom", target=str(path)))

    assert result.scanner["input_format"] == "spdx"


def test_sbom_scanner_rejects_unsupported_or_ambiguous_spdx(tmp_path: Path) -> None:
    unsupported = tmp_path / "unsupported.json"
    _write_spdx(unsupported, "SPDX-3.0")
    with pytest.raises(ValueError, match="SPDX-2.2 or SPDX-2.3"):
        SBOMScanner().scan(ScanRequest(scanner_name="sbom", target=str(unsupported)))

    ambiguous = tmp_path / "ambiguous.json"
    ambiguous.write_text(
        json.dumps({"bomFormat": "CycloneDX", "spdxVersion": "SPDX-2.3"}),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="ambiguous"):
        SBOMScanner().scan(ScanRequest(scanner_name="sbom", target=str(ambiguous)))


def test_sbom_scanner_rejects_invalid_format_collections(tmp_path: Path) -> None:
    cyclonedx = tmp_path / "bad.cdx.json"
    cyclonedx.write_text(json.dumps({"bomFormat": "CycloneDX", "components": {}}), encoding="utf-8")
    with pytest.raises(ValueError, match="components must be a list"):
        SBOMScanner().scan(ScanRequest(scanner_name="sbom", target=str(cyclonedx)))

    spdx = tmp_path / "bad.spdx.json"
    spdx.write_text(json.dumps({"spdxVersion": "SPDX-2.3", "packages": {}}), encoding="utf-8")
    with pytest.raises(ValueError, match="packages must be a list"):
        SBOMScanner().scan(ScanRequest(scanner_name="sbom", target=str(spdx)))


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


def test_spdx_artifact_name_and_copy_preserve_input(tmp_path: Path) -> None:
    source = tmp_path / "input.spdx.json"
    _write_spdx(source)
    request = ScanRequest(scanner_name="sbom", target=str(source))
    scanner = SBOMScanner()
    output = tmp_path / "reports" / scanner.sbom_artifact_name(request)

    scanner.generate_sbom(request, output)

    assert output.name == "secscan.spdx.json"
    assert output.read_bytes() == source.read_bytes()
