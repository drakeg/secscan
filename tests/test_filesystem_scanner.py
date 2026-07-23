from __future__ import annotations

from pathlib import Path

import pytest

from secscan.scanners.base import ScanRequest
from secscan.scanners.filesystem import FilesystemScanner
from secscan.scanners.registry import build_default_registry


def test_default_registry_contains_filesystem_scanner() -> None:
    registry = build_default_registry()

    assert registry.get("filesystem").capability.name == "filesystem"


def test_filesystem_scanner_rejects_missing_path(tmp_path: Path) -> None:
    scanner = FilesystemScanner()
    request = ScanRequest(scanner_name="filesystem", target=str(tmp_path / "missing"))

    with pytest.raises(ValueError, match="does not exist"):
        scanner.scan(request)


def test_filesystem_scanner_normalizes_results(monkeypatch, tmp_path: Path) -> None:
    scanner = FilesystemScanner()
    request = ScanRequest(scanner_name="filesystem", target=str(tmp_path))
    payload = {
        "Results": [
            {
                "Target": str(tmp_path),
                "Type": "filesystem",
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

    monkeypatch.setattr("secscan.scanners.filesystem.scan_filesystem", lambda *_args, **_kwargs: payload)
    monkeypatch.setattr(scanner, "_engine_version", lambda: "Trivy test")

    result = scanner.scan(request)

    assert len(result.findings) == 1
    assert result.findings[0].vulnerability_id == "CVE-TEST-1"
    assert result.scanner["name"] == "trivy"
