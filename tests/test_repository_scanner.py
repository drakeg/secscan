from __future__ import annotations

from pathlib import Path

import pytest

from secscan.scanners.base import ScanRequest
from secscan.scanners.registry import build_default_registry
from secscan.scanners.repository import RepositoryScanner


def test_default_registry_contains_repository_scanner() -> None:
    registry = build_default_registry()
    assert registry.get("repository").capability.name == "repository"


def test_repository_scanner_rejects_missing_path(tmp_path: Path) -> None:
    scanner = RepositoryScanner()
    request = ScanRequest(scanner_name="repository", target=str(tmp_path / "missing"))
    with pytest.raises(ValueError, match="does not exist"):
        scanner.scan(request)


def test_repository_scanner_rejects_file_target(tmp_path: Path) -> None:
    target = tmp_path / "file.txt"
    target.write_text("content", encoding="utf-8")
    scanner = RepositoryScanner()
    request = ScanRequest(scanner_name="repository", target=str(target))
    with pytest.raises(ValueError, match="not a directory"):
        scanner.scan(request)


def test_repository_scanner_normalizes_results(monkeypatch, tmp_path: Path) -> None:
    scanner = RepositoryScanner()
    request = ScanRequest(scanner_name="repository", target=str(tmp_path))
    payload = {
        "Results": [
            {
                "Target": "requirements.txt",
                "Type": "pip",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-TEST-REPO",
                        "PkgName": "example",
                        "InstalledVersion": "1.0",
                        "FixedVersion": "1.1",
                        "Severity": "HIGH",
                        "Title": "Example repository vulnerability",
                    }
                ],
            }
        ]
    }
    monkeypatch.setattr(
        "secscan.scanners.repository.scan_repository", lambda *_args, **_kwargs: payload
    )
    monkeypatch.setattr(scanner, "_engine_version", lambda: "Trivy test")

    result = scanner.scan(request)

    assert len(result.findings) == 1
    assert result.findings[0].vulnerability_id == "CVE-TEST-REPO"
    assert result.scanner["name"] == "trivy"
