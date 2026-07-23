from __future__ import annotations

from pathlib import Path

import pytest

from secscan.scanners.base import ScanRequest, ScanResult, Scanner, ScannerCapability
from secscan.scanners.registry import ScannerRegistry, build_default_registry


class StubScanner(Scanner):
    @property
    def capability(self) -> ScannerCapability:
        return ScannerCapability("stub", "stub scanner", "stub target")

    def scan(self, request: ScanRequest) -> ScanResult:
        return ScanResult(request=request, findings=(), raw={}, scanner={"name": "stub"})

    def generate_sbom(self, request: ScanRequest, output_path: Path) -> None:
        output_path.write_text("{}", encoding="utf-8")


def test_default_registry_contains_builtin_scanners() -> None:
    registry = build_default_registry()

    assert registry.get("image").capability.name == "image"
    assert registry.get("filesystem").capability.name == "filesystem"
    assert [capability.name for capability in registry.capabilities()] == [
        "filesystem",
        "image",
    ]


def test_registry_rejects_duplicate_scanner_names() -> None:
    registry = ScannerRegistry([StubScanner()])

    with pytest.raises(ValueError, match="already registered"):
        registry.register(StubScanner())


def test_registry_reports_available_scanners_for_unknown_name() -> None:
    registry = ScannerRegistry([StubScanner()])

    with pytest.raises(ValueError, match="available scanners: stub"):
        registry.get("missing")
