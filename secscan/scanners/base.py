from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from secscan.models import Finding


@dataclass(frozen=True)
class ScannerCapability:
    name: str
    description: str
    target_help: str


@dataclass(frozen=True)
class ScanRequest:
    scanner_name: str
    target: str
    timeout_seconds: int = 600
    output_dir: Path | None = None


@dataclass(frozen=True)
class ScanResult:
    request: ScanRequest
    findings: tuple[Finding, ...]
    raw: dict[str, Any]
    scanner: dict[str, str]


class Scanner(ABC):
    @property
    @abstractmethod
    def capability(self) -> ScannerCapability:
        raise NotImplementedError

    @abstractmethod
    def scan(self, request: ScanRequest) -> ScanResult:
        raise NotImplementedError

    @abstractmethod
    def generate_sbom(self, request: ScanRequest, output_path: Path) -> None:
        raise NotImplementedError
