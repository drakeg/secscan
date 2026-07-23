from __future__ import annotations

import subprocess
from pathlib import Path

from secscan.normalize import normalize_trivy
from secscan.scanners.base import ScanRequest, ScanResult, Scanner, ScannerCapability
from secscan.trivy import generate_cyclonedx, scan_image


class ImageScanner(Scanner):
    @property
    def capability(self) -> ScannerCapability:
        return ScannerCapability(
            name="image",
            description="scan a container image",
            target_help="image reference, for example alpine:3.20",
        )

    def scan(self, request: ScanRequest) -> ScanResult:
        raw = scan_image(request.target, timeout_seconds=request.timeout_seconds)
        findings = tuple(normalize_trivy(raw))
        return ScanResult(
            request=request,
            findings=findings,
            raw=raw,
            scanner={"name": "trivy", "version": self._engine_version()},
        )

    def generate_sbom(self, request: ScanRequest, output_path: Path) -> None:
        generate_cyclonedx(
            request.target,
            output_path,
            timeout_seconds=request.timeout_seconds,
        )

    @staticmethod
    def _engine_version() -> str:
        try:
            completed = subprocess.run(
                ["trivy", "--version"],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return "unknown"
        return (completed.stdout or completed.stderr).strip().splitlines()[0] or "unknown"
