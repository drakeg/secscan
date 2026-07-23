from __future__ import annotations

import os
import subprocess
from pathlib import Path

from secscan.normalize import normalize_trivy
from secscan.scanners.base import ScanRequest, ScanResult, Scanner, ScannerCapability
from secscan.trivy import generate_filesystem_cyclonedx, scan_filesystem


class FilesystemScanner(Scanner):
    @property
    def capability(self) -> ScannerCapability:
        return ScannerCapability(
            name="filesystem",
            description="scan a local filesystem path",
            target_help="path to scan, for example /scan or .",
        )

    def scan(self, request: ScanRequest) -> ScanResult:
        target = self._validated_target(request.target)
        raw = scan_filesystem(target, timeout_seconds=request.timeout_seconds)
        findings = tuple(normalize_trivy(raw))
        return ScanResult(
            request=request,
            findings=findings,
            raw=raw,
            scanner={"name": "trivy", "version": self._engine_version()},
        )

    def generate_sbom(self, request: ScanRequest, output_path: Path) -> None:
        target = self._validated_target(request.target)
        generate_filesystem_cyclonedx(
            target,
            output_path,
            timeout_seconds=request.timeout_seconds,
        )

    @staticmethod
    def _validated_target(target: str) -> Path:
        path = Path(target).expanduser().resolve()
        if not path.exists():
            raise ValueError(f"filesystem target does not exist: {path}")
        if not os.access(path, os.R_OK):
            raise ValueError(f"filesystem target is not readable: {path}")
        return path

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
