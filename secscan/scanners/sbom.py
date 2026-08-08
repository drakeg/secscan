from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, Literal

from secscan.normalize import normalize_trivy
from secscan.scanners.base import ScanRequest, ScanResult, Scanner, ScannerCapability
from secscan.trivy import scan_sbom


class SBOMScanner(Scanner):
    @property
    def capability(self) -> ScannerCapability:
        return ScannerCapability(
            name="sbom",
            description="scan a CycloneDX or SPDX JSON SBOM",
            target_help="path to a CycloneDX or SPDX JSON SBOM",
        )

    def scan(self, request: ScanRequest) -> ScanResult:
        target, sbom_format = self._validated_target(request.target)
        raw = scan_sbom(target, timeout_seconds=request.timeout_seconds)
        findings = tuple(normalize_trivy(raw))
        return ScanResult(
            request=request,
            findings=findings,
            raw=raw,
            scanner={
                "name": "trivy",
                "version": self._engine_version(),
                "input_format": sbom_format,
            },
        )

    def generate_sbom(self, request: ScanRequest, output_path: Path) -> None:
        target, _ = self._validated_target(request.target)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        if target.resolve() != output_path.resolve():
            shutil.copyfile(target, output_path)

    def sbom_artifact_name(self, request: ScanRequest) -> str:
        _, sbom_format = self._validated_target(request.target)
        return "secscan.spdx.json" if sbom_format == "spdx" else "secscan.cdx.json"

    @staticmethod
    def _validated_target(target: str) -> tuple[Path, Literal["cyclonedx", "spdx"]]:
        path = Path(target).expanduser().resolve()
        if not path.is_file():
            raise ValueError(f"SBOM target is not a file: {path}")
        try:
            payload: Any = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"SBOM target is not valid JSON: {path}") from exc
        if not isinstance(payload, dict):
            raise ValueError("SBOM root must be an object")
        has_cyclonedx_marker = "bomFormat" in payload
        has_spdx_marker = "spdxVersion" in payload
        if has_cyclonedx_marker and has_spdx_marker:
            raise ValueError("SBOM format is ambiguous")
        if has_cyclonedx_marker:
            if payload.get("bomFormat") != "CycloneDX":
                raise ValueError("unsupported CycloneDX SBOM format")
            components = payload.get("components", [])
            if not isinstance(components, list):
                raise ValueError("CycloneDX components must be a list")
            return path, "cyclonedx"
        if has_spdx_marker:
            if payload.get("spdxVersion") not in {"SPDX-2.2", "SPDX-2.3"}:
                raise ValueError("SPDX version must be SPDX-2.2 or SPDX-2.3")
            packages = payload.get("packages", [])
            if not isinstance(packages, list):
                raise ValueError("SPDX packages must be a list")
            return path, "spdx"
        raise ValueError("SBOM must use CycloneDX JSON or SPDX 2.2/2.3 JSON format")

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
