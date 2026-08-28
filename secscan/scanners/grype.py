from __future__ import annotations

import json
from pathlib import Path
import subprocess
from typing import Any

from secscan.models import Finding
from secscan.normalize import SEVERITIES
from secscan.scanners.base import ScanRequest, ScanResult, Scanner, ScannerCapability


def _normalize_grype(payload: dict[str, Any], target: str) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    for match in payload.get("matches") or []:
        vulnerability = match.get("vulnerability") or {}
        artifact = match.get("artifact") or {}
        severity = str(vulnerability.get("severity") or "UNKNOWN").upper()
        if severity not in SEVERITIES:
            severity = "UNKNOWN"
        fix = vulnerability.get("fix") or {}
        versions = fix.get("versions") or []
        urls = vulnerability.get("urls") or []
        findings.append(
            Finding(
                vulnerability_id=str(vulnerability.get("id") or "UNKNOWN"),
                package_name=str(artifact.get("name") or "unknown"),
                installed_version=str(artifact.get("version") or "unknown"),
                fixed_version=", ".join(str(version) for version in versions) or None,
                severity=severity,
                title=str(vulnerability.get("description") or vulnerability.get("id") or "No title provided"),
                target=target,
                package_type=str(artifact.get("type")) if artifact.get("type") else None,
                primary_url=str(urls[0]) if urls else None,
            )
        )
    return tuple(findings)


class GrypeImageScanner(Scanner):
    @property
    def capability(self) -> ScannerCapability:
        return ScannerCapability(
            name="image-grype",
            description="scan a container image with Grype for complementary vulnerability coverage",
            target_help="image reference, for example alpine:3.20",
        )

    def scan(self, request: ScanRequest) -> ScanResult:
        try:
            completed = subprocess.run(
                ["grype", request.target, "-o", "json", "--only-fixed=false"],
                check=False,
                capture_output=True,
                text=True,
                timeout=request.timeout_seconds,
                env=dict(request.environment) if request.environment is not None else None,
            )
        except FileNotFoundError as exc:
            raise RuntimeError("Grype executable not found") from exc
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"Grype timed out after {request.timeout_seconds} seconds") from exc
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout).strip()
            raise RuntimeError(f"Grype failed with exit code {completed.returncode}: {detail[:500]}")
        try:
            raw = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError("Grype returned invalid JSON") from exc
        if not isinstance(raw, dict):
            raise RuntimeError("Grype returned an unexpected JSON document")
        return ScanResult(
            request=request,
            findings=_normalize_grype(raw, request.target),
            raw=raw,
            scanner={"name": "grype", "version": self._engine_version()},
        )

    def generate_sbom(self, request: ScanRequest, output_path: Path) -> None:
        raise RuntimeError("Grype adapter does not generate SBOMs; use the existing SBOM scanner")

    def raw_artifact_name(self, request: ScanRequest) -> str:
        return "grype.json"

    @staticmethod
    def _engine_version() -> str:
        try:
            completed = subprocess.run(
                ["grype", "version", "-o", "json"],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return "unknown"
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError:
            return "unknown"
        return str(payload.get("version") or "unknown")
