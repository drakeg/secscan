from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Iterable

from secscan.models import Finding
from secscan.normalize import normalize_trivy
from secscan.scanners.base import ScanRequest, ScanResult, Scanner, ScannerCapability
from secscan.scanners.repository import RepositoryScanner
from secscan.trivy import generate_repository_cyclonedx, scan_repository


def _as_dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _severity(value: object, *, default: str = "UNKNOWN") -> str:
    normalized = str(value or "").upper()
    if normalized in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}:
        return normalized
    return {
        "ERROR": "HIGH",
        "WARNING": "MEDIUM",
        "WARN": "MEDIUM",
        "INFO": "LOW",
        "NOTE": "LOW",
    }.get(normalized, default)


def _run_json(command: list[str], *, timeout: int, tool: str) -> Any:
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise ValueError(f"{tool} is required for a full repository scan") from exc
    except subprocess.TimeoutExpired as exc:
        raise ValueError(f"{tool} scan timed out") from exc
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip().splitlines()
        message = detail[-1] if detail else f"exit code {completed.returncode}"
        raise ValueError(f"{tool} scan failed: {message}")
    try:
        return json.loads(completed.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise ValueError(f"{tool} returned invalid JSON") from exc


def _tool_version(command: list[str]) -> str:
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return "unknown"
    output = (completed.stdout or completed.stderr).strip().splitlines()
    return output[0] if output else "unknown"


def _semgrep_findings(payload: object) -> list[Finding]:
    if not isinstance(payload, dict):
        return []
    findings: list[Finding] = []
    results = payload.get("results")
    if not isinstance(results, list):
        return findings
    for item in results:
        if not isinstance(item, dict):
            continue
        extra = _as_dict(item.get("extra"))
        start = _as_dict(item.get("start"))
        metadata = _as_dict(extra.get("metadata"))
        path = str(item.get("path") or "unknown")
        line = start.get("line")
        target = f"{path}:{line}" if isinstance(line, int) else path
        rule_id = str(item.get("check_id") or "SEMGREP")
        message = str(extra.get("message") or rule_id)
        reference = metadata.get("source") or metadata.get("reference")
        if isinstance(reference, list):
            reference = reference[0] if reference else None
        findings.append(
            Finding(
                vulnerability_id=rule_id,
                package_name="source-code",
                installed_version="detected",
                fixed_version=None,
                severity=_severity(extra.get("severity")),
                title=f"[Semgrep] {message}",
                target=target,
                package_type="sast/semgrep",
                primary_url=str(reference) if reference else None,
            )
        )
    return findings


def _gitleaks_findings(payload: object) -> list[Finding]:
    if not isinstance(payload, list):
        return []
    findings: list[Finding] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        rule_id = str(item.get("RuleID") or item.get("RuleId") or "GITLEAKS")
        description = str(item.get("Description") or rule_id)
        path = str(item.get("File") or "unknown")
        line = item.get("StartLine")
        target = f"{path}:{line}" if isinstance(line, int) else path
        findings.append(
            Finding(
                vulnerability_id=rule_id,
                package_name="secret",
                installed_version="detected",
                fixed_version=None,
                severity="CRITICAL",
                title=f"[Gitleaks] {description}",
                target=target,
                package_type="secret/gitleaks",
                primary_url=None,
            )
        )
    return findings


def _checkov_documents(payload: object) -> Iterable[dict[str, Any]]:
    if isinstance(payload, dict):
        yield payload
    elif isinstance(payload, list):
        for item in payload:
            if isinstance(item, dict):
                yield item


def _checkov_findings(payload: object) -> list[Finding]:
    findings: list[Finding] = []
    for document in _checkov_documents(payload):
        results = _as_dict(document.get("results"))
        framework = str(document.get("check_type") or document.get("framework") or "iac")
        failed_checks = results.get("failed_checks")
        if not isinstance(failed_checks, list):
            continue
        for item in failed_checks:
            if not isinstance(item, dict):
                continue
            check_id = str(item.get("check_id") or "CHECKOV")
            name = str(item.get("check_name") or check_id)
            path = str(item.get("file_path") or item.get("repo_file_path") or "unknown")
            lines = item.get("file_line_range")
            line = lines[0] if isinstance(lines, list) and lines and isinstance(lines[0], int) else None
            target = f"{path}:{line}" if line is not None else path
            resource = str(item.get("resource") or "infrastructure")
            guideline = item.get("guideline")
            findings.append(
                Finding(
                    vulnerability_id=check_id,
                    package_name=resource,
                    installed_version="configured",
                    fixed_version=None,
                    severity=_severity(item.get("severity"), default="MEDIUM"),
                    title=f"[Checkov] {name}",
                    target=target,
                    package_type=f"iac/checkov/{framework}",
                    primary_url=str(guideline) if guideline else None,
                )
            )
    return findings


def _deduplicate(findings: Iterable[Finding]) -> tuple[Finding, ...]:
    unique: dict[tuple[str, str, str | None], Finding] = {}
    for finding in findings:
        key = (finding.vulnerability_id, finding.target, finding.package_type)
        unique.setdefault(key, finding)
    return tuple(unique.values())


class FullRepositoryScanner(Scanner):
    """Run complementary OSS engines over one repository checkout."""

    @property
    def capability(self) -> ScannerCapability:
        return ScannerCapability(
            name="full-repository",
            description="run Trivy, Semgrep, Gitleaks, and Checkov against a repository",
            target_help="repository path or HTTPS Git URL",
        )

    def scan(self, request: ScanRequest) -> ScanResult:
        with RepositoryScanner._resolved_target(request.target, request.timeout_seconds) as target:
            trivy_raw = scan_repository(target, timeout_seconds=request.timeout_seconds)
            semgrep_raw = _run_json(
                [
                    "semgrep",
                    "scan",
                    "--config",
                    "p/security-audit",
                    "--json",
                    "--metrics",
                    "off",
                    "--disable-version-check",
                    "--quiet",
                    str(target),
                ],
                timeout=request.timeout_seconds,
                tool="Semgrep",
            )
            with tempfile.TemporaryDirectory(prefix="secscan-gitleaks-") as temporary:
                report_path = Path(temporary) / "gitleaks.json"
                try:
                    completed = subprocess.run(
                        [
                            "gitleaks",
                            "dir",
                            str(target),
                            "--report-format",
                            "json",
                            "--report-path",
                            str(report_path),
                            "--redact=100",
                            "--exit-code",
                            "0",
                            "--no-banner",
                        ],
                        check=False,
                        capture_output=True,
                        text=True,
                        timeout=request.timeout_seconds,
                    )
                except FileNotFoundError as exc:
                    raise ValueError("Gitleaks is required for a full repository scan") from exc
                except subprocess.TimeoutExpired as exc:
                    raise ValueError("Gitleaks scan timed out") from exc
                if completed.returncode != 0:
                    detail = (completed.stderr or completed.stdout).strip().splitlines()
                    message = detail[-1] if detail else f"exit code {completed.returncode}"
                    raise ValueError(f"Gitleaks scan failed: {message}")
                try:
                    gitleaks_raw = json.loads(report_path.read_text(encoding="utf-8") or "[]")
                except (OSError, json.JSONDecodeError) as exc:
                    raise ValueError("Gitleaks returned invalid JSON") from exc

            checkov_raw = _run_json(
                [
                    "checkov",
                    "-d",
                    str(target),
                    "-o",
                    "json",
                    "--quiet",
                    "--soft-fail",
                ],
                timeout=request.timeout_seconds,
                tool="Checkov",
            )

        findings = _deduplicate(
            [
                *normalize_trivy(trivy_raw),
                *_semgrep_findings(semgrep_raw),
                *_gitleaks_findings(gitleaks_raw),
                *_checkov_findings(checkov_raw),
            ]
        )
        versions = {
            "trivy": RepositoryScanner._engine_version(),
            "semgrep": _tool_version(["semgrep", "--version"]),
            "gitleaks": _tool_version(["gitleaks", "version"]),
            "checkov": _tool_version(["checkov", "--version"]),
        }
        return ScanResult(
            request=request,
            findings=findings,
            raw={
                "schema_version": 1,
                "engines": {
                    "trivy": trivy_raw,
                    "semgrep": semgrep_raw,
                    "gitleaks": gitleaks_raw,
                    "checkov": checkov_raw,
                },
                "versions": versions,
            },
            scanner={
                "name": "secscan-full-repository",
                "version": "; ".join(f"{name}={version}" for name, version in versions.items()),
            },
        )

    def generate_sbom(self, request: ScanRequest, output_path: Path) -> None:
        with RepositoryScanner._resolved_target(request.target, request.timeout_seconds) as target:
            generate_repository_cyclonedx(
                target,
                output_path,
                timeout_seconds=request.timeout_seconds,
            )

    def raw_artifact_name(self, request: ScanRequest) -> str:
        return "secscan.raw.json"
