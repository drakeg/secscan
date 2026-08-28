from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from secscan.scanners.base import ScanRequest, ScanResult, Scanner, ScannerCapability
from secscan.scanners.network import NUCLEI_TEMPLATES_PATH, _deduplicate, _nuclei_findings, _run

MAX_WEB_TARGET_LENGTH = 2048


def validate_web_target(target: str) -> str:
    value = target.strip()
    if not value or len(value) > MAX_WEB_TARGET_LENGTH:
        raise ValueError("web target must be one HTTP or HTTPS URL")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("web target must be one valid HTTP or HTTPS URL") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("web target must be one HTTP or HTTPS URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("web target must not contain embedded credentials")
    if parsed.fragment:
        raise ValueError("web target must not contain a URL fragment")
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("web target port must be between 1 and 65535")
    host = parsed.hostname
    if host is None:
        raise ValueError("web target must include a hostname")
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    netloc = host if port is None else f"{host}:{port}"
    path = parsed.path or "/"
    return urlunsplit((parsed.scheme, netloc, path, parsed.query, ""))


class WebDastScanner(Scanner):
    @property
    def capability(self) -> ScannerCapability:
        return ScannerCapability(
            name="web-dast",
            description="bounded HTTP/HTTPS application assessment with Nuclei",
            target_help="one explicit http:// or https:// URL",
        )

    def scan(self, request: ScanRequest) -> ScanResult:
        target = validate_web_target(request.target)
        nuclei = _run(
            [
                "nuclei",
                "-u",
                target,
                "-templates",
                NUCLEI_TEMPLATES_PATH,
                "-jsonl",
                "-silent",
                "-disable-update-check",
                "-no-interactsh",
                "-timeout",
                "10",
            ],
            timeout=request.timeout_seconds,
            tool="Nuclei",
        )
        findings = _deduplicate(_nuclei_findings(nuclei.stdout, target))
        return ScanResult(
            request=request,
            findings=findings,
            raw={
                "schema_version": 1,
                "target": target,
                "controls": {
                    "target_count": 1,
                    "explicit_url_only": True,
                    "crawler_enabled": False,
                    "interactsh_enabled": False,
                    "template_updates_enabled": False,
                    "arbitrary_scanner_flags": False,
                },
                "engines": {"nuclei_jsonl": nuclei.stdout},
            },
            scanner={"name": "secscan-web-dast", "version": "nuclei"},
        )

    def generate_sbom(self, request: ScanRequest, output_path: Path) -> None:
        output_path.write_text(
            json.dumps(
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.6",
                    "version": 1,
                    "metadata": {
                        "component": {
                            "type": "application",
                            "name": validate_web_target(request.target),
                        }
                    },
                    "components": [],
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
