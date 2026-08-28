from __future__ import annotations

from dataclasses import replace
import ipaddress
import json
from pathlib import Path
import re
import socket
import subprocess
import xml.etree.ElementTree as ET

from secscan.models import Finding
from secscan.scanners.base import ScanRequest, ScanResult, Scanner, ScannerCapability


_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,252}$")
NUCLEI_TEMPLATES_PATH = "/opt/nuclei-templates"
MAX_NETWORK_RANGE_TARGETS = 16


def validate_network_target(target: str) -> str:
    value = target.strip()
    if not value or len(value) > 253 or not _HOST_RE.fullmatch(value):
        raise ValueError("network target must be a hostname or IP address")
    if "/" in value or " " in value or "://" in value:
        raise ValueError("network target must be one hostname or IP address, not a URL or CIDR")
    try:
        socket.getaddrinfo(value, None)
    except socket.gaierror as exc:
        raise ValueError(f"network target could not be resolved: {value}") from exc
    return value


def expand_network_range(target: str, *, maximum: int = MAX_NETWORK_RANGE_TARGETS) -> tuple[str, ...]:
    value = target.strip()
    if not value or " " in value or "," in value or "://" in value:
        raise ValueError("network range target must be one literal IP address or CIDR")
    try:
        if "/" in value:
            network = ipaddress.ip_network(value, strict=False)
            addresses = tuple(str(address) for address in network.hosts())
            if not addresses and network.num_addresses == 1:
                addresses = (str(network.network_address),)
        else:
            addresses = (str(ipaddress.ip_address(value)),)
    except ValueError as exc:
        raise ValueError("network range target must be one literal IP address or CIDR") from exc
    if not addresses:
        raise ValueError("network range did not contain any scannable host addresses")
    if len(addresses) > maximum:
        raise ValueError(f"network range expands to {len(addresses)} hosts; maximum is {maximum}")
    return addresses


def _run(command: list[str], *, timeout: int, tool: str) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise ValueError(f"{tool} is required for network assessments") from exc
    except subprocess.TimeoutExpired as exc:
        raise ValueError(f"{tool} assessment timed out") from exc
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip().splitlines()
        message = detail[-1] if detail else f"exit code {completed.returncode}"
        raise ValueError(f"{tool} assessment failed: {message}")
    return completed


def _nmap_findings(xml_text: str, target: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ValueError("Nmap returned invalid XML") from exc
    for port in root.findall(".//port"):
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue
        port_id = port.get("portid", "unknown")
        protocol = port.get("protocol", "tcp")
        service = port.find("service")
        name = service.get("name", "unknown") if service is not None else "unknown"
        product = service.get("product", "") if service is not None else ""
        version = service.get("version", "") if service is not None else ""
        detail = " ".join(part for part in (product, version) if part).strip() or name
        findings.append(
            Finding(
                vulnerability_id=f"OPEN-{protocol.upper()}-{port_id}",
                package_name=name,
                installed_version=detail,
                fixed_version=None,
                severity="LOW",
                title=f"[Nmap] Exposed {name} service on {protocol}/{port_id}",
                target=f"{target}:{port_id}",
                package_type="network/nmap",
                primary_url=None,
            )
        )
    return findings


def _nuclei_findings(jsonl: str, target: str) -> list[Finding]:
    findings: list[Finding] = []
    for line in jsonl.splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError("Nuclei returned invalid JSONL") from exc
        if not isinstance(item, dict):
            continue
        raw_info = item.get("info")
        info = raw_info if isinstance(raw_info, dict) else {}
        template_id = str(item.get("template-id") or item.get("templateID") or "NUCLEI")
        name = str(info.get("name") or template_id)
        severity = str(info.get("severity") or "unknown").upper()
        if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}:
            severity = "UNKNOWN"
        matched = str(item.get("matched-at") or item.get("host") or target)
        reference = info.get("reference")
        if isinstance(reference, list):
            reference = reference[0] if reference else None
        findings.append(
            Finding(
                vulnerability_id=template_id,
                package_name="network-service",
                installed_version="detected",
                fixed_version=None,
                severity=severity,
                title=f"[Nuclei] {name}",
                target=matched,
                package_type="network/nuclei",
                primary_url=str(reference) if reference else None,
            )
        )
    return findings


def _deduplicate(findings: list[Finding]) -> tuple[Finding, ...]:
    unique: dict[tuple[str, str, str | None], Finding] = {}
    for finding in findings:
        unique.setdefault((finding.vulnerability_id, finding.target, finding.package_type), finding)
    return tuple(unique.values())


class NetworkScanner(Scanner):
    @property
    def capability(self) -> ScannerCapability:
        return ScannerCapability(
            name="network",
            description="agentless host/network exposure assessment with Nmap and Nuclei",
            target_help="single hostname or IP address",
        )

    def scan(self, request: ScanRequest) -> ScanResult:
        target = validate_network_target(request.target)
        nmap = _run(
            ["nmap", "-Pn", "-sV", "--version-light", "--top-ports", "1000", "-oX", "-", "--", target],
            timeout=request.timeout_seconds,
            tool="Nmap",
        )
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
        findings = _deduplicate(
            [*_nmap_findings(nmap.stdout, target), *_nuclei_findings(nuclei.stdout, target)]
        )
        return ScanResult(
            request=request,
            findings=findings,
            raw={
                "schema_version": 1,
                "target": target,
                "engines": {"nmap_xml": nmap.stdout, "nuclei_jsonl": nuclei.stdout},
            },
            scanner={"name": "secscan-network", "version": "nmap+nuclei"},
        )

    def generate_sbom(self, request: ScanRequest, output_path: Path) -> None:
        output_path.write_text(
            json.dumps(
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.6",
                    "version": 1,
                    "metadata": {"component": {"type": "device", "name": request.target}},
                    "components": [],
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )


class NetworkRangeScanner(Scanner):
    @property
    def capability(self) -> ScannerCapability:
        return ScannerCapability(
            name="network-range",
            description="bounded authorized IP/CIDR exposure assessment with sequential Nmap and Nuclei scans",
            target_help=f"literal IP address or CIDR expanding to at most {MAX_NETWORK_RANGE_TARGETS} hosts",
        )

    def scan(self, request: ScanRequest) -> ScanResult:
        targets = expand_network_range(request.target)
        scanner = NetworkScanner()
        findings: list[Finding] = []
        target_results: list[dict[str, object]] = []
        for target in targets:
            child_request = replace(request, scanner_name="network", target=target)
            result = scanner.scan(child_request)
            findings.extend(result.findings)
            target_results.append({"target": target, "raw": result.raw})
        return ScanResult(
            request=request,
            findings=_deduplicate(findings),
            raw={
                "schema_version": 1,
                "requested_target": request.target,
                "expanded_targets": list(targets),
                "target_count": len(targets),
                "controls": {
                    "maximum_targets": MAX_NETWORK_RANGE_TARGETS,
                    "concurrency": 1,
                    "ordering": "ascending-address",
                },
                "targets": target_results,
            },
            scanner={"name": "secscan-network-range", "version": "bounded-sequential-v1"},
        )

    def generate_sbom(self, request: ScanRequest, output_path: Path) -> None:
        output_path.write_text(
            json.dumps(
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.6",
                    "version": 1,
                    "metadata": {"component": {"type": "device", "name": request.target}},
                    "components": [],
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )