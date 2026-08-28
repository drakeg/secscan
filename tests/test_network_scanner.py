from __future__ import annotations

import subprocess

import pytest

from secscan.scanners.base import ScanRequest, ScanResult
from secscan.scanners.network import (
    MAX_NETWORK_RANGE_TARGETS,
    NUCLEI_TEMPLATES_PATH,
    NetworkRangeScanner,
    NetworkScanner,
    _nmap_findings,
    _nuclei_findings,
    expand_network_range,
    validate_network_target,
)


def test_nmap_open_service_is_normalized() -> None:
    xml = """<?xml version='1.0'?><nmaprun><host><ports><port protocol='tcp' portid='22'><state state='open'/><service name='ssh' product='OpenSSH' version='9.2'/></port></ports></host></nmaprun>"""
    findings = _nmap_findings(xml, "server.example.com")
    assert len(findings) == 1
    assert findings[0].vulnerability_id == "OPEN-TCP-22"
    assert findings[0].package_type == "network/nmap"
    assert findings[0].target == "server.example.com:22"
    assert findings[0].severity == "LOW"


def test_nuclei_finding_is_normalized() -> None:
    payload = '{"template-id":"CVE-2026-1234","host":"https://server.example.com","matched-at":"https://server.example.com/admin","info":{"name":"Example issue","severity":"high","reference":["https://example.invalid/advisory"]}}'
    findings = _nuclei_findings(payload, "server.example.com")
    assert len(findings) == 1
    assert findings[0].vulnerability_id == "CVE-2026-1234"
    assert findings[0].severity == "HIGH"
    assert findings[0].package_type == "network/nuclei"
    assert findings[0].primary_url == "https://example.invalid/advisory"


def test_network_target_rejects_urls_and_cidr() -> None:
    with pytest.raises(ValueError, match="hostname or IP"):
        validate_network_target("https://example.com")
    with pytest.raises(ValueError, match="hostname or IP"):
        validate_network_target("10.0.0.0/24")


def test_network_range_expands_deterministically_and_accepts_single_ip() -> None:
    assert expand_network_range("10.0.0.0/30") == ("10.0.0.1", "10.0.0.2")
    assert expand_network_range("2001:db8::1") == ("2001:db8::1",)


def test_network_range_rejects_hostnames_urls_lists_and_large_ranges() -> None:
    for target in ("example.com", "https://10.0.0.1", "10.0.0.1,10.0.0.2"):
        with pytest.raises(ValueError, match="literal IP address or CIDR"):
            expand_network_range(target)
    with pytest.raises(ValueError, match=f"maximum is {MAX_NETWORK_RANGE_TARGETS}"):
        expand_network_range("10.0.0.0/27")


def test_network_scanner_invokes_nmap_and_nuclei(monkeypatch: pytest.MonkeyPatch) -> None:
    commands: list[list[str]] = []

    def fake_getaddrinfo(host: str, port: object) -> list[tuple[object, ...]]:
        return [(object(),)]

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        stdout = "<?xml version='1.0'?><nmaprun><host><ports/></host></nmaprun>" if command[0] == "nmap" else ""
        return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

    monkeypatch.setattr("secscan.scanners.network.socket.getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr("secscan.scanners.network.subprocess.run", fake_run)
    result = NetworkScanner().scan(ScanRequest(scanner_name="network", target="host.example.com"))
    assert result.findings == ()
    assert commands[0][0] == "nmap"
    assert commands[1][0] == "nuclei"
    assert commands[1][commands[1].index("-templates") + 1] == NUCLEI_TEMPLATES_PATH
    assert "-disable-update-check" in commands[1]
    assert "--" in commands[0]
    assert commands[0][-1] == "host.example.com"


def test_network_range_scans_each_expanded_target_sequentially(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[str] = []

    def fake_scan(_scanner: NetworkScanner, request: ScanRequest) -> ScanResult:
        seen.append(request.target)
        return ScanResult(
            request=request,
            findings=(),
            raw={"target": request.target, "engines": {}},
            scanner={"name": "secscan-network", "version": "fixture"},
        )

    monkeypatch.setattr(NetworkScanner, "scan", fake_scan)
    result = NetworkRangeScanner().scan(
        ScanRequest(scanner_name="network-range", target="10.0.0.0/30")
    )
    assert seen == ["10.0.0.1", "10.0.0.2"]
    assert result.raw["expanded_targets"] == seen
    assert result.raw["target_count"] == 2
    assert result.raw["controls"] == {
        "maximum_targets": MAX_NETWORK_RANGE_TARGETS,
        "concurrency": 1,
        "ordering": "ascending-address",
    }
