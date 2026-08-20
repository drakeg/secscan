from __future__ import annotations

import subprocess

import pytest

from secscan.scanners.base import ScanRequest
from secscan.scanners.network import NetworkScanner, _nmap_findings, _nuclei_findings, validate_network_target


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


def test_network_scanner_invokes_nmap_and_nuclei(monkeypatch: pytest.MonkeyPatch) -> None:
    commands: list[list[str]] = []

    def fake_getaddrinfo(host: str, port: object) -> list[tuple[object, ...]]:
        return [(object(),)]

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        if command[0] == "nmap":
            stdout = "<?xml version='1.0'?><nmaprun><host><ports/></host></nmaprun>"
        else:
            stdout = ""
        return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

    monkeypatch.setattr("secscan.scanners.network.socket.getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr("secscan.scanners.network.subprocess.run", fake_run)

    result = NetworkScanner().scan(ScanRequest(scanner_name="network", target="host.example.com"))

    assert result.findings == ()
    assert commands[0][0] == "nmap"
    assert commands[1][0] == "nuclei"
    assert "--" in commands[0]
    assert commands[0][-1] == "host.example.com"
