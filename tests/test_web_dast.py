from __future__ import annotations

import subprocess

import pytest

from secscan.scanners.base import ScanRequest
from secscan.scanners.network import NUCLEI_TEMPLATES_PATH
from secscan.scanners.web_dast import WebDastScanner, validate_web_target


def test_web_target_normalizes_and_preserves_query() -> None:
    assert validate_web_target(" https://example.com/app?q=1 ") == "https://example.com/app?q=1"
    assert validate_web_target("http://127.0.0.1:8080") == "http://127.0.0.1:8080/"


@pytest.mark.parametrize(
    "target",
    [
        "example.com",
        "ftp://example.com",
        "https://user:secret@example.com/",
        "https://example.com/#fragment",
        "https://example.com:70000/",
    ],
)
def test_web_target_rejects_unsafe_or_unbounded_forms(target: str) -> None:
    with pytest.raises(ValueError):
        validate_web_target(target)


def test_web_dast_invokes_hardened_nuclei(monkeypatch: pytest.MonkeyPatch) -> None:
    commands: list[list[str]] = []

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        payload = '{"template-id":"test-header","matched-at":"https://example.com/","info":{"name":"Example","severity":"medium"}}\n'
        return subprocess.CompletedProcess(command, 0, stdout=payload, stderr="")

    monkeypatch.setattr("secscan.scanners.network.subprocess.run", fake_run)

    result = WebDastScanner().scan(
        ScanRequest(scanner_name="web-dast", target="https://example.com/")
    )

    assert len(result.findings) == 1
    assert result.findings[0].severity == "MEDIUM"
    assert result.raw["controls"]["target_count"] == 1
    assert result.raw["controls"]["crawler_enabled"] is False
    assert result.raw["controls"]["interactsh_enabled"] is False
    command = commands[0]
    assert command[0] == "nuclei"
    assert command[command.index("-u") + 1] == "https://example.com/"
    assert command[command.index("-templates") + 1] == NUCLEI_TEMPLATES_PATH
    assert "-disable-update-check" in command
    assert "-no-interactsh" in command
