from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from secscan.web import create_web_app


def test_web_ui_exposes_authorized_network_assessment(tmp_path: Path) -> None:
    client = TestClient(create_web_app(job_root=tmp_path, runner=lambda _args: 0))

    page = client.get("/")
    dashboard = client.get("/dashboard.js")
    network_styles = client.get("/network.css")

    assert page.status_code == 200
    assert 'value="network"' in page.text
    assert "Server / Network — Agentless assessment" in page.text
    assert 'id="network-authorization"' in page.text
    assert 'id="network-authorized"' in page.text
    assert "explicit authorization to security-test it" in page.text
    assert 'href="/network.css"' in page.text

    assert dashboard.status_code == 200
    assert 'scanner==="network"' in dashboard.text
    assert "server.example.com or 192.0.2.10" in dashboard.text
    assert "network_authorized:true" in dashboard.text
    assert "stopImmediatePropagation" in dashboard.text
    assert "authorized to security-test this network target" in dashboard.text

    assert network_styles.status_code == 200
    assert "#network-authorization" in network_styles.text
    assert "#network-authorized" in network_styles.text
