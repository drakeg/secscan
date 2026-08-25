from __future__ import annotations

from pathlib import Path

import yaml


def test_local_compose_service_keeps_secure_persistent_defaults() -> None:
    compose = yaml.safe_load(
        (Path(__file__).parents[1] / "compose.yaml").read_text(encoding="utf-8")
    )
    service = compose["services"]["service"]
    cli = compose["services"]["cli"]
    network_fixture = compose["services"]["network-fixture"]
    linux_host_fixture = compose["services"]["linux-host-fixture"]

    assert compose["name"] == "${SECSCAN_COMPOSE_PROJECT:-secscan}"
    assert service["image"] == "${SECSCAN_IMAGE:-secscan:local}"
    assert cli["image"] == service["image"]
    assert service["entrypoint"] == ["secscan-service"]
    assert service["command"][-2:] == ["--allowed-input-root", "/workspace"]
    assert service["ports"] == [
        "${SECSCAN_BIND_ADDRESS:-127.0.0.1}:${SECSCAN_PORT:-8000}:8000"
    ]
    assert service["environment"] == {
        "SECSCAN_API_TOKEN": "${SECSCAN_API_TOKEN:-}",
        "SECSCAN_GITHUB_TOKEN": "${SECSCAN_GITHUB_TOKEN:-}",
    }
    assert cli["environment"] == {
        "SECSCAN_GITHUB_TOKEN": "${SECSCAN_GITHUB_TOKEN:-}",
        "SECSCAN_SSH_USER": "${SECSCAN_SSH_USER:-}",
        "SECSCAN_SSH_KEY": "${SECSCAN_SSH_KEY:-}",
        "SECSCAN_SSH_KNOWN_HOSTS": "${SECSCAN_SSH_KNOWN_HOSTS:-}",
        "SECSCAN_SSH_PORT": "${SECSCAN_SSH_PORT:-22}",
    }
    assert service["read_only"] is True
    assert service["cap_drop"] == ["ALL"]
    assert service["security_opt"] == ["no-new-privileges:true"]
    assert service["tmpfs"] == ["/tmp:size=512m,mode=1777"]
    assert "secscan-reports:/reports" in service["volumes"]
    assert "secscan-cache:/cache" in service["volumes"]
    assert "${SECSCAN_WORKSPACE:-.}:/workspace:ro" in service["volumes"]
    assert service["healthcheck"]["test"][:3] == ["CMD", "python", "-c"]

    assert "secscan-ssh-fixture:/run/secscan-ssh-fixture:ro" in cli["volumes"]

    assert network_fixture["profiles"] == ["network-test"]
    assert network_fixture["image"] == "secscan:local"
    assert network_fixture["entrypoint"] == ["python", "-m", "http.server"]
    assert network_fixture["command"] == ["8080", "--bind", "0.0.0.0", "--directory", "/tmp"]
    assert network_fixture["read_only"] is True
    assert network_fixture["cap_drop"] == ["ALL"]
    assert network_fixture["security_opt"] == ["no-new-privileges:true"]
    assert "ports" not in network_fixture

    assert linux_host_fixture["profiles"] == ["linux-host-test"]
    assert linux_host_fixture["image"] == "secscan-linux-host-fixture:local"
    assert linux_host_fixture["build"]["context"] == "tests/fixtures/linux-host"
    assert linux_host_fixture["volumes"] == ["secscan-ssh-fixture:/fixture"]
    assert "ports" not in linux_host_fixture
    assert linux_host_fixture["security_opt"] == ["no-new-privileges:true"]
    assert linux_host_fixture["cap_drop"] == ["ALL"]
    assert set(linux_host_fixture["cap_add"]) == {"SETGID", "SETUID", "CHOWN", "DAC_OVERRIDE"}

    assert set(compose["volumes"]) == {
        "secscan-reports",
        "secscan-cache",
        "secscan-ssh-fixture",
    }


def test_linux_host_fixture_generates_credentials_at_runtime() -> None:
    root = Path(__file__).parents[1]
    dockerfile = (root / "tests/fixtures/linux-host/Dockerfile").read_text(encoding="utf-8")
    entrypoint = (root / "tests/fixtures/linux-host/entrypoint.sh").read_text(encoding="utf-8")

    assert "openssh-server" in dockerfile
    assert "PRIVATE KEY" not in dockerfile
    assert "PRIVATE KEY" not in entrypoint
    assert "ssh-keygen -q -t ed25519" in entrypoint
    assert "PasswordAuthentication no" in entrypoint
    assert "PermitRootLogin no" in entrypoint
    assert "AllowAgentForwarding no" in entrypoint
    assert "linux-host-fixture" in entrypoint
