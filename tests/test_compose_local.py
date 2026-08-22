from __future__ import annotations

from pathlib import Path

import yaml


def test_compose_supports_configurable_parallel_local_instances_and_cli_profile() -> None:
    compose_path = Path("compose.yaml")
    compose = yaml.safe_load(compose_path.read_text(encoding="utf-8"))

    service = compose["services"]["service"]
    cli = compose["services"]["cli"]

    assert compose["name"] == "${SECSCAN_COMPOSE_PROJECT:-secscan}"
    assert service["image"] == "${SECSCAN_IMAGE:-secscan:local}"
    assert cli["image"] == service["image"]
    assert "${SECSCAN_WORKSPACE:-.}:/workspace:ro" in service["volumes"]
    assert service["ports"] == [
        "${SECSCAN_BIND_ADDRESS:-127.0.0.1}:${SECSCAN_PORT:-8000}:8000"
    ]
    assert cli["profiles"] == ["tools"]
    assert cli["entrypoint"] == ["secscan"]
    assert "${SECSCAN_WORKSPACE:-.}:/workspace:ro" in cli["volumes"]
    assert service["read_only"] is True
    assert cli["read_only"] is True
