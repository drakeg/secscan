from __future__ import annotations

from pathlib import Path

import yaml


def test_local_compose_service_keeps_secure_persistent_defaults() -> None:
    compose = yaml.safe_load(
        (Path(__file__).parents[1] / "compose.yaml").read_text(encoding="utf-8")
    )
    service = compose["services"]["service"]

    assert service["entrypoint"] == ["secscan-service"]
    assert service["ports"] == ["127.0.0.1:${SECSCAN_PORT:-8000}:8000"]
    assert service["read_only"] is True
    assert service["cap_drop"] == ["ALL"]
    assert service["security_opt"] == ["no-new-privileges:true"]
    assert service["tmpfs"] == ["/tmp:size=512m,mode=1777"]
    assert "secscan-reports:/reports" in service["volumes"]
    assert "secscan-cache:/cache" in service["volumes"]
    assert ".:/workspace:ro" in service["volumes"]
    assert service["healthcheck"]["test"][:3] == ["CMD", "python", "-c"]
    assert set(compose["volumes"]) == {"secscan-reports", "secscan-cache"}
