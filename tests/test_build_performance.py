from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).parents[1]


def test_ci_reuses_container_cache_and_avoids_duplicate_agent_pushes() -> None:
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

    assert '"agent/**"' not in workflow
    assert "docker build --no-cache" not in workflow
    assert "docker/setup-buildx-action@v4" in workflow
    assert "docker/build-push-action@v7" in workflow
    assert "cache-from: type=gha,scope=secscan-ci" in workflow
    assert "cache-to: type=gha,mode=max,scope=secscan-ci" in workflow
    assert "load: true" in workflow


def test_container_security_gate_is_vulnerability_only_and_version_aligned() -> None:
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert "FROM aquasec/trivy:0.74.0 AS trivy" in dockerfile
    assert "aquasec/trivy:0.74.0 image" in workflow
    assert "--scanners vuln" in workflow
    assert "--skip-version-check" in workflow
    assert "--ignore-unfixed" in workflow
    assert "--severity CRITICAL" in workflow


def test_expensive_python_scanner_tools_precede_app_wheel_install() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")

    scanner_stage = "FROM python:3.14.7-slim-bookworm AS python-scanner-tools"
    scanner_copy = "COPY --from=python-scanner-tools /opt/semgrep /opt/semgrep"
    wheel_copy = "COPY --from=builder /wheels /wheels"

    assert scanner_stage in dockerfile
    assert scanner_copy in dockerfile
    assert dockerfile.index(scanner_copy) < dockerfile.index(wheel_copy)
    assert "semgrep==1.172.0" in dockerfile
    assert "checkov==3.3.8" in dockerfile
