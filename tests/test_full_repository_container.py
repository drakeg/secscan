from __future__ import annotations

from pathlib import Path


def test_container_bundles_full_repository_engines() -> None:
    dockerfile = (Path(__file__).parents[1] / "Dockerfile").read_text(encoding="utf-8")

    assert "semgrep==1.172.0" in dockerfile
    assert "checkov==3.3.8" in dockerfile
    assert "github.com/gitleaks/gitleaks/v8@v8.30.1" in dockerfile
    assert "semgrep --version" in dockerfile
    assert "gitleaks version" in dockerfile
    assert "checkov --version" in dockerfile
