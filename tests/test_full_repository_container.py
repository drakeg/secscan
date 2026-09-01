from __future__ import annotations

from pathlib import Path


def test_container_bundles_full_repository_engines() -> None:
    dockerfile = (Path(__file__).parents[1] / "Dockerfile").read_text(encoding="utf-8")

    assert "semgrep==1.172.0" in dockerfile
    assert "checkov==3.3.8" in dockerfile
    assert "--branch v8.30.1 https://github.com/gitleaks/gitleaks.git" in dockerfile
    assert "ARG X_CRYPTO_VERSION=v0.55.0" in dockerfile
    assert "go mod edit -require=golang.org/x/crypto@${X_CRYPTO_VERSION}" in dockerfile
    assert 'go version -m /out/gitleaks | grep -E "golang.org/x/crypto[[:space:]]+${X_CRYPTO_VERSION}"' in dockerfile
    assert "semgrep --version" in dockerfile
    assert "gitleaks version" in dockerfile
    assert "checkov --version" in dockerfile
