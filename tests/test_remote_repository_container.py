from __future__ import annotations

from pathlib import Path


def test_container_installs_git_for_remote_repository_scans() -> None:
    dockerfile = (Path(__file__).parents[1] / "Dockerfile").read_text(encoding="utf-8")

    assert "apt-get install --no-install-recommends -y git ca-certificates" in dockerfile
