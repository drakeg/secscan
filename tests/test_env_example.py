from __future__ import annotations

from pathlib import Path


def test_env_example_covers_local_compose_settings() -> None:
    root = Path(__file__).parents[1]
    env_example = (root / ".env.example").read_text(encoding="utf-8")
    gitignore = (root / ".gitignore").read_text(encoding="utf-8").splitlines()

    for name in (
        "SECSCAN_COMPOSE_PROJECT",
        "SECSCAN_IMAGE",
        "SECSCAN_BIND_ADDRESS",
        "SECSCAN_PORT",
        "SECSCAN_WORKSPACE",
        "SECSCAN_WORKERS",
        "SECSCAN_API_TOKEN",
        "SECSCAN_GITHUB_TOKEN",
    ):
        assert f"{name}=" in env_example

    assert ".env" in gitignore
    assert ".env.example" not in gitignore
