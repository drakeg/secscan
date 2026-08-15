from __future__ import annotations

from pathlib import Path
import sys

from pytest import MonkeyPatch

import secscan.service
from secscan import service_cli


def test_service_cli_propagates_repeated_allowed_input_roots(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    captured: dict[str, object] = {}
    monkeypatch.setattr(
        secscan.service,
        "create_app",
        lambda **kwargs: captured.update(kwargs) or object(),
    )
    monkeypatch.setattr(service_cli.uvicorn, "run", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "secscan-service",
            "--allowed-input-root",
            str(first),
            "--allowed-input-root",
            str(second),
        ],
    )

    service_cli.main()

    assert captured["allowed_input_roots"] == [first, second]
