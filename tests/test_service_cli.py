from __future__ import annotations

from pathlib import Path
import sys

from fastapi import FastAPI
from pytest import MonkeyPatch

import secscan.auth
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


def test_service_cli_routes_api_token_through_outer_auth_middleware(monkeypatch: MonkeyPatch) -> None:
    create_app_kwargs: dict[str, object] = {}
    mount_auth_kwargs: dict[str, object] = {}
    mount_trust_kwargs: dict[str, object] = {}
    app = FastAPI()

    monkeypatch.setattr(
        secscan.service,
        "create_app",
        lambda **kwargs: create_app_kwargs.update(kwargs) or app,
    )
    monkeypatch.setattr(
        secscan.auth,
        "mount_auth",
        lambda _app, **kwargs: mount_auth_kwargs.update(kwargs) or _app,
    )
    monkeypatch.setattr("secscan.web.mount_web_ui", lambda _app, **_kwargs: _app)
    monkeypatch.setattr(
        "secscan.ssh_host_trust_web.mount_ssh_host_trust",
        lambda _app, **kwargs: mount_trust_kwargs.update(kwargs) or _app,
    )
    monkeypatch.setattr(service_cli.uvicorn, "run", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(sys, "argv", ["secscan-service"])
    monkeypatch.setenv("SECSCAN_API_TOKEN", "a" * 32)

    service_cli.main()

    assert create_app_kwargs["api_token"] is None
    assert mount_auth_kwargs["api_token"] == "a" * 32
    assert mount_trust_kwargs["database"] == Path("/reports/jobs/jobs.db")
