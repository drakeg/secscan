from __future__ import annotations

from pathlib import Path
import sys

from fastapi import FastAPI
from fastapi.testclient import TestClient
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
    mount_order: list[str] = []
    app = FastAPI()

    monkeypatch.setattr(
        secscan.service,
        "create_app",
        lambda **kwargs: create_app_kwargs.update(kwargs) or app,
    )
    monkeypatch.setattr(
        secscan.auth,
        "mount_auth",
        lambda _app, **kwargs: mount_order.append("auth") or mount_auth_kwargs.update(kwargs) or _app,
    )
    monkeypatch.setattr(
        "secscan.ssh_host_trust_web.mount_ssh_host_trust",
        lambda _app, **kwargs: mount_order.append("trust") or mount_trust_kwargs.update(kwargs) or _app,
    )
    monkeypatch.setattr(
        "secscan.web.mount_web_ui",
        lambda _app, **_kwargs: mount_order.append("web") or _app,
    )
    monkeypatch.setattr(service_cli.uvicorn, "run", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(sys, "argv", ["secscan-service"])
    monkeypatch.setenv("SECSCAN_API_TOKEN", "a" * 32)

    service_cli.main()

    assert create_app_kwargs["api_token"] is None
    assert mount_auth_kwargs["api_token"] == "a" * 32
    assert mount_trust_kwargs["database"] == Path("/reports/jobs/jobs.db")
    assert mount_order == ["auth", "trust", "web"]


def test_service_cli_login_route_precedes_static_catch_all(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    captured: dict[str, object] = {}

    def capture_run(app: object, **_kwargs: object) -> None:
        captured["app"] = app

    monkeypatch.setattr(service_cli.uvicorn, "run", capture_run)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "secscan-service",
            "--job-root",
            str(tmp_path / "jobs"),
            "--allowed-input-root",
            str(tmp_path),
        ],
    )
    monkeypatch.delenv("SECSCAN_API_TOKEN", raising=False)

    service_cli.main()

    app = captured["app"]
    assert isinstance(app, FastAPI)
    client = TestClient(app)
    login = client.get("/login")
    assert login.status_code == 200
    assert "Sign in" in login.text

    root = client.get("/", follow_redirects=False)
    assert root.status_code == 303
    assert root.headers["location"] == "/login"
