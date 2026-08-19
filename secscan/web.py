from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from secscan.service import create_app

_WEB_ROOT = Path(__file__).with_name("web_assets")


def mount_web_ui(app: FastAPI) -> FastAPI:
    """Mount the browser UI onto an existing secscan FastAPI application."""
    app.mount("/", StaticFiles(directory=_WEB_ROOT, html=True), name="web")
    return app


def create_web_app(**service_options: Any) -> FastAPI:
    """Create the secscan API and mount the browser UI at the site root."""
    return mount_web_ui(create_app(**service_options))
