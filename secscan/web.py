from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from secscan.service import create_app

_WEB_ROOT = Path(__file__).with_name("web_assets")


def create_web_app(**service_options: Any) -> FastAPI:
    """Create the secscan API and mount the browser UI at the site root."""
    app = create_app(**service_options)
    app.mount("/", StaticFiles(directory=_WEB_ROOT, html=True), name="web")
    return app


app = create_web_app()
