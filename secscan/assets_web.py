from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, Request

from secscan.assets import AssetStore
from secscan.tenancy import request_tenant_id


def mount_assets(app: FastAPI, *, database: Path) -> FastAPI:
    """Mount read-only persistent tenant-aware asset inventory routes."""
    store = AssetStore(database)

    @app.get("/api/v1/assets")
    def list_assets(
        request: Request,
        limit: int = Query(default=100, ge=1, le=500),
    ) -> list[dict[str, object]]:
        return [
            asset.to_dict()
            for asset in store.list(limit=limit, tenant_id=request_tenant_id(request))
        ]

    @app.get("/api/v1/assets/{asset_id}")
    def get_asset(asset_id: str, request: Request) -> dict[str, object]:
        asset = store.get(asset_id, tenant_id=request_tenant_id(request))
        if asset is None:
            raise HTTPException(status_code=404, detail="asset not found")
        return asset.to_dict()

    return app
