from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, Response
from pydantic import BaseModel, Field

from secscan.ssh_host_trust import SshHostTrustStore


class HostKeyDiscoveryRequest(BaseModel):
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(default=22, ge=1, le=65535)


class HostKeyApprovalRequest(BaseModel):
    discovery_id: str = Field(min_length=1, max_length=128)


def _require_admin(request: Request) -> str:
    user = getattr(request.state, "secscan_user", None)
    if user is None:
        raise HTTPException(status_code=403, detail="administrator browser session required")
    if getattr(user, "role", None) != "admin":
        raise HTTPException(status_code=403, detail="administrator access required")
    return str(getattr(user, "id"))


def mount_ssh_host_trust(app: FastAPI, *, database: Path) -> FastAPI:
    store = SshHostTrustStore(database)

    @app.get("/api/v1/admin/ssh-host-trust")
    def list_host_trust(request: Request) -> list[dict[str, object]]:
        _require_admin(request)
        return [record.as_public_dict() for record in store.list()]

    @app.post("/api/v1/admin/ssh-host-trust/discover")
    def discover_host_trust(
        payload: HostKeyDiscoveryRequest, request: Request
    ) -> dict[str, object]:
        _require_admin(request)
        try:
            discovered = store.discover(payload.host, payload.port)
            approved = store.get(payload.host, payload.port)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return {
            "host": payload.host,
            "port": payload.port,
            "approved": approved.as_public_dict() if approved else None,
            "discovered": [record.as_public_dict() for record in discovered],
        }

    @app.post("/api/v1/admin/ssh-host-trust/approve")
    def approve_host_trust(
        payload: HostKeyApprovalRequest, request: Request
    ) -> dict[str, object]:
        user_id = _require_admin(request)
        try:
            trusted = store.approve(payload.discovery_id, user_id)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return trusted.as_public_dict()

    @app.delete("/api/v1/admin/ssh-host-trust/{host}/{port}", status_code=204)
    def delete_host_trust(host: str, port: int, request: Request) -> Response:
        _require_admin(request)
        try:
            deleted = store.delete(host, port)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        if not deleted:
            raise HTTPException(status_code=404, detail="trusted SSH host key was not found")
        return Response(status_code=204)

    return app
