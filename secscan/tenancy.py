from __future__ import annotations

from fastapi import Request

SYSTEM_TENANT_ID = "__system__"


def request_tenant_id(request: Request) -> str | None:
    """Return the authenticated session tenant or None for the trusted system actor."""
    user = getattr(request.state, "secscan_user", None)
    if user is None:
        return None
    tenant_id = getattr(user, "tenant_id", None)
    if not isinstance(tenant_id, str) or not tenant_id:
        raise RuntimeError("authenticated user is missing tenant identity")
    return tenant_id
