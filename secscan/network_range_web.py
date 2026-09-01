from __future__ import annotations

from collections.abc import Callable
from typing import Literal, cast

from fastapi import FastAPI, HTTPException, Request
from fastapi.routing import APIRoute
from pydantic import BaseModel, Field

from secscan.scanners.network import expand_network_range
from secscan.service import ScanSubmission


class NetworkRangeSubmission(BaseModel):
    target: str = Field(min_length=1)
    fail_on: Literal["NONE", "UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"] | None = None
    policy: str | None = None
    baseline: str | None = None
    timeout: int = Field(default=600, ge=1, le=86400)
    network_authorized: bool = False


def _job_submitter(app: FastAPI) -> Callable[[Request, ScanSubmission], dict[str, object]]:
    for route in app.routes:
        if (
            isinstance(route, APIRoute)
            and route.path == "/api/v1/jobs"
            and route.methods is not None
            and "POST" in route.methods
        ):
            return cast(Callable[[Request, ScanSubmission], dict[str, object]], route.endpoint)
    raise RuntimeError("secscan job submission route is unavailable")


def mount_network_range_submission(app: FastAPI) -> FastAPI:
    """Expose the bounded CLI network-range scanner through an explicit authorized API."""
    submit_job = _job_submitter(app)

    @app.post("/api/v1/network-range-jobs", status_code=202, tags=["network"])
    def submit_network_range(request: Request, submission: NetworkRangeSubmission) -> dict[str, object]:
        if not submission.network_authorized:
            raise HTTPException(
                status_code=422,
                detail="network range scans require explicit authorization acknowledgement",
            )
        try:
            expand_network_range(submission.target)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

        # The dedicated endpoint owns validation for this scanner identity. The
        # generic persisted job machinery then supplies normal tenant ownership,
        # execution, history, status, and artifact behavior.
        job_request = ScanSubmission.model_construct(
            scanner="network-range",
            target=submission.target,
            fail_on=submission.fail_on,
            policy=submission.policy,
            baseline=submission.baseline,
            timeout=submission.timeout,
            network_authorized=True,
            web_authorized=False,
        )
        return submit_job(request, job_request)

    return app
