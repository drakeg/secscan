from __future__ import annotations

import argparse
import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
import uvicorn


def main() -> None:
    parser = argparse.ArgumentParser(prog="secscan-service", description="Run the secscan web UI and REST API")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--job-root", type=Path, default=Path("/reports/jobs"))
    parser.add_argument(
        "--job-database",
        type=Path,
        help="SQLite job database (default: <job-root>/jobs.db)",
    )
    parser.add_argument("--workers", type=int, default=2, help="maximum concurrent scan jobs")
    parser.add_argument(
        "--reassessment-scheduler",
        action="store_true",
        default=os.environ.get("SECSCAN_REASSESSMENT_SCHEDULER", "").lower() == "true",
        help="enable the local recurring reassessment scheduler",
    )
    parser.add_argument(
        "--allowed-input-root",
        action="append",
        type=Path,
        default=[],
        help="allow service-controlled local paths beneath this root (repeatable)",
    )
    args = parser.parse_args()

    if args.workers < 1:
        parser.error("--workers must be at least 1")

    from secscan.assets_web import mount_assets
    from secscan.auth import mount_auth
    from secscan.credential_tenancy import SshCredentialTenantMiddleware
    from secscan.network_range_web import mount_network_range_submission
    from secscan.project_access import mount_project_access
    from secscan.project_jobs import mount_project_job_association
    from secscan.projects import mount_projects
    from secscan.public_navigation import PublicSessionNavigationMiddleware
    from secscan.public_site import mount_public_site
    from secscan.reassessment import (
        ReassessmentExecutor,
        ReassessmentScheduler,
        mount_reassessment_schedules,
    )
    from secscan.service import create_app
    from secscan.ssh_host_trust_web import mount_ssh_host_trust
    from secscan.tenant_api_keys import mount_tenant_api_keys
    from secscan.tenant_invitations import mount_tenant_invitations
    from secscan.web import mount_web_ui
    from secscan.windows_host_web import mount_windows_host_submission

    database = (args.job_database or args.job_root / "jobs.db").expanduser().resolve()
    api_token = os.environ.get("SECSCAN_API_TOKEN")
    app = create_app(
        job_root=args.job_root,
        job_database=args.job_database,
        max_workers=args.workers,
        allowed_input_roots=args.allowed_input_root,
        api_token=None,
    )
    if isinstance(app, FastAPI):
        # Register every explicit page/API before the StaticFiles "/" catch-all.
        # The public-site routes intentionally precede mount_auth's compatibility
        # login/register handlers so plan-aware onboarding wins route matching.
        mount_public_site(app, database=database)
        mount_auth(app, database=database, api_token=api_token)
        mount_tenant_api_keys(app, database=database, api_token=api_token)
        mount_tenant_invitations(app, database=database)
        mount_projects(app, database=database)
        mount_project_access(app, database=database)
        mount_project_job_association(app, database=database)
        mount_ssh_host_trust(app, database=database)
        mount_assets(app, database=database)
        mount_reassessment_schedules(app, database=database)
        if args.reassessment_scheduler:
            get_manager = getattr(app.state, "secscan_get_manager", None)
            if not callable(get_manager):
                raise RuntimeError("secscan job manager factory is unavailable")
            scheduler = ReassessmentScheduler(
                ReassessmentExecutor(database, get_manager()),
            )
            scheduler.start()
            app.state.reassessment_scheduler = scheduler

            @app.on_event("shutdown")
            def stop_reassessment_scheduler() -> None:
                scheduler.stop()
        mount_network_range_submission(app)
        mount_windows_host_submission(
            app,
            database=database,
            job_root=args.job_root,
            job_database=args.job_database,
        )

        @app.get("/app", include_in_schema=False)
        def workspace() -> FileResponse:
            return FileResponse(Path(__file__).with_name("web_assets") / "index.html")

        mount_web_ui(app, job_root=args.job_root, job_database=args.job_database)
        app.add_middleware(PublicSessionNavigationMiddleware, database=database)
        app.add_middleware(SshCredentialTenantMiddleware, database=database)
    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
