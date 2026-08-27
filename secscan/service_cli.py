from __future__ import annotations

import argparse
import os
from pathlib import Path

from fastapi import FastAPI
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
        "--allowed-input-root",
        action="append",
        type=Path,
        default=[],
        help="allow service-controlled local paths beneath this root (repeatable)",
    )
    args = parser.parse_args()

    if args.workers < 1:
        parser.error("--workers must be at least 1")

    from secscan.auth import mount_auth
    from secscan.service import create_app
    from secscan.ssh_host_trust_web import mount_ssh_host_trust
    from secscan.web import mount_web_ui

    database = (args.job_database or args.job_root / "jobs.db").expanduser().resolve()
    api_token = os.environ.get("SECSCAN_API_TOKEN")
    # Browser sessions and compatibility bearer tokens share the outer auth
    # boundary mounted below. Keep create_app's legacy bearer middleware off here
    # so registration/login endpoints remain reachable when a bearer token is set.
    app = create_app(
        job_root=args.job_root,
        job_database=args.job_database,
        max_workers=args.workers,
        allowed_input_roots=args.allowed_input_root,
        api_token=None,
    )
    if isinstance(app, FastAPI):
        mount_web_ui(app, job_root=args.job_root, job_database=args.job_database)
        mount_ssh_host_trust(app, database=database)
        mount_auth(app, database=database, api_token=api_token)
    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
    )


if __name__ == "__main__":
    main()
