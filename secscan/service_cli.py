from __future__ import annotations

import argparse
from pathlib import Path

import uvicorn


def main() -> None:
    parser = argparse.ArgumentParser(prog="secscan-service", description="Run the secscan REST API")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--job-root", type=Path, default=Path("/reports/jobs"))
    parser.add_argument("--workers", type=int, default=2, help="maximum concurrent scan jobs")
    args = parser.parse_args()

    if args.workers < 1:
        parser.error("--workers must be at least 1")

    from secscan.service import create_app

    uvicorn.run(create_app(job_root=args.job_root, max_workers=args.workers), host=args.host, port=args.port)


if __name__ == "__main__":
    main()
