from __future__ import annotations

import json
from pathlib import Path
from time import sleep

from fastapi.testclient import TestClient

from secscan.web import create_web_app


def test_job_summary_returns_only_severity_counts(tmp_path: Path) -> None:
    def runner(args: list[str]) -> int:
        output_dir = Path(args[args.index("--output-dir") + 1])
        output_dir.mkdir(parents=True)
        (output_dir / "secscan.json").write_text(
            json.dumps(
                {
                    "findings": [
                        {"severity": "CRITICAL"},
                        {"severity": "HIGH"},
                        {"severity": "HIGH"},
                        {"severity": "MEDIUM"},
                        {"severity": "unexpected"},
                    ]
                }
            ),
            encoding="utf-8",
        )
        return 0

    client = TestClient(create_web_app(job_root=tmp_path, runner=runner))
    submitted = client.post(
        "/api/v1/jobs",
        json={"scanner": "image", "target": "example:latest"},
    )
    job_id = submitted.json()["id"]
    for _ in range(100):
        job = client.get(f"/api/v1/jobs/{job_id}").json()
        if job["status"] == "completed":
            break
        sleep(0.01)

    summary = client.get(f"/api/v1/jobs/{job_id}/summary")

    assert summary.status_code == 200
    assert summary.json() == {
        "job_id": job_id,
        "status": "completed",
        "total": 5,
        "severity": {
            "CRITICAL": 1,
            "HIGH": 2,
            "MEDIUM": 1,
            "LOW": 0,
            "UNKNOWN": 1,
        },
    }


def test_job_summary_is_protected_by_api_token(tmp_path: Path) -> None:
    token = "a" * 32
    client = TestClient(
        create_web_app(job_root=tmp_path, runner=lambda _args: 0, api_token=token)
    )

    assert client.get("/api/v1/jobs/missing/summary").status_code == 401
