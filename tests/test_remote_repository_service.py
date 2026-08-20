from __future__ import annotations

from pathlib import Path
from time import sleep

from fastapi.testclient import TestClient

from secscan.service import create_app


def test_service_accepts_remote_repository_with_local_input_boundary(tmp_path: Path) -> None:
    captured: list[list[str]] = []

    def runner(args: list[str]) -> int:
        captured.append(args)
        output_dir = Path(args[args.index("--output-dir") + 1])
        output_dir.mkdir(parents=True)
        return 0

    client = TestClient(
        create_app(
            job_root=tmp_path / "jobs",
            runner=runner,
            allowed_input_roots=[tmp_path / "workspace"],
        )
    )
    response = client.post(
        "/api/v1/jobs",
        json={
            "scanner": "repository",
            "target": "https://github.com/example/project.git",
        },
    )

    assert response.status_code == 202
    job_id = response.json()["id"]
    for _ in range(100):
        job = client.get(f"/api/v1/jobs/{job_id}").json()
        if job["status"] == "completed":
            break
        sleep(0.01)

    assert captured
    assert captured[0][0:3] == ["scan", "repository", "https://github.com/example/project.git"]


def test_service_rejects_remote_repository_credentials(tmp_path: Path) -> None:
    client = TestClient(
        create_app(
            job_root=tmp_path / "jobs",
            runner=lambda _args: 0,
            allowed_input_roots=[tmp_path / "workspace"],
        )
    )

    response = client.post(
        "/api/v1/jobs",
        json={
            "scanner": "repository",
            "target": "https://user:secret@github.com/example/project.git",
        },
    )

    assert response.status_code == 422
    assert response.json() == {
        "detail": "remote repository URLs must not contain embedded credentials"
    }


def test_service_still_rejects_local_repository_outside_allowed_roots(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    client = TestClient(
        create_app(
            job_root=tmp_path / "jobs",
            runner=lambda _args: 0,
            allowed_input_roots=[workspace],
        )
    )

    response = client.post(
        "/api/v1/jobs",
        json={"scanner": "repository", "target": str(outside)},
    )

    assert response.status_code == 422
    assert response.json() == {"detail": "target is outside the configured input roots"}
