from __future__ import annotations

from pathlib import Path
import sqlite3
from time import sleep

from fastapi.testclient import TestClient

from secscan.assets import AssetStore
from secscan.assets_web import mount_assets
from secscan.auth import AuthStore, mount_auth
from secscan.service import JobStore, create_app
from secscan.tenancy import SYSTEM_TENANT_ID
from secscan.web import mount_web_ui


def _register(client: TestClient, email: str, password: str) -> dict[str, object]:
    response = client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": password},
    )
    assert response.status_code == 201
    return response.json()


def _wait_for_terminal(client: TestClient, job_id: str) -> dict[str, object]:
    for _ in range(200):
        response = client.get(f"/api/v1/jobs/{job_id}")
        assert response.status_code == 200
        job = response.json()
        if job["status"] not in {"queued", "running"}:
            return job
        sleep(0.01)
    raise AssertionError("job did not reach a terminal state")


def test_session_jobs_and_assets_are_isolated_by_server_derived_tenant(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setenv("SECSCAN_REGISTRATION_ENABLED", "true")
    database = tmp_path / "jobs.db"
    job_root = tmp_path / "jobs"

    def runner(args: list[str]) -> int:
        output_dir = Path(args[args.index("--output-dir") + 1])
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "secscan.json").write_text("{}", encoding="utf-8")
        return 0

    app = create_app(job_root=job_root, job_database=database, runner=runner)
    mount_auth(app, database=database)
    mount_assets(app, database=database)
    mount_web_ui(app, job_root=job_root, job_database=database)
    first = TestClient(app)
    second = TestClient(app)

    first_user = _register(first, "first@example.com", "correct horse battery staple")
    second_user = _register(second, "second@example.com", "another correct horse battery staple")
    assert first_user["role"] == "admin"
    assert first_user["tenant_id"] == first_user["id"]
    assert second_user["tenant_id"] == second_user["id"]
    assert first_user["tenant_id"] != second_user["tenant_id"]

    first_job_response = first.post(
        "/api/v1/jobs", json={"scanner": "image", "target": "alpine:3.20"}
    )
    assert first_job_response.status_code == 202
    first_job_id = first_job_response.json()["id"]
    _wait_for_terminal(first, first_job_id)

    assert second.get(f"/api/v1/jobs/{first_job_id}").status_code == 404
    assert second.delete(f"/api/v1/jobs/{first_job_id}").status_code == 404
    assert second.get(f"/api/v1/jobs/{first_job_id}/artifacts").status_code == 404
    assert second.get(f"/api/v1/jobs/{first_job_id}/artifacts/secscan.json").status_code == 404
    assert second.get(f"/api/v1/jobs/{first_job_id}/summary").status_code == 404
    assert second.delete(f"/api/v1/jobs/{first_job_id}/history").status_code == 404
    assert all(item["id"] != first_job_id for item in second.get("/api/v1/jobs").json())

    first_assets = first.get("/api/v1/assets").json()
    assert len(first_assets) == 1
    first_asset_id = first_assets[0]["id"]
    assert second.get("/api/v1/assets").json() == []
    assert second.get(f"/api/v1/assets/{first_asset_id}").status_code == 404

    second_job_response = second.post(
        "/api/v1/jobs", json={"scanner": "image", "target": "alpine:3.20"}
    )
    assert second_job_response.status_code == 202
    second_job_id = second_job_response.json()["id"]
    _wait_for_terminal(second, second_job_id)

    assert first.get(f"/api/v1/jobs/{second_job_id}").status_code == 404
    assert first.get(f"/api/v1/jobs/{second_job_id}/summary").status_code == 404
    assert first.delete(f"/api/v1/jobs/{second_job_id}/history").status_code == 404

    second_assets = second.get("/api/v1/assets").json()
    assert len(second_assets) == 1
    assert second_assets[0]["target"] == "alpine:3.20"
    assert second_assets[0]["id"] != first_asset_id
    assert first.get(f"/api/v1/assets/{second_assets[0]['id']}").status_code == 404

    with sqlite3.connect(database) as connection:
        stored = connection.execute(
            "SELECT id, tenant_id FROM service_jobs ORDER BY created_at ASC"
        ).fetchall()
    assert stored == [
        (first_job_id, first_user["tenant_id"]),
        (second_job_id, second_user["tenant_id"]),
    ]


def test_auth_migration_backfills_existing_user_tenant_idempotently(tmp_path: Path) -> None:
    database = tmp_path / "jobs.db"
    with sqlite3.connect(database) as connection:
        connection.executescript(
            """
            CREATE TABLE auth_users (
                id TEXT PRIMARY KEY,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('admin', 'user')),
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            );
            INSERT INTO auth_users (
                id, email, password_hash, role, enabled, created_at
            ) VALUES (
                'admin-id', 'admin@example.com', 'unused', 'admin', 1,
                '2026-08-01T00:00:00+00:00'
            );
            """
        )

    store = AuthStore(database)
    store.migrate()

    with sqlite3.connect(database) as connection:
        tenant_id = connection.execute(
            "SELECT tenant_id FROM auth_users WHERE id = 'admin-id'"
        ).fetchone()[0]
    assert tenant_id == "admin-id"


def test_legacy_jobs_migrate_to_original_admin_or_system_scope(tmp_path: Path) -> None:
    with_admin = tmp_path / "admin.db"
    with sqlite3.connect(with_admin) as connection:
        connection.executescript(
            """
            CREATE TABLE auth_users (
                id TEXT PRIMARY KEY,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                enabled INTEGER NOT NULL,
                created_at TEXT NOT NULL
            );
            INSERT INTO auth_users VALUES (
                'admin-id', 'admin@example.com', 'unused', 'admin', 1,
                '2026-08-01T00:00:00+00:00'
            );
            CREATE TABLE service_jobs (
                id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                scanner TEXT NOT NULL,
                target TEXT NOT NULL,
                output_dir TEXT NOT NULL,
                created_at TEXT NOT NULL,
                started_at TEXT,
                completed_at TEXT,
                exit_code INTEGER,
                error TEXT
            );
            INSERT INTO service_jobs (
                id, status, scanner, target, output_dir, created_at
            ) VALUES (
                'legacy-admin', 'completed', 'image', 'alpine:3.20', '/tmp/legacy-admin',
                '2026-08-02T00:00:00+00:00'
            );
            """
        )

    JobStore(with_admin).migrate()
    with sqlite3.connect(with_admin) as connection:
        assert connection.execute(
            "SELECT tenant_id FROM service_jobs WHERE id = 'legacy-admin'"
        ).fetchone()[0] == "admin-id"

    without_admin = tmp_path / "system.db"
    with sqlite3.connect(without_admin) as connection:
        connection.executescript(
            """
            CREATE TABLE service_jobs (
                id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                scanner TEXT NOT NULL,
                target TEXT NOT NULL,
                output_dir TEXT NOT NULL,
                created_at TEXT NOT NULL,
                started_at TEXT,
                completed_at TEXT,
                exit_code INTEGER,
                error TEXT
            );
            INSERT INTO service_jobs (
                id, status, scanner, target, output_dir, created_at
            ) VALUES (
                'legacy-system', 'completed', 'image', 'alpine:3.20', '/tmp/legacy-system',
                '2026-08-02T00:00:00+00:00'
            );
            """
        )

    JobStore(without_admin).migrate()
    with sqlite3.connect(without_admin) as connection:
        assert connection.execute(
            "SELECT tenant_id FROM service_jobs WHERE id = 'legacy-system'"
        ).fetchone()[0] == SYSTEM_TENANT_ID


def test_asset_identity_includes_tenant(tmp_path: Path) -> None:
    database = tmp_path / "jobs.db"
    JobStore(database)
    with sqlite3.connect(database) as connection:
        connection.executemany(
            """
            INSERT INTO service_jobs (
                id, status, scanner, target, output_dir, created_at, tenant_id
            ) VALUES (?, 'completed', 'image', 'alpine:3.20', ?, ?, ?)
            """,
            [
                ("one", "/tmp/one", "2026-08-01T00:00:00+00:00", "tenant-one"),
                ("two", "/tmp/two", "2026-08-02T00:00:00+00:00", "tenant-two"),
            ],
        )

    store = AssetStore(database)
    first = store.list(tenant_id="tenant-one")
    second = store.list(tenant_id="tenant-two")
    assert len(first) == len(second) == 1
    assert first[0].id != second[0].id
    assert store.get(first[0].id, tenant_id="tenant-two") is None
