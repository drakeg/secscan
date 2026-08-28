from __future__ import annotations

from pathlib import Path
import sqlite3

from fastapi import FastAPI
from fastapi.testclient import TestClient

from secscan.assets import AssetStore
from secscan.assets_web import mount_assets


def _seed_jobs(database: Path) -> None:
    with sqlite3.connect(database) as connection:
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
            """
        )
        connection.executemany(
            """
            INSERT INTO service_jobs (
                id, status, scanner, target, output_dir, created_at
            ) VALUES (?, 'completed', ?, ?, ?, ?)
            """,
            [
                ("job-1", "image", "alpine:3.20", "/tmp/job-1", "2026-08-01T00:00:00+00:00"),
                ("job-2", "image", "alpine:3.20", "/tmp/job-2", "2026-08-02T00:00:00+00:00"),
                ("job-3", "network", "server.example.com", "/tmp/job-3", "2026-08-03T00:00:00+00:00"),
            ],
        )


def test_asset_store_reconciles_durable_job_history(tmp_path: Path) -> None:
    database = tmp_path / "jobs.db"
    _seed_jobs(database)
    store = AssetStore(database)

    assets = store.list()

    assert len(assets) == 2
    image = next(asset for asset in assets if asset.scanner == "image")
    assert image.id == AssetStore.asset_id("image", "alpine:3.20")
    assert image.first_seen_at == "2026-08-01T00:00:00+00:00"
    assert image.last_seen_at == "2026-08-02T00:00:00+00:00"
    assert image.latest_job_id == "job-2"
    assert image.scan_count == 2


def test_asset_reconciliation_is_idempotent(tmp_path: Path) -> None:
    database = tmp_path / "jobs.db"
    _seed_jobs(database)
    store = AssetStore(database)

    first = store.list()
    second = store.list()

    assert first == second
    with sqlite3.connect(database) as connection:
        count = connection.execute("SELECT COUNT(*) FROM service_assets").fetchone()[0]
    assert count == 2


def test_asset_api_lists_and_reads_assets(tmp_path: Path) -> None:
    database = tmp_path / "jobs.db"
    _seed_jobs(database)
    app = mount_assets(FastAPI(), database=database)
    client = TestClient(app)

    response = client.get("/api/v1/assets")
    assert response.status_code == 200
    assets = response.json()
    assert len(assets) == 2

    asset_id = AssetStore.asset_id("network", "server.example.com")
    detail = client.get(f"/api/v1/assets/{asset_id}")
    assert detail.status_code == 200
    assert detail.json()["latest_job_id"] == "job-3"
    assert detail.json()["scan_count"] == 1


def test_asset_api_rejects_unknown_asset(tmp_path: Path) -> None:
    database = tmp_path / "jobs.db"
    _seed_jobs(database)
    client = TestClient(mount_assets(FastAPI(), database=database))

    response = client.get("/api/v1/assets/missing")

    assert response.status_code == 404
    assert response.json() == {"detail": "asset not found"}
