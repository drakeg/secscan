from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
import sqlite3

import pytest

from secscan.assets import AssetStore
from secscan.auth import AuthStore, User
from secscan.project_access import ProjectAccessStore
from secscan.projects import ProjectStore
from secscan.project_jobs import ProjectJobStore
from secscan.reassessment import (
    ReassessmentAssetAdapter,
    ReassessmentExecutor,
    ReassessmentScheduleAuthorizer,
    ReassessmentScheduler,
    ReassessmentScheduleStore,
    next_run_for,
)
from secscan.service import JobManager, JobRecord, JobStore


NOW = datetime(2026, 9, 23, 18, 0, tzinfo=UTC)


def test_next_run_supports_only_bounded_cadences() -> None:
    assert next_run_for("daily", now=NOW) == NOW + timedelta(days=1)
    assert next_run_for("weekly", now=NOW) == NOW + timedelta(days=7)
    with pytest.raises(ValueError, match="daily or weekly"):
        next_run_for("* * * * *", now=NOW)


def test_schedule_time_must_be_timezone_aware() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        next_run_for("daily", now=datetime(2026, 9, 23, 18, 0))


def test_schedule_persists_tenant_scope_and_public_metadata(tmp_path: Path) -> None:
    database = tmp_path / "jobs.db"
    store = ReassessmentScheduleStore(database)
    created = store.create(
        tenant_id="tenant-a",
        asset_id="asset-1",
        project_id="project-1",
        created_by="user-1",
        cadence="daily",
        now=NOW,
    )

    reopened = ReassessmentScheduleStore(database)
    loaded = reopened.get(created.id, tenant_id="tenant-a")
    assert loaded == created
    assert loaded.next_run_at == (NOW + timedelta(days=1)).isoformat()
    assert loaded.public() == {
        "id": created.id,
        "asset_id": "asset-1",
        "project_id": "project-1",
        "cadence": "daily",
        "enabled": True,
        "next_run_at": (NOW + timedelta(days=1)).isoformat(),
        "last_attempted_at": None,
        "last_enqueued_at": None,
        "created_at": NOW.isoformat(),
        "updated_at": NOW.isoformat(),
    }
    assert "tenant_id" not in loaded.public()
    assert "created_by" not in loaded.public()


def test_schedule_lookup_and_listing_are_tenant_scoped(tmp_path: Path) -> None:
    store = ReassessmentScheduleStore(tmp_path / "jobs.db")
    first = store.create(
        tenant_id="tenant-a",
        asset_id="asset-1",
        created_by="user-a",
        cadence="daily",
        now=NOW,
    )
    store.create(
        tenant_id="tenant-b",
        asset_id="asset-1",
        created_by="user-b",
        cadence="weekly",
        now=NOW,
    )

    assert [item.id for item in store.list(tenant_id="tenant-a")] == [first.id]
    with pytest.raises(ValueError, match="not found"):
        store.get(first.id, tenant_id="tenant-b")


def test_duplicate_schedule_for_same_asset_scope_fails_closed(tmp_path: Path) -> None:
    store = ReassessmentScheduleStore(tmp_path / "jobs.db")
    kwargs = {
        "tenant_id": "tenant-a",
        "asset_id": "asset-1",
        "project_id": "project-1",
        "created_by": "user-a",
        "cadence": "daily",
        "now": NOW,
    }
    store.create(**kwargs)
    with pytest.raises(ValueError, match="already exists"):
        store.create(**kwargs)


def test_due_is_deterministic_and_excludes_future_or_disabled_by_default(
    tmp_path: Path,
) -> None:
    store = ReassessmentScheduleStore(tmp_path / "jobs.db")
    first = store.create(
        tenant_id="tenant-a",
        asset_id="asset-1",
        created_by="user-a",
        cadence="daily",
        now=NOW,
    )
    second = store.create(
        tenant_id="tenant-b",
        asset_id="asset-2",
        created_by="user-b",
        cadence="weekly",
        now=NOW,
    )

    assert store.due(now=NOW + timedelta(hours=23)) == []
    assert [item.id for item in store.due(now=NOW + timedelta(days=1))] == [first.id]
    assert [item.id for item in store.due(now=NOW + timedelta(days=8))] == [
        first.id,
        second.id,
    ]


def test_record_attempt_advances_from_current_time_without_catchup_burst(
    tmp_path: Path,
) -> None:
    store = ReassessmentScheduleStore(tmp_path / "jobs.db")
    schedule = store.create(
        tenant_id="tenant-a",
        asset_id="asset-1",
        created_by="user-a",
        cadence="daily",
        now=NOW,
    )
    restart_time = NOW + timedelta(days=30)

    updated = store.record_attempt(
        schedule.id,
        tenant_id="tenant-a",
        enqueued=True,
        now=restart_time,
    )

    assert updated.last_attempted_at == restart_time.isoformat()
    assert updated.last_enqueued_at == restart_time.isoformat()
    assert updated.next_run_at == (restart_time + timedelta(days=1)).isoformat()
    assert store.due(now=restart_time) == []


def test_failed_attempt_records_attempt_but_not_successful_enqueue(tmp_path: Path) -> None:
    store = ReassessmentScheduleStore(tmp_path / "jobs.db")
    schedule = store.create(
        tenant_id="tenant-a",
        asset_id="asset-1",
        created_by="user-a",
        cadence="weekly",
        now=NOW,
    )
    attempted = NOW + timedelta(days=8)

    updated = store.record_attempt(
        schedule.id,
        tenant_id="tenant-a",
        enqueued=False,
        now=attempted,
    )

    assert updated.last_attempted_at == attempted.isoformat()
    assert updated.last_enqueued_at is None
    assert updated.next_run_at == (attempted + timedelta(days=7)).isoformat()


def test_due_limit_is_bounded(tmp_path: Path) -> None:
    store = ReassessmentScheduleStore(tmp_path / "jobs.db")
    with pytest.raises(ValueError, match="between 1 and 100"):
        store.due(now=NOW, limit=0)
    with pytest.raises(ValueError, match="between 1 and 100"):
        store.due(now=NOW, limit=101)


def _member_in_tenant(auth: AuthStore, owner: User, email: str) -> User:
    account = auth.register(email, "correct-horse-battery-staple")
    auth.add_tenant_member(owner.id, owner.tenant_id, email)
    return User(account.id, owner.tenant_id, account.email, account.role, True, account.created_at)


def test_tenant_owner_can_manage_tenant_and_project_schedules(tmp_path: Path) -> None:
    database = tmp_path / "jobs.db"
    auth = AuthStore(database)
    projects = ProjectStore(database)
    authorizer = ReassessmentScheduleAuthorizer(database)
    owner = auth.register("owner@example.com", "correct-horse-battery-staple")
    project = projects.create(owner, "Production")

    authorizer.require_manage(owner, project_id=None)
    authorizer.require_manage(owner, project_id=project.id)


def test_tenant_member_cannot_manage_unscoped_schedule(tmp_path: Path) -> None:
    database = tmp_path / "jobs.db"
    auth = AuthStore(database)
    authorizer = ReassessmentScheduleAuthorizer(database)
    owner = auth.register("owner@example.com", "correct-horse-battery-staple")
    member = _member_in_tenant(auth, owner, "member@example.com")

    with pytest.raises(PermissionError, match="tenant owner"):
        authorizer.require_manage(member, project_id=None)


def test_project_operator_can_manage_only_authorized_project_schedule(tmp_path: Path) -> None:
    database = tmp_path / "jobs.db"
    auth = AuthStore(database)
    projects = ProjectStore(database)
    access = ProjectAccessStore(database)
    authorizer = ReassessmentScheduleAuthorizer(database)
    owner = auth.register("owner@example.com", "correct-horse-battery-staple")
    operator = _member_in_tenant(auth, owner, "operator@example.com")
    viewer = _member_in_tenant(auth, owner, "viewer@example.com")
    project = projects.create(owner, "Production")
    access.grant(owner, project.id, operator.id, "operator")
    access.grant(owner, project.id, viewer.id, "viewer")

    authorizer.require_manage(operator, project_id=project.id)
    with pytest.raises(PermissionError, match="project operator"):
        authorizer.require_manage(viewer, project_id=project.id)

    access.revoke(owner, project.id, operator.id)
    with pytest.raises(PermissionError, match="project operator"):
        authorizer.require_manage(operator, project_id=project.id)


def test_schedule_access_fails_closed_across_tenants(tmp_path: Path) -> None:
    database = tmp_path / "jobs.db"
    auth = AuthStore(database)
    schedules = ReassessmentScheduleStore(database)
    authorizer = ReassessmentScheduleAuthorizer(database)
    owner = auth.register("owner@example.com", "correct-horse-battery-staple")
    outsider = auth.register("outsider@example.com", "correct-horse-battery-staple")
    schedule = schedules.create(
        tenant_id=owner.tenant_id,
        asset_id="asset-1",
        created_by=owner.id,
        cadence="daily",
        now=NOW,
    )

    with pytest.raises(ValueError, match="not found"):
        authorizer.require_schedule_access(outsider, schedule)


def _save_asset_job(
    database: Path,
    *,
    job_id: str,
    tenant_id: str,
    scanner: str,
    target: str,
) -> None:
    JobStore(database).save(
        JobRecord(
            id=job_id,
            status="completed",
            scanner=scanner,
            target=target,
            output_dir=f"/reports/{job_id}",
            created_at=NOW.isoformat(),
            completed_at=NOW.isoformat(),
            exit_code=0,
            tenant_id=tenant_id,
        )
    )


def test_asset_adapter_reconstructs_safe_image_submission(tmp_path: Path) -> None:
    database = tmp_path / "jobs.db"
    _save_asset_job(
        database,
        job_id="job-1",
        tenant_id="tenant-a",
        scanner="image",
        target="python:3.14",
    )
    assets = AssetStore(database)
    asset = assets.list(tenant_id="tenant-a")[0]
    schedule = ReassessmentScheduleStore(database).create(
        tenant_id="tenant-a",
        asset_id=asset.id,
        created_by="user-a",
        cadence="daily",
        now=NOW,
    )

    submission = ReassessmentAssetAdapter(database).submission_for(schedule)

    assert submission.scanner == "image"
    assert submission.target == "python:3.14"
    assert submission.policy is None
    assert submission.baseline is None


@pytest.mark.parametrize("scanner", ["filesystem", "sbom", "network", "network-range", "web-dast"])
def test_asset_adapter_rejects_scanners_without_persisted_safe_profile(
    tmp_path: Path,
    scanner: str,
) -> None:
    database = tmp_path / f"{scanner}.db"
    _save_asset_job(
        database,
        job_id="job-1",
        tenant_id="tenant-a",
        scanner=scanner,
        target="example",
    )
    assets = AssetStore(database)
    asset = assets.list(tenant_id="tenant-a")[0]
    schedule = ReassessmentScheduleStore(database).create(
        tenant_id="tenant-a",
        asset_id=asset.id,
        created_by="user-a",
        cadence="daily",
        now=NOW,
    )

    with pytest.raises(ValueError, match="not supported"):
        ReassessmentAssetAdapter(database).submission_for(schedule)


def test_asset_adapter_rejects_local_repository_target(tmp_path: Path) -> None:
    database = tmp_path / "jobs.db"
    _save_asset_job(
        database,
        job_id="job-1",
        tenant_id="tenant-a",
        scanner="repository",
        target="/workspace/repository",
    )
    asset = AssetStore(database).list(tenant_id="tenant-a")[0]
    schedule = ReassessmentScheduleStore(database).create(
        tenant_id="tenant-a",
        asset_id=asset.id,
        created_by="user-a",
        cadence="daily",
        now=NOW,
    )

    with pytest.raises(ValueError, match="remote repository URL"):
        ReassessmentAssetAdapter(database).submission_for(schedule)


def test_asset_adapter_preserves_valid_remote_repository_target(tmp_path: Path) -> None:
    database = tmp_path / "jobs.db"
    target = "https://github.com/example/project.git"
    _save_asset_job(
        database,
        job_id="job-1",
        tenant_id="tenant-a",
        scanner="repository",
        target=target,
    )
    asset = AssetStore(database).list(tenant_id="tenant-a")[0]
    schedule = ReassessmentScheduleStore(database).create(
        tenant_id="tenant-a",
        asset_id=asset.id,
        created_by="user-a",
        cadence="daily",
        now=NOW,
    )

    submission = ReassessmentAssetAdapter(database).submission_for(schedule)

    assert submission.scanner == "repository"
    assert submission.target == target


def test_asset_adapter_requires_exact_project_binding(tmp_path: Path) -> None:
    database = tmp_path / "jobs.db"
    auth = AuthStore(database)
    projects = ProjectStore(database)
    owner = auth.register("owner@example.com", "correct-horse-battery-staple")
    project = projects.create(owner, "Production")
    _save_asset_job(
        database,
        job_id="job-1",
        tenant_id=owner.tenant_id,
        scanner="image",
        target="python:3.14",
    )
    ProjectJobStore(database).associate(
        job_id="job-1",
        tenant_id=owner.tenant_id,
        project_id=project.id,
    )
    assets = AssetStore(database)
    asset = assets.list(tenant_id=owner.tenant_id)[0]
    schedule = ReassessmentScheduleStore(database).create(
        tenant_id=owner.tenant_id,
        asset_id=asset.id,
        created_by=owner.id,
        cadence="daily",
        now=NOW,
    )

    with pytest.raises(ValueError, match="project binding"):
        ReassessmentAssetAdapter(database).submission_for(schedule)


def test_asset_adapter_rejects_cross_tenant_asset_reference(tmp_path: Path) -> None:
    database = tmp_path / "jobs.db"
    _save_asset_job(
        database,
        job_id="job-1",
        tenant_id="tenant-a",
        scanner="image",
        target="python:3.14",
    )
    assets = AssetStore(database)
    asset = assets.list(tenant_id="tenant-a")[0]
    schedule = ReassessmentScheduleStore(database).create(
        tenant_id="tenant-b",
        asset_id=asset.id,
        created_by="user-b",
        cadence="daily",
        now=NOW,
    )

    with pytest.raises(ValueError, match="asset is unavailable"):
        ReassessmentAssetAdapter(database).submission_for(schedule)


def test_due_claim_is_exclusive_until_released_or_expired(tmp_path: Path) -> None:
    store = ReassessmentScheduleStore(tmp_path / "jobs.db")
    schedule = store.create(
        tenant_id="tenant-a",
        asset_id="asset-1",
        created_by="user-a",
        cadence="daily",
        now=NOW,
    )
    due_time = NOW + timedelta(days=1)

    claimed = store.claim_due(now=due_time)
    assert claimed is not None
    assert claimed.id == schedule.id
    assert claimed.claim_token is not None
    assert store.claim_due(now=due_time) is None

    store.release_claim(
        claimed.id,
        tenant_id=claimed.tenant_id,
        claim_token=claimed.claim_token,
        now=due_time,
    )
    reclaimed = store.claim_due(now=due_time)
    assert reclaimed is not None
    assert reclaimed.id == schedule.id
    assert reclaimed.claim_token != claimed.claim_token


def test_expired_due_claim_can_be_recovered_after_restart(tmp_path: Path) -> None:
    database = tmp_path / "jobs.db"
    store = ReassessmentScheduleStore(database)
    store.create(
        tenant_id="tenant-a",
        asset_id="asset-1",
        created_by="user-a",
        cadence="daily",
        now=NOW,
    )
    due_time = NOW + timedelta(days=1)
    claimed = store.claim_due(now=due_time, lease=timedelta(minutes=5))
    assert claimed is not None

    reopened = ReassessmentScheduleStore(database)
    assert reopened.claim_due(now=due_time + timedelta(minutes=4)) is None
    recovered = reopened.claim_due(now=due_time + timedelta(minutes=5))
    assert recovered is not None
    assert recovered.id == claimed.id
    assert recovered.claim_token != claimed.claim_token


def test_claimed_attempt_requires_matching_token_and_clears_lease(tmp_path: Path) -> None:
    store = ReassessmentScheduleStore(tmp_path / "jobs.db")
    store.create(
        tenant_id="tenant-a",
        asset_id="asset-1",
        created_by="user-a",
        cadence="daily",
        now=NOW,
    )
    due_time = NOW + timedelta(days=1)
    claimed = store.claim_due(now=due_time)
    assert claimed is not None
    assert claimed.claim_token is not None

    with pytest.raises(ValueError, match="not found"):
        store.record_attempt(
            claimed.id,
            tenant_id=claimed.tenant_id,
            enqueued=True,
            now=due_time,
            claim_token="wrong-token",
        )

    updated = store.record_attempt(
        claimed.id,
        tenant_id=claimed.tenant_id,
        enqueued=True,
        now=due_time,
        claim_token=claimed.claim_token,
    )
    assert updated.claim_token is None
    assert updated.claim_expires_at is None
    assert updated.next_run_at == (due_time + timedelta(days=1)).isoformat()


@pytest.mark.parametrize(
    "lease",
    [timedelta(0), timedelta(minutes=-1), timedelta(minutes=31)],
)
def test_claim_lease_is_bounded(tmp_path: Path, lease: timedelta) -> None:
    store = ReassessmentScheduleStore(tmp_path / "jobs.db")
    with pytest.raises(ValueError, match="at most 30 minutes"):
        store.claim_due(now=NOW, lease=lease)


def test_executor_enqueues_one_due_safe_asset_and_advances_schedule(tmp_path: Path) -> None:
    database = tmp_path / "jobs.db"
    reports = tmp_path / "reports"
    _save_asset_job(
        database,
        job_id="job-1",
        tenant_id="tenant-a",
        scanner="image",
        target="python:3.14",
    )
    asset = AssetStore(database).list(tenant_id="tenant-a")[0]
    schedules = ReassessmentScheduleStore(database)
    schedule = schedules.create(
        tenant_id="tenant-a",
        asset_id=asset.id,
        created_by="user-a",
        cadence="daily",
        now=NOW,
    )
    manager = JobManager(reports, lambda _args: 0, database=database)

    job = ReassessmentExecutor(database, manager).run_one(now=NOW + timedelta(days=1))

    assert job is not None
    assert job.tenant_id == "tenant-a"
    assert job.scanner == "image"
    assert job.target == "python:3.14"
    updated = schedules.get(schedule.id, tenant_id="tenant-a")
    assert updated.last_enqueued_at == (NOW + timedelta(days=1)).isoformat()
    assert updated.next_run_at == (NOW + timedelta(days=2)).isoformat()
    assert updated.claim_token is None
    manager.executor.shutdown(wait=True)


def test_executor_records_failed_adapter_attempt_without_enqueue(tmp_path: Path) -> None:
    database = tmp_path / "jobs.db"
    reports = tmp_path / "reports"
    _save_asset_job(
        database,
        job_id="job-1",
        tenant_id="tenant-a",
        scanner="network",
        target="127.0.0.1",
    )
    asset = AssetStore(database).list(tenant_id="tenant-a")[0]
    schedules = ReassessmentScheduleStore(database)
    schedule = schedules.create(
        tenant_id="tenant-a",
        asset_id=asset.id,
        created_by="user-a",
        cadence="daily",
        now=NOW,
    )
    manager = JobManager(reports, lambda _args: 0, database=database)
    run_at = NOW + timedelta(days=1)

    assert ReassessmentExecutor(database, manager).run_one(now=run_at) is None

    updated = schedules.get(schedule.id, tenant_id="tenant-a")
    assert updated.last_attempted_at == run_at.isoformat()
    assert updated.last_enqueued_at is None
    assert updated.next_run_at == (run_at + timedelta(days=1)).isoformat()
    assert updated.claim_token is None
    assert manager.list(tenant_id="tenant-a") == [
        manager.store.get("job-1", tenant_id="tenant-a")
    ]
    manager.executor.shutdown(wait=True)


def test_executor_preserves_project_association_for_scheduled_job(tmp_path: Path) -> None:
    database = tmp_path / "jobs.db"
    reports = tmp_path / "reports"
    auth = AuthStore(database)
    projects = ProjectStore(database)
    owner = auth.register("owner@example.com", "correct-horse-battery-staple")
    project = projects.create(owner, "Production")
    _save_asset_job(
        database,
        job_id="job-1",
        tenant_id=owner.tenant_id,
        scanner="image",
        target="python:3.14",
    )
    links = ProjectJobStore(database)
    links.associate(job_id="job-1", tenant_id=owner.tenant_id, project_id=project.id)
    asset = AssetStore(database).list(tenant_id=owner.tenant_id)[0]
    ReassessmentScheduleStore(database).create(
        tenant_id=owner.tenant_id,
        asset_id=asset.id,
        created_by=owner.id,
        cadence="daily",
        project_id=project.id,
        now=NOW,
    )
    manager = JobManager(reports, lambda _args: 0, database=database)

    job = ReassessmentExecutor(database, manager).run_one(now=NOW + timedelta(days=1))

    assert job is not None
    assert links.project_id(job.id, tenant_id=owner.tenant_id) == project.id
    manager.executor.shutdown(wait=True)


def test_scheduler_tick_is_bounded_and_uses_injected_clock(tmp_path: Path) -> None:
    database = tmp_path / "jobs.db"
    reports = tmp_path / "reports"
    for index in range(3):
        _save_asset_job(
            database,
            job_id=f"job-{index}",
            tenant_id="tenant-a",
            scanner="image",
            target=f"python:3.{index + 10}",
        )
    assets = AssetStore(database).list(tenant_id="tenant-a")
    schedules = ReassessmentScheduleStore(database)
    for asset in assets:
        schedules.create(
            tenant_id="tenant-a",
            asset_id=asset.id,
            created_by="user-a",
            cadence="daily",
            now=NOW,
        )
    manager = JobManager(reports, lambda _args: 0, database=database)
    scheduler = ReassessmentScheduler(
        ReassessmentExecutor(database, manager),
        clock=lambda: NOW + timedelta(days=1),
    )

    assert scheduler.tick(limit=2) == 2
    assert scheduler.tick(limit=2) == 1
    assert scheduler.tick(limit=2) == 0
    manager.executor.shutdown(wait=True)


@pytest.mark.parametrize(
    "interval",
    [timedelta(seconds=9), timedelta(hours=1, seconds=1)],
)
def test_scheduler_interval_is_bounded(tmp_path: Path, interval: timedelta) -> None:
    database = tmp_path / "jobs.db"
    manager = JobManager(tmp_path / "reports", lambda _args: 0, database=database)
    with pytest.raises(ValueError, match="between 10 seconds and 1 hour"):
        ReassessmentScheduler(ReassessmentExecutor(database, manager), interval=interval)
    manager.executor.shutdown(wait=True)


def test_scheduler_tick_limit_is_bounded(tmp_path: Path) -> None:
    database = tmp_path / "jobs.db"
    manager = JobManager(tmp_path / "reports", lambda _args: 0, database=database)
    scheduler = ReassessmentScheduler(ReassessmentExecutor(database, manager))
    with pytest.raises(ValueError, match="between 1 and 100"):
        scheduler.tick(limit=101)
    manager.executor.shutdown(wait=True)


def test_tenant_level_schedule_scope_is_unique_with_null_project(tmp_path: Path) -> None:
    store = ReassessmentScheduleStore(tmp_path / "jobs.db")
    store.create(
        tenant_id="tenant-a",
        asset_id="asset-1",
        created_by="user-a",
        cadence="daily",
        now=NOW,
    )
    with pytest.raises(ValueError, match="already exists"):
        store.create(
            tenant_id="tenant-a",
            asset_id="asset-1",
            created_by="user-a",
            cadence="weekly",
            now=NOW,
        )


def test_pause_clears_claim_and_prevents_due_execution(tmp_path: Path) -> None:
    store = ReassessmentScheduleStore(tmp_path / "jobs.db")
    schedule = store.create(
        tenant_id="tenant-a",
        asset_id="asset-1",
        created_by="user-a",
        cadence="daily",
        now=NOW,
    )
    due_time = NOW + timedelta(days=1)
    claimed = store.claim_due(now=due_time)
    assert claimed is not None
    paused = store.set_enabled(
        schedule.id,
        tenant_id="tenant-a",
        enabled=False,
        now=due_time,
    )
    assert paused.enabled is False
    assert paused.claim_token is None
    assert store.claim_due(now=due_time) is None


def test_schedule_delete_is_tenant_scoped(tmp_path: Path) -> None:
    store = ReassessmentScheduleStore(tmp_path / "jobs.db")
    schedule = store.create(
        tenant_id="tenant-a",
        asset_id="asset-1",
        created_by="user-a",
        cadence="daily",
        now=NOW,
    )
    with pytest.raises(ValueError, match="not found"):
        store.delete(schedule.id, tenant_id="tenant-b")
    store.delete(schedule.id, tenant_id="tenant-a")
    with pytest.raises(ValueError, match="not found"):
        store.get(schedule.id, tenant_id="tenant-a")


def test_migrate_adds_claim_columns_to_preclaim_database(tmp_path: Path) -> None:
    database = tmp_path / "jobs.db"
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            CREATE TABLE reassessment_schedules (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                asset_id TEXT NOT NULL,
                project_id TEXT,
                cadence TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                next_run_at TEXT NOT NULL,
                last_attempted_at TEXT,
                last_enqueued_at TEXT,
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(tenant_id, asset_id, project_id)
            )
            """
        )

    ReassessmentScheduleStore(database)

    with sqlite3.connect(database) as connection:
        columns = {
            str(row[1])
            for row in connection.execute(
                "PRAGMA table_info(reassessment_schedules)"
            ).fetchall()
        }
    assert {"claim_token", "claim_expires_at"} <= columns


def test_record_attempt_without_token_cannot_complete_active_claim(tmp_path: Path) -> None:
    store = ReassessmentScheduleStore(tmp_path / "jobs.db")
    schedule = store.create(
        tenant_id="tenant-a",
        asset_id="asset-1",
        created_by="user-a",
        cadence="daily",
        now=NOW,
    )
    due_time = NOW + timedelta(days=1)
    claimed = store.claim_due(now=due_time)
    assert claimed is not None
    assert claimed.claim_token is not None

    with pytest.raises(ValueError, match="not found"):
        store.record_attempt(
            schedule.id,
            tenant_id="tenant-a",
            enqueued=True,
            now=due_time,
            claim_token=None,
        )

    persisted = store.get(schedule.id, tenant_id="tenant-a")
    assert persisted.claim_token == claimed.claim_token
    assert persisted.last_attempted_at is None
