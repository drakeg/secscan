from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from secscan.auth import AuthStore, User
from secscan.project_access import ProjectAccessStore
from secscan.projects import ProjectStore
from secscan.project_jobs import ProjectJobStore
from secscan.reassessment import (
    ReassessmentAssetAdapter,
    ReassessmentScheduleAuthorizer,
    ReassessmentScheduleStore,
    next_run_for,
)
from secscan.service import JobRecord, JobStore


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
    assets = __import__("secscan.assets", fromlist=["AssetStore"]).AssetStore(database)
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
    assets = __import__("secscan.assets", fromlist=["AssetStore"]).AssetStore(database)
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
    assets = __import__("secscan.assets", fromlist=["AssetStore"]).AssetStore(database)
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
    assets = __import__("secscan.assets", fromlist=["AssetStore"]).AssetStore(database)
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
