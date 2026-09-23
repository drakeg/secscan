from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from secscan.reassessment import ReassessmentScheduleStore, next_run_for


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
