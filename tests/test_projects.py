from pathlib import Path

import pytest

from secscan.auth import AuthStore
from secscan.projects import ProjectStore


def _users(database: Path):
    auth = AuthStore(database)
    owner = auth.register("owner@example.com", "correct horse battery staple")
    member = auth.register("member@example.com", "correct horse battery staple")
    outsider = auth.register("outside@example.com", "correct horse battery staple")
    auth.add_tenant_member(owner.id, owner.tenant_id, member.email)
    member = auth.authenticate(member.email, "correct horse battery staple")
    assert member is not None
    auth.switch_session_tenant(auth.create_session(member.id), owner.tenant_id)
    # User objects carry the active tenant, so obtain the member through that session.
    token = auth.create_session(member.id)
    auth.switch_session_tenant(token, owner.tenant_id)
    member = auth.user_for_session(token)
    assert member is not None
    return auth, owner, member, outsider


def test_owner_creates_and_members_list_and_use_project(tmp_path: Path) -> None:
    database = tmp_path / "secscan.db"
    _auth, owner, member, _outsider = _users(database)
    projects = ProjectStore(database)

    created = projects.create(owner, " Production ")
    assert created.name == "Production"
    assert created.enabled is True
    assert [project.id for project in projects.list(member)] == [created.id]
    assert projects.get(member, created.id, require_enabled=True).id == created.id


def test_member_cannot_administer_projects(tmp_path: Path) -> None:
    database = tmp_path / "secscan.db"
    _auth, owner, member, _outsider = _users(database)
    projects = ProjectStore(database)
    created = projects.create(owner, "Production")

    with pytest.raises(PermissionError, match="owner"):
        projects.create(member, "Unauthorized")
    with pytest.raises(PermissionError, match="owner"):
        projects.update(member, created.id, name="Renamed")


def test_cross_tenant_project_access_fails_closed(tmp_path: Path) -> None:
    database = tmp_path / "secscan.db"
    _auth, owner, _member, outsider = _users(database)
    projects = ProjectStore(database)
    created = projects.create(owner, "Production")

    assert projects.list(outsider) == []
    with pytest.raises(ValueError, match="not found"):
        projects.get(outsider, created.id)
    with pytest.raises(ValueError, match="not found"):
        projects.update(outsider, created.id, enabled=False)


def test_disabled_project_remains_readable_but_rejects_new_use(tmp_path: Path) -> None:
    database = tmp_path / "secscan.db"
    _auth, owner, member, _outsider = _users(database)
    projects = ProjectStore(database)
    created = projects.create(owner, "Production")

    disabled = projects.update(owner, created.id, enabled=False)
    assert disabled.enabled is False
    assert projects.get(member, created.id).enabled is False
    with pytest.raises(ValueError, match="disabled"):
        projects.get(member, created.id, require_enabled=True)


def test_project_names_are_unique_only_within_tenant(tmp_path: Path) -> None:
    database = tmp_path / "secscan.db"
    _auth, owner, _member, outsider = _users(database)
    projects = ProjectStore(database)
    projects.create(owner, "Production")

    with pytest.raises(ValueError, match="already exists"):
        projects.create(owner, "Production")
    other = projects.create(outsider, "Production")
    assert other.tenant_id == outsider.tenant_id
