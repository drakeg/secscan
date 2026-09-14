from pathlib import Path

import pytest

from secscan.auth import AuthStore, User
from secscan.project_access import ProjectAccessStore
from secscan.projects import ProjectStore


def _member_in_owner_tenant(auth: AuthStore, owner: User, email: str) -> User:
    account = auth.register(email, "correct-horse-battery-staple")
    auth.add_tenant_member(owner.id, owner.tenant_id, email)
    return User(account.id, owner.tenant_id, account.email, account.role, True, account.created_at)


def test_project_acl_preserves_open_compatibility_until_first_grant(tmp_path: Path) -> None:
    database = tmp_path / "jobs.db"
    auth = AuthStore(database)
    projects = ProjectStore(database)
    access = ProjectAccessStore(database)
    owner = auth.register("owner@example.com", "correct-horse-battery-staple")
    member = _member_in_owner_tenant(auth, owner, "member@example.com")
    project = projects.create(owner, "Production")

    assert access.role(member, project.id) == "member"
    assert access.require_operator(member, project.id).id == project.id

    access.grant(owner, project.id, member.id, "viewer")
    assert access.role(member, project.id) == "viewer"
    assert access.require_read(member, project.id).id == project.id
    with pytest.raises(ValueError, match="project was not found"):
        access.require_operator(member, project.id)


def test_owner_can_promote_and_revoke_same_tenant_project_member(tmp_path: Path) -> None:
    database = tmp_path / "jobs.db"
    auth = AuthStore(database)
    projects = ProjectStore(database)
    access = ProjectAccessStore(database)
    owner = auth.register("owner@example.com", "correct-horse-battery-staple")
    member = _member_in_owner_tenant(auth, owner, "member@example.com")
    project = projects.create(owner, "Production")

    viewer = access.grant(owner, project.id, member.id, "viewer")
    assert viewer.role == "viewer"
    operator = access.grant(owner, project.id, member.id, "operator")
    assert operator.role == "operator"
    assert access.require_operator(member, project.id).id == project.id
    assert access.list_members(owner, project.id)[0].user_id == member.id

    access.revoke(owner, project.id, member.id)
    assert access.role(member, project.id) == "member"


def test_non_owner_cannot_administer_project_acl(tmp_path: Path) -> None:
    database = tmp_path / "jobs.db"
    auth = AuthStore(database)
    projects = ProjectStore(database)
    access = ProjectAccessStore(database)
    owner = auth.register("owner@example.com", "correct-horse-battery-staple")
    member = _member_in_owner_tenant(auth, owner, "member@example.com")
    other = _member_in_owner_tenant(auth, owner, "other@example.com")
    project = projects.create(owner, "Production")

    with pytest.raises(PermissionError, match="tenant owner access required"):
        access.grant(member, project.id, other.id, "viewer")


def test_cross_tenant_user_cannot_be_granted_project_access(tmp_path: Path) -> None:
    database = tmp_path / "jobs.db"
    auth = AuthStore(database)
    projects = ProjectStore(database)
    access = ProjectAccessStore(database)
    owner = auth.register("owner@example.com", "correct-horse-battery-staple")
    outsider = auth.register("outsider@example.com", "correct-horse-battery-staple")
    project = projects.create(owner, "Production")

    with pytest.raises(ValueError, match="tenant member was not found"):
        access.grant(owner, project.id, outsider.id, "viewer")


def test_disabled_project_remains_readable_but_rejects_operator_submission(tmp_path: Path) -> None:
    database = tmp_path / "jobs.db"
    auth = AuthStore(database)
    projects = ProjectStore(database)
    access = ProjectAccessStore(database)
    owner = auth.register("owner@example.com", "correct-horse-battery-staple")
    member = _member_in_owner_tenant(auth, owner, "member@example.com")
    project = projects.create(owner, "Production")
    access.grant(owner, project.id, member.id, "operator")
    projects.update(owner, project.id, enabled=False)

    assert access.require_read(member, project.id).id == project.id
    with pytest.raises(ValueError, match="project is disabled"):
        access.require_operator(member, project.id)
