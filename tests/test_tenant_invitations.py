from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

import pytest

from secscan.auth import AuthStore
from secscan.tenant_invitations import TenantInvitationStore

PASSWORD = "correct horse battery staple"


def _users(database: Path):
    auth = AuthStore(database)
    owner = auth.register("owner@example.com", PASSWORD)
    invited = auth.register("invited@example.com", PASSWORD)
    outsider = auth.register("outsider@example.com", PASSWORD)
    return auth, owner, invited, outsider


def test_invitation_persists_only_token_digest_and_accepts_once(tmp_path: Path) -> None:
    database = tmp_path / "jobs.db"
    _auth, owner, invited, _outsider = _users(database)
    store = TenantInvitationStore(database)
    invitation, token = store.create(owner, " Invited@Example.COM ")
    assert invitation.email == "invited@example.com"
    with sqlite3.connect(database) as connection:
        stored = connection.execute(
            "SELECT token_hash FROM auth_tenant_invitations WHERE id = ?", (invitation.id,)
        ).fetchone()[0]
    assert stored == hashlib.sha256(token.encode()).hexdigest()
    assert token != stored
    assert store.accept(invited, token) == owner.tenant_id
    with pytest.raises(ValueError, match="no longer active"):
        store.accept(invited, token)


def test_invitation_is_bound_to_exact_authenticated_email(tmp_path: Path) -> None:
    database = tmp_path / "jobs.db"
    _auth, owner, _invited, outsider = _users(database)
    store = TenantInvitationStore(database)
    _invitation, token = store.create(owner, "invited@example.com")
    with pytest.raises(PermissionError, match="different account"):
        store.accept(outsider, token)


def test_non_owner_cannot_administer_invitations(tmp_path: Path) -> None:
    database = tmp_path / "jobs.db"
    auth, owner, invited, _outsider = _users(database)
    auth.add_tenant_member(owner.id, owner.tenant_id, invited.email)
    member = invited.__class__(
        invited.id, owner.tenant_id, invited.email, invited.role, invited.enabled, invited.created_at
    )
    store = TenantInvitationStore(database)
    with pytest.raises(PermissionError, match="owner"):
        store.create(member, "new@example.com")
    with pytest.raises(PermissionError, match="owner"):
        store.list(member)


def test_owner_can_revoke_and_cross_tenant_owner_cannot_revoke(tmp_path: Path) -> None:
    database = tmp_path / "jobs.db"
    _auth, owner, invited, outsider = _users(database)
    store = TenantInvitationStore(database)
    invitation, token = store.create(owner, invited.email)
    with pytest.raises(PermissionError, match="owner"):
        store.revoke(outsider, invitation.id)
    store.revoke(owner, invitation.id)
    with pytest.raises(ValueError, match="no longer active"):
        store.accept(invited, token)


def test_new_invitation_revokes_previous_active_invitation(tmp_path: Path) -> None:
    database = tmp_path / "jobs.db"
    _auth, owner, invited, _outsider = _users(database)
    store = TenantInvitationStore(database)
    _first, first_token = store.create(owner, invited.email)
    _second, second_token = store.create(owner, invited.email)
    with pytest.raises(ValueError, match="no longer active"):
        store.accept(invited, first_token)
    assert store.accept(invited, second_token) == owner.tenant_id


def test_existing_member_cannot_be_invited(tmp_path: Path) -> None:
    database = tmp_path / "jobs.db"
    auth, owner, invited, _outsider = _users(database)
    auth.add_tenant_member(owner.id, owner.tenant_id, invited.email)
    store = TenantInvitationStore(database)
    with pytest.raises(ValueError, match="already a member"):
        store.create(owner, invited.email)
