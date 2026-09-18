from __future__ import annotations

import base64
from pathlib import Path
import secrets

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi import FastAPI
from fastapi.testclient import TestClient

from secscan.auth import AuthStore, User, mount_auth
from secscan.credential_tenancy import SshCredentialTenantMiddleware
from secscan.project_access import ProjectAccessStore, mount_project_access
from secscan.project_jobs import ProjectJobStore, mount_project_job_association
from secscan.projects import ProjectStore, mount_projects
from secscan.service import create_app
from secscan.tenant_api_keys import TenantApiKeyStore, mount_tenant_api_keys
from secscan.web import mount_web_ui


def _master_key() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")


def _private_key() -> str:
    return ed25519.Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")


def _known_hosts() -> str:
    public_key = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.OpenSSH,
        serialization.PublicFormat.OpenSSH,
    ).decode("ascii")
    return f"127.0.0.1 {public_key}\n"


def _app(monkeypatch, tmp_path: Path) -> tuple[FastAPI, Path]:
    monkeypatch.setenv("SECSCAN_REGISTRATION_ENABLED", "true")
    monkeypatch.setenv("SECSCAN_CREDENTIAL_KEY", _master_key())
    database = tmp_path / "jobs.db"
    root = tmp_path / "jobs"
    app = create_app(job_root=root, job_database=database, runner=lambda _args: 0)
    mount_auth(app, database=database)
    mount_tenant_api_keys(app, database=database)
    mount_projects(app, database=database)
    mount_project_access(app, database=database)
    mount_project_job_association(app, database=database)
    mount_web_ui(app, job_root=root, job_database=database)
    app.add_middleware(SshCredentialTenantMiddleware, database=database)
    return app, database


def test_project_acl_remains_additional_boundary_for_api_key_ssh_scan(
    monkeypatch, tmp_path: Path
) -> None:
    app, database = _app(monkeypatch, tmp_path)
    owner_client = TestClient(app)
    member_client = TestClient(app)

    owner = owner_client.post(
        "/api/v1/auth/register",
        json={"email": "owner@example.com", "password": "correct horse battery staple"},
    ).json()
    member_home = member_client.post(
        "/api/v1/auth/register",
        json={"email": "member@example.com", "password": "another correct horse battery staple"},
    ).json()

    auth = AuthStore(database)
    owner_user = User(
        id=str(owner["id"]),
        tenant_id=str(owner["tenant_id"]),
        email=str(owner["email"]),
        role=str(owner["role"]),
        enabled=bool(owner["enabled"]),
        created_at=str(owner["created_at"]),
    )
    auth.add_tenant_member(owner_user.id, owner_user.tenant_id, "member@example.com")

    member = User(
        id=str(member_home["id"]),
        tenant_id=owner_user.tenant_id,
        email="member@example.com",
        role="user",
        enabled=True,
        created_at=str(member_home["created_at"]),
    )

    projects = ProjectStore(database)
    project = projects.create(owner_user, "Production")
    access = ProjectAccessStore(database)
    access.grant(owner_user, project.id, member.id, "viewer")

    created = owner_client.post(
        "/api/v1/ssh-credentials",
        json={
            "name": "Shared",
            "username": "audit",
            "private_key": _private_key(),
            "known_hosts": _known_hosts(),
        },
    )
    assert created.status_code == 201, created.text
    profile_id = created.json()["id"]

    key_store = TenantApiKeyStore(database)
    _key, secret = key_store.create(
        actor=owner_user,
        name="member automation",
        principal_user_id=member.id,
    )
    headers = {"Authorization": f"Bearer {secret}"}
    member_client.cookies.clear()

    denied = member_client.post(
        "/api/v1/linux-host-jobs",
        headers=headers,
        json={
            "target": "127.0.0.1",
            "linux_host_authorized": True,
            "credential_profile_id": profile_id,
            "project_id": project.id,
        },
    )
    assert denied.status_code == 422
    assert denied.json()["detail"] == "project was not found"

    access.grant(owner_user, project.id, member.id, "operator")
    submitted = member_client.post(
        "/api/v1/linux-host-jobs",
        headers=headers,
        json={
            "target": "127.0.0.1",
            "linux_host_authorized": True,
            "credential_profile_id": profile_id,
            "project_id": project.id,
        },
    )
    assert submitted.status_code == 202, submitted.text
    document = submitted.json()
    assert document["project_id"] == project.id
    assert ProjectJobStore(database).project_id(
        str(document["id"]),
        tenant_id=owner_user.tenant_id,
    ) == project.id


def test_cross_tenant_project_id_fails_closed_for_credential_scan(monkeypatch, tmp_path: Path) -> None:
    app, database = _app(monkeypatch, tmp_path)
    first = TestClient(app)
    second = TestClient(app)

    first_user = first.post(
        "/api/v1/auth/register",
        json={"email": "first@example.com", "password": "correct horse battery staple"},
    ).json()
    second_user = second.post(
        "/api/v1/auth/register",
        json={"email": "second@example.com", "password": "another correct horse battery staple"},
    ).json()

    second_owner = User(
        id=str(second_user["id"]),
        tenant_id=str(second_user["tenant_id"]),
        email=str(second_user["email"]),
        role=str(second_user["role"]),
        enabled=bool(second_user["enabled"]),
        created_at=str(second_user["created_at"]),
    )

    project = ProjectStore(database).create(second_owner, "Other tenant")
    created = first.post(
        "/api/v1/ssh-credentials",
        json={
            "name": "First credential",
            "username": "audit",
            "private_key": _private_key(),
            "known_hosts": _known_hosts(),
        },
    )
    assert created.status_code == 201

    rejected = first.post(
        "/api/v1/linux-host-jobs",
        json={
            "target": "127.0.0.1",
            "linux_host_authorized": True,
            "credential_profile_id": created.json()["id"],
            "project_id": project.id,
        },
    )
    assert rejected.status_code == 422
    assert rejected.json()["detail"] == "project was not found"
