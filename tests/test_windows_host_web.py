from __future__ import annotations

import base64
from pathlib import Path
import secrets
import subprocess
from time import sleep

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi.testclient import TestClient

from secscan.auth import mount_auth
from secscan.public_site import mount_public_site
from secscan.service import create_app
from secscan.ssh_credentials import SshCredentialStore
from secscan.windows_host_web import mount_windows_host_submission


def _master_key() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")


def _private_key() -> str:
    key = ed25519.Ed25519PrivateKey.generate()
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")


def _known_hosts(host: str = "127.0.0.1") -> str:
    public_key = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.OpenSSH,
        serialization.PublicFormat.OpenSSH,
    ).decode("ascii")
    return f"{host} {public_key}\n"


def _app(tmp_path: Path, *, runner=lambda _args: 0):  # noqa: ANN001
    root = tmp_path / "jobs"
    database = root / "jobs.db"
    app = create_app(job_root=root, job_database=database, runner=runner)
    mount_windows_host_submission(app, database=database, job_root=root, job_database=database)
    return app


def _configure_fallback(monkeypatch, tmp_path: Path, *, user: str = "Administrator") -> None:
    key = tmp_path / "id_ed25519"
    known_hosts = tmp_path / "known_hosts"
    key.write_text("test-key-placeholder\n", encoding="utf-8")
    known_hosts.write_text("host-key-placeholder\n", encoding="utf-8")
    monkeypatch.setenv("SECSCAN_SSH_USER", user)
    monkeypatch.setenv("SECSCAN_SSH_KEY", str(key))
    monkeypatch.setenv("SECSCAN_SSH_KNOWN_HOSTS", str(known_hosts))
    monkeypatch.setenv("SECSCAN_SSH_PORT", "22")


def test_web_ui_exposes_windows_authenticated_workflow() -> None:
    web_root = Path(__file__).parents[1] / "secscan" / "web_assets"
    html = (web_root / "index.html").read_text(encoding="utf-8")
    javascript = (web_root / "windows_host.js").read_text(encoding="utf-8")

    assert '<option value="windows-host">Windows server — Authenticated assessment</option>' in html
    assert "windows-host-authorized" in html
    assert "windows-host-user" in html
    assert 'api("/api/v1/windows-host-jobs"' in javascript
    assert "windows_host_authorized:true" in javascript
    assert "private_key" not in javascript
    assert "known_hosts" not in javascript
    assert "SECSCAN_SSH_KEY" not in javascript


def test_windows_host_requires_authorization_and_configuration(tmp_path: Path) -> None:
    client = TestClient(_app(tmp_path))

    assert client.get("/api/v1/windows-host-capability").json() == {"configured": False}
    unauthorized = client.post(
        "/api/v1/windows-host-jobs",
        json={"target": "192.0.2.20", "windows_host_authorized": False},
    )
    unconfigured = client.post(
        "/api/v1/windows-host-jobs",
        json={"target": "192.0.2.20", "windows_host_authorized": True},
    )

    assert unauthorized.status_code == 422
    assert "authorization acknowledgement" in unauthorized.json()["detail"]
    assert unconfigured.status_code == 422
    assert "Windows host scanning is not configured" in unconfigured.json()["detail"]
    assert client.get("/api/v1/jobs").json() == []


def test_windows_host_rejects_bad_target_and_username_before_persistence(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("SECSCAN_CREDENTIAL_KEY", _master_key())
    client = TestClient(_app(tmp_path))

    bad_target = client.post(
        "/api/v1/windows-host-jobs",
        json={"target": "https://example.com", "windows_host_authorized": True},
    )
    bad_user = client.post(
        "/api/v1/windows-host-jobs",
        json={
            "target": "192.0.2.20",
            "windows_host_authorized": True,
            "ssh_username": "bad user",
        },
    )

    assert bad_target.status_code == 422
    assert bad_user.status_code == 422
    assert "simple Windows" in bad_user.json()["detail"]
    assert client.get("/api/v1/jobs").json() == []


def test_configured_windows_fallback_uses_normal_job_pipeline(
    monkeypatch, tmp_path: Path
) -> None:
    _configure_fallback(monkeypatch, tmp_path)
    captured: list[list[str]] = []

    def runner(args: list[str]) -> int:
        captured.append(args)
        output_dir = Path(args[args.index("--output-dir") + 1])
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "secscan.json").write_text(
            '{"findings": [], "summary": {"total": 0}}', encoding="utf-8"
        )
        return 0

    client = TestClient(_app(tmp_path, runner=runner))
    assert client.get("/api/v1/windows-host-capability").json() == {"configured": True}
    submitted = client.post(
        "/api/v1/windows-host-jobs",
        json={
            "target": "192.0.2.20",
            "windows_host_authorized": True,
            "timeout": 321,
            "fail_on": "HIGH",
        },
    )
    assert submitted.status_code == 202
    job_id = submitted.json()["id"]

    for _ in range(100):
        job = client.get(f"/api/v1/jobs/{job_id}").json()
        if job["status"] == "completed":
            break
        sleep(0.01)

    assert job["scanner"] == "windows-host"
    assert job["target"] == "192.0.2.20"
    assert captured[0][:3] == ["scan", "windows-host", "192.0.2.20"]
    assert captured[0][captured[0].index("--timeout") + 1] == "321"
    assert captured[0][captured[0].index("--fail-on") + 1] == "HIGH"


def test_profile_windows_job_uses_ephemeral_files_and_username_override(
    monkeypatch, tmp_path: Path
) -> None:
    master_key = _master_key()
    monkeypatch.setenv("SECSCAN_CREDENTIAL_KEY", master_key)
    captured: dict[str, object] = {}

    def fake_run(command, *, check, capture_output, text, env, timeout):  # noqa: ANN001
        assert check is False
        assert capture_output is True
        assert text is True
        assert timeout == 153
        captured["command"] = list(command)
        captured["user"] = env["SECSCAN_SSH_USER"]
        captured["port"] = env["SECSCAN_SSH_PORT"]
        key_path = Path(env["SECSCAN_SSH_KEY"])
        known_hosts_path = Path(env["SECSCAN_SSH_KNOWN_HOSTS"])
        captured["key_path"] = str(key_path)
        captured["known_hosts_path"] = str(known_hosts_path)
        assert key_path.is_file()
        assert known_hosts_path.is_file()
        output_dir = Path(command[command.index("--output-dir") + 1])
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "secscan.json").write_text(
            '{"findings": [], "summary": {"total": 0}}', encoding="utf-8"
        )
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr("secscan.windows_host_web.subprocess.run", fake_run)
    root = tmp_path / "jobs"
    database = root / "jobs.db"
    app = create_app(job_root=root, job_database=database, runner=lambda _args: 0)
    mount_windows_host_submission(app, database=database, job_root=root, job_database=database)
    store = SshCredentialStore(database, master_key)
    profile = store.create(
        name="Windows key",
        username="Administrator",
        private_key=_private_key(),
        known_hosts=_known_hosts(),
        is_default=True,
    )
    client = TestClient(app)

    submitted = client.post(
        "/api/v1/windows-host-jobs",
        json={
            "target": "127.0.0.1",
            "windows_host_authorized": True,
            "credential_profile_id": profile.id,
            "ssh_username": "ACME\\secscan-audit",
            "ssh_port": 2222,
            "timeout": 123,
        },
    )
    assert submitted.status_code == 202
    job_id = submitted.json()["id"]

    for _ in range(100):
        job = client.get(f"/api/v1/jobs/{job_id}").json()
        if job["status"] in {"completed", "failed"}:
            break
        sleep(0.01)

    assert job["status"] == "completed"
    assert captured["command"][:4] == ["secscan", "scan", "windows-host", "127.0.0.1"]
    assert captured["user"] == "ACME\\secscan-audit"
    assert captured["port"] == "2222"
    assert not Path(str(captured["key_path"])).exists()
    assert not Path(str(captured["known_hosts_path"])).exists()


def test_free_session_is_denied_windows_authenticated_workflow(tmp_path: Path) -> None:
    root = tmp_path / "jobs"
    database = root / "jobs.db"
    app = create_app(job_root=root, job_database=database, runner=lambda _args: 0)
    mount_public_site(app, database=database)
    mount_auth(app, database=database)
    mount_windows_host_submission(app, database=database, job_root=root, job_database=database)
    client = TestClient(app)

    registered = client.post(
        "/api/v1/auth/register",
        json={"email": "free@example.com", "password": "correct-horse-battery", "plan": "free"},
    )
    assert registered.status_code == 201

    capability = client.get("/api/v1/windows-host-capability")
    submission = client.post(
        "/api/v1/windows-host-jobs",
        json={"target": "192.0.2.20", "windows_host_authorized": True},
    )

    assert capability.status_code == 403
    assert submission.status_code == 403
    assert "Professional plan" in submission.json()["detail"]
