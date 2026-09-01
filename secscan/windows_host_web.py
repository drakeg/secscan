from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
from typing import Literal, cast
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request
from fastapi.routing import APIRoute
from pydantic import BaseModel, Field

from secscan.auth import AuthStore, SESSION_COOKIE
from secscan.public_site import PlanStore
from secscan.scanners.network import validate_network_target
from secscan.scanners.windows_host import validate_windows_ssh_user
from secscan.service import (
    ARTIFACT_MANIFEST_NAME,
    ARTIFACT_PATHS,
    JobRecord,
    JobStore,
    ScanSubmission,
)
from secscan.ssh_credentials import SshCredentialStore
from secscan.tenancy import SYSTEM_TENANT_ID, request_tenant_id


class WindowsHostWebSubmission(BaseModel):
    target: str = Field(min_length=1)
    fail_on: Literal["NONE", "UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"] | None = None
    policy: str | None = None
    baseline: str | None = None
    timeout: int = Field(default=600, ge=1, le=86400)
    windows_host_authorized: bool = False
    credential_profile_id: str | None = None
    remember_credential: bool = False
    ssh_port: int = Field(default=22, ge=1, le=65535)
    ssh_username: str | None = Field(default=None, min_length=1, max_length=128)


def _job_submitter(app: FastAPI) -> Callable[[Request, ScanSubmission], dict[str, object]]:
    for route in app.routes:
        if (
            isinstance(route, APIRoute)
            and route.path == "/api/v1/jobs"
            and route.methods is not None
            and "POST" in route.methods
        ):
            return cast(Callable[[Request, ScanSubmission], dict[str, object]], route.endpoint)
    raise RuntimeError("secscan job submission route is unavailable")


def _windows_host_service_ready() -> bool:
    user = os.environ.get("SECSCAN_SSH_USER", "")
    key = os.environ.get("SECSCAN_SSH_KEY", "")
    known_hosts = os.environ.get("SECSCAN_SSH_KNOWN_HOSTS", "")
    port = os.environ.get("SECSCAN_SSH_PORT", "22")
    try:
        validate_windows_ssh_user(user)
        parsed_port = int(port)
    except (ValueError, TypeError):
        return False
    if not 1 <= parsed_port <= 65535:
        return False
    for value in (key, known_hosts):
        path = Path(value).expanduser()
        if not path.is_absolute() or not path.is_file():
            return False
    return True


def _hash_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size_bytes = 0
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
            size_bytes += len(chunk)
    return digest.hexdigest(), size_bytes


def _write_manifest(store: JobStore, root: Path, record: JobRecord) -> None:
    job_dir = (root / record.id).resolve()
    if job_dir != Path(record.output_dir).resolve() or not job_dir.is_relative_to(root):
        raise ValueError("job output directory escaped the configured job root")
    job_dir.mkdir(parents=True, exist_ok=True)
    artifacts: list[dict[str, object]] = []
    for name in sorted(ARTIFACT_PATHS):
        if name == ARTIFACT_MANIFEST_NAME:
            continue
        artifact = job_dir / ARTIFACT_PATHS[name]
        if not artifact.is_file():
            continue
        digest, size_bytes = _hash_file(artifact)
        artifacts.append({"name": name, "size_bytes": size_bytes, "sha256": digest})
    manifest = {"schema_version": 1, "job_id": record.id, "artifacts": artifacts}
    temporary = job_dir / ".artifacts.json.tmp"
    temporary.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(job_dir / ARTIFACT_PATHS[ARTIFACT_MANIFEST_NAME])
    store.save(record)


def mount_windows_host_submission(
    app: FastAPI,
    *,
    database: Path,
    job_root: Path = Path("/reports/jobs"),
    job_database: Path | None = None,
) -> FastAPI:
    resolved_root = job_root.expanduser().resolve()
    resolved_database = (job_database or resolved_root / "jobs.db").expanduser().resolve()
    submit_job = _job_submitter(app)
    store = JobStore(resolved_database)
    executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="secscan-windows-profile")
    master_key = os.environ.get("SECSCAN_CREDENTIAL_KEY")
    credential_store = SshCredentialStore(resolved_database, master_key) if master_key else None
    auth = AuthStore(database)
    plans = PlanStore(database)

    def require_professional(request: Request) -> None:
        user = auth.user_for_session(request.cookies.get(SESSION_COOKIE))
        if user is not None and plans.get(user.id) != "professional":
            raise HTTPException(
                status_code=403,
                detail="Professional plan is required for authenticated host workflows",
            )

    def run_profile_job(
        job_id: str,
        request: WindowsHostWebSubmission,
        profile_id: str,
    ) -> None:
        record = store.get(job_id)
        if record is None or record.status != "queued":
            return
        record.status = "running"
        record.started_at = datetime.now(UTC).isoformat()
        store.save(record)
        try:
            if credential_store is None:
                raise ValueError("encrypted SSH credential storage is disabled")
            credentials = credential_store.decrypt(profile_id)
            username = validate_windows_ssh_user(
                request.ssh_username or credentials.profile.username
            )
            with tempfile.TemporaryDirectory(prefix="secscan-windows-ssh-") as temporary_directory:
                ssh_dir = Path(temporary_directory)
                private_key = ssh_dir / "id_key"
                known_hosts = ssh_dir / "known_hosts"
                private_key.write_text(credentials.private_key, encoding="utf-8")
                private_key.chmod(0o600)
                known_hosts.write_text(credentials.known_hosts, encoding="utf-8")
                known_hosts.chmod(0o600)
                environment = os.environ.copy()
                environment.update(
                    {
                        "SECSCAN_SSH_USER": username,
                        "SECSCAN_SSH_KEY": str(private_key),
                        "SECSCAN_SSH_KNOWN_HOSTS": str(known_hosts),
                        "SECSCAN_SSH_PORT": str(request.ssh_port),
                    }
                )
                command = [
                    "secscan",
                    "scan",
                    "windows-host",
                    request.target,
                    "--output-dir",
                    record.output_dir,
                    "--timeout",
                    str(request.timeout),
                ]
                if request.fail_on:
                    command.extend(["--fail-on", request.fail_on])
                if request.policy:
                    command.extend(["--policy", request.policy])
                if request.baseline:
                    command.extend(["--baseline", request.baseline])
                completed = subprocess.run(
                    command,
                    check=False,
                    capture_output=True,
                    text=True,
                    env=environment,
                    timeout=request.timeout + 30,
                )
            record.exit_code = completed.returncode
            record.status = "completed" if completed.returncode in (0, 2) else "failed"
            if record.status == "failed":
                detail = (completed.stderr or completed.stdout).strip().splitlines()
                record.error = detail[-1] if detail else f"scan exited with code {completed.returncode}"
        except subprocess.TimeoutExpired:
            record.status = "failed"
            record.error = "Windows host assessment timed out"
        except Exception as exc:  # defensive worker boundary
            record.status = "failed"
            record.error = str(exc)
        finally:
            record.completed_at = datetime.now(UTC).isoformat()
            try:
                _write_manifest(store, resolved_root, record)
            except Exception as exc:  # defensive artifact boundary
                record.status = "failed"
                manifest_error = f"failed to write artifact manifest: {exc}"
                record.error = f"{record.error}; {manifest_error}" if record.error else manifest_error
                store.save(record)

    def submit_profile_job(
        request: WindowsHostWebSubmission,
        profile_id: str,
        tenant_id: str,
    ) -> dict[str, object]:
        job_id = str(uuid4())
        output_dir = (resolved_root / job_id).resolve()
        if not output_dir.is_relative_to(resolved_root):
            raise HTTPException(
                status_code=500,
                detail="job output directory escaped the configured job root",
            )
        record = JobRecord(
            id=job_id,
            status="queued",
            scanner="windows-host",
            target=request.target,
            output_dir=str(output_dir),
            created_at=datetime.now(UTC).isoformat(),
            tenant_id=tenant_id,
        )
        store.save(record)
        executor.submit(run_profile_job, job_id, request, profile_id)
        document = asdict(record)
        document.pop("tenant_id", None)
        return document

    @app.get("/api/v1/windows-host-capability")
    def windows_host_capability(request: Request) -> dict[str, bool]:
        require_professional(request)
        has_profiles = bool(credential_store and credential_store.list())
        return {"configured": _windows_host_service_ready() or has_profiles}

    @app.post("/api/v1/windows-host-jobs", status_code=202)
    def submit_windows_host_job(
        http_request: Request,
        request: WindowsHostWebSubmission,
    ) -> dict[str, object]:
        require_professional(http_request)
        if not request.windows_host_authorized:
            raise HTTPException(
                status_code=422,
                detail="Windows host scans require explicit authorization acknowledgement",
            )
        try:
            target = validate_network_target(request.target)
            username_override = (
                validate_windows_ssh_user(request.ssh_username)
                if request.ssh_username is not None
                else None
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

        profile_id = request.credential_profile_id
        if credential_store is not None:
            if profile_id is None:
                profile_id = credential_store.resolve_profile_id(target)
            elif credential_store.get(profile_id) is None:
                raise HTTPException(status_code=422, detail="SSH credential profile was not found")
            if profile_id is not None:
                if request.remember_credential:
                    credential_store.bind_host(target, profile_id)
                normalized = request.model_copy(
                    update={"target": target, "ssh_username": username_override}
                )
                tenant_id = request_tenant_id(http_request) or SYSTEM_TENANT_ID
                return submit_profile_job(normalized, profile_id, tenant_id)

        if request.ssh_username is not None:
            raise HTTPException(
                status_code=422,
                detail=(
                    "Windows SSH username override requires an encrypted SSH credential profile; "
                    "the server-side fallback uses SECSCAN_SSH_USER"
                ),
            )
        if not _windows_host_service_ready():
            raise HTTPException(
                status_code=422,
                detail=(
                    "Windows host scanning is not configured. Create an encrypted SSH credential "
                    "profile or configure the server-side SECSCAN_SSH_* fallback settings."
                ),
            )
        submission = ScanSubmission.model_construct(
            scanner="windows-host",
            target=target,
            fail_on=request.fail_on,
            policy=request.policy,
            baseline=request.baseline,
            timeout=request.timeout,
            network_authorized=False,
            web_authorized=False,
        )
        return submit_job(http_request, submission)

    return app
