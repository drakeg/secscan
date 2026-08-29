from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tempfile
from typing import Any, Literal, cast
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.routing import APIRoute
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from secscan.scanners.linux_host import validate_ssh_user
from secscan.scanners.network import validate_network_target
from secscan.service import ARTIFACT_MANIFEST_NAME, ARTIFACT_PATHS, JobRecord, JobStore, ScanSubmission, create_app
from secscan.ssh_credentials import SshCredentialStore
from secscan.tenancy import SYSTEM_TENANT_ID, request_tenant_id

_WEB_ROOT = Path(__file__).with_name("web_assets")
_TERMINAL_JOB_STATUSES = {"completed", "failed", "cancelled"}
_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")


class LinuxHostWebSubmission(BaseModel):
    target: str = Field(min_length=1)
    fail_on: Literal["NONE", "UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"] | None = None
    policy: str | None = None
    baseline: str | None = None
    timeout: int = Field(default=600, ge=1, le=86400)
    linux_host_authorized: bool = False
    credential_profile_id: str | None = None
    remember_credential: bool = False
    ssh_port: int = Field(default=22, ge=1, le=65535)


class SshCredentialCreate(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    username: str = Field(min_length=1, max_length=32)
    private_key: str = Field(min_length=1, max_length=1024 * 1024)
    known_hosts: str = Field(min_length=1, max_length=1024 * 1024)
    is_default: bool = False


def _linux_host_service_ready() -> bool:
    user = os.environ.get("SECSCAN_SSH_USER", "")
    key = os.environ.get("SECSCAN_SSH_KEY", "")
    known_hosts = os.environ.get("SECSCAN_SSH_KNOWN_HOSTS", "")
    port = os.environ.get("SECSCAN_SSH_PORT", "22")
    try:
        validate_ssh_user(user)
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


def _initialize_job_manager(app: FastAPI) -> None:
    for route in app.routes:
        if (
            isinstance(route, APIRoute)
            and route.path == "/api/v1/jobs"
            and route.methods is not None
            and "GET" in route.methods
        ):
            endpoint = cast(Callable[..., list[dict[str, object]]], route.endpoint)
            internal_request = Request({"type": "http", "state": {}})
            endpoint(request=internal_request, status=None, scanner=None, limit=1)
            return
    raise RuntimeError("secscan job listing route is unavailable")


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


def mount_web_ui(
    app: FastAPI,
    *,
    job_root: Path = Path("/reports/jobs"),
    job_database: Path | None = None,
) -> FastAPI:
    """Mount the browser UI and web-only helpers onto a secscan FastAPI app."""
    resolved_root = job_root.expanduser().resolve()
    database = (job_database or resolved_root / "jobs.db").expanduser().resolve()
    submit_job = _job_submitter(app)
    _initialize_job_manager(app)
    store = JobStore(database)
    profile_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="secscan-ssh-profile")
    master_key = os.environ.get("SECSCAN_CREDENTIAL_KEY")
    credential_store = SshCredentialStore(database, master_key) if master_key else None

    def require_credential_store() -> SshCredentialStore:
        if credential_store is None:
            raise HTTPException(
                status_code=503,
                detail="encrypted SSH credential storage is disabled; configure SECSCAN_CREDENTIAL_KEY",
            )
        return credential_store

    def job_storage(job_id: str, tenant_id: str | None) -> tuple[str, Path]:
        if not database.is_file():
            raise HTTPException(status_code=404, detail="job not found")
        with sqlite3.connect(database) as connection:
            if tenant_id is None:
                row = connection.execute(
                    "SELECT status, output_dir FROM service_jobs WHERE id = ?",
                    (job_id,),
                ).fetchone()
            else:
                row = connection.execute(
                    "SELECT status, output_dir FROM service_jobs WHERE id = ? AND tenant_id = ?",
                    (job_id, tenant_id),
                ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="job not found")
        status, output_dir = str(row[0]), str(row[1])
        job_dir = (resolved_root / job_id).resolve()
        recorded_dir = Path(output_dir).resolve()
        if job_dir != recorded_dir or not job_dir.is_relative_to(resolved_root):
            raise HTTPException(status_code=409, detail="job output directory is not safe")
        return status, job_dir

    def run_profile_job(job_id: str, request: LinuxHostWebSubmission, profile_id: str) -> None:
        record = store.get(job_id)
        if record is None or record.status != "queued":
            return
        record.status = "running"
        from datetime import UTC, datetime

        record.started_at = datetime.now(UTC).isoformat()
        store.save(record)
        try:
            credentials = require_credential_store().decrypt(profile_id)
            with tempfile.TemporaryDirectory(prefix="secscan-ssh-") as temporary_directory:
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
                        "SECSCAN_SSH_USER": credentials.profile.username,
                        "SECSCAN_SSH_KEY": str(private_key),
                        "SECSCAN_SSH_KNOWN_HOSTS": str(known_hosts),
                        "SECSCAN_SSH_PORT": str(request.ssh_port),
                    }
                )
                command = [
                    "secscan",
                    "scan",
                    "linux-host",
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
            record.error = "Linux host assessment timed out"
        except Exception as exc:  # defensive worker boundary
            record.status = "failed"
            record.error = str(exc)
        finally:
            from datetime import UTC, datetime

            record.completed_at = datetime.now(UTC).isoformat()
            try:
                _write_manifest(store, resolved_root, record)
            except Exception as exc:  # defensive artifact boundary
                record.status = "failed"
                manifest_error = f"failed to write artifact manifest: {exc}"
                record.error = f"{record.error}; {manifest_error}" if record.error else manifest_error
                store.save(record)

    def submit_profile_job(
        request: LinuxHostWebSubmission, profile_id: str, tenant_id: str
    ) -> dict[str, object]:
        job_id = str(uuid4())
        output_dir = (resolved_root / job_id).resolve()
        if not output_dir.is_relative_to(resolved_root):
            raise HTTPException(status_code=500, detail="job output directory escaped the configured job root")
        from datetime import UTC, datetime

        record = JobRecord(
            id=job_id,
            status="queued",
            scanner="linux-host",
            target=request.target,
            output_dir=str(output_dir),
            created_at=datetime.now(UTC).isoformat(),
            tenant_id=tenant_id,
        )
        store.save(record)
        profile_executor.submit(run_profile_job, job_id, request, profile_id)
        document = asdict(record)
        document.pop("tenant_id", None)
        return document

    @app.get("/api/v1/ssh-credentials/capability")
    def ssh_credential_capability() -> dict[str, bool]:
        return {"configured": credential_store is not None}

    @app.get("/api/v1/ssh-credentials")
    def list_ssh_credentials() -> list[dict[str, object]]:
        return [profile.as_public_dict() for profile in require_credential_store().list()]

    @app.post("/api/v1/ssh-credentials", status_code=201)
    def create_ssh_credential(request: SshCredentialCreate) -> dict[str, object]:
        try:
            profile = require_credential_store().create(
                name=request.name,
                username=request.username,
                private_key=request.private_key,
                known_hosts=request.known_hosts,
                is_default=request.is_default,
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return profile.as_public_dict()

    @app.put("/api/v1/ssh-credentials/{profile_id}/default")
    def set_default_ssh_credential(profile_id: str) -> dict[str, object]:
        try:
            return require_credential_store().set_default(profile_id).as_public_dict()
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.delete("/api/v1/ssh-credentials/{profile_id}", status_code=204)
    def delete_ssh_credential(profile_id: str) -> Response:
        if not require_credential_store().delete(profile_id):
            raise HTTPException(status_code=404, detail="SSH credential profile was not found")
        return Response(status_code=204)

    @app.get("/api/v1/ssh-credentials/resolve")
    def resolve_ssh_credential(host: str = Query(min_length=1)) -> dict[str, object]:
        try:
            target = validate_network_target(host)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        profile_id = require_credential_store().resolve_profile_id(target)
        profile = require_credential_store().get(profile_id) if profile_id else None
        return {"profile": profile.as_public_dict() if profile else None}

    @app.get("/api/v1/linux-host-capability")
    def linux_host_capability() -> dict[str, bool]:
        has_profiles = bool(credential_store and credential_store.list())
        return {"configured": _linux_host_service_ready() or has_profiles}

    @app.post("/api/v1/linux-host-jobs", status_code=202)
    def submit_linux_host_job(
        http_request: Request, request: LinuxHostWebSubmission
    ) -> dict[str, object]:
        if not request.linux_host_authorized:
            raise HTTPException(
                status_code=422,
                detail="Linux host scans require explicit authorization acknowledgement",
            )
        try:
            target = validate_network_target(request.target)
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
                tenant_id = request_tenant_id(http_request) or SYSTEM_TENANT_ID
                return submit_profile_job(request, profile_id, tenant_id)

        if not _linux_host_service_ready():
            raise HTTPException(
                status_code=422,
                detail=(
                    "Linux host scanning is not configured. Create an encrypted SSH credential "
                    "profile or configure the server-side SECSCAN_SSH_* fallback settings."
                ),
            )
        submission = ScanSubmission.model_construct(
            scanner="linux-host",
            target=target,
            fail_on=request.fail_on,
            policy=request.policy,
            baseline=request.baseline,
            timeout=request.timeout,
            network_authorized=False,
        )
        return submit_job(http_request, submission)

    @app.get("/api/v1/jobs/{job_id}/summary")
    def job_summary(job_id: str, request: Request) -> dict[str, object]:
        status, job_dir = job_storage(job_id, request_tenant_id(request))
        report_path = job_dir / "secscan.json"
        if not report_path.is_file():
            raise HTTPException(status_code=404, detail="scan report not found")
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise HTTPException(status_code=422, detail="scan report is not valid JSON") from exc
        findings = report.get("findings", []) if isinstance(report, dict) else []
        counts = {severity: 0 for severity in _SEVERITIES}
        if isinstance(findings, list):
            for finding in findings:
                if not isinstance(finding, dict):
                    continue
                severity = str(finding.get("severity", "UNKNOWN")).upper()
                counts[severity if severity in counts else "UNKNOWN"] += 1
        return {
            "job_id": job_id,
            "status": status,
            "total": sum(counts.values()),
            "severity": counts,
        }

    @app.delete("/api/v1/jobs/{job_id}/history", status_code=204)
    def delete_job_history(job_id: str, request: Request) -> Response:
        tenant_id = request_tenant_id(request)
        status, job_dir = job_storage(job_id, tenant_id)
        if status not in _TERMINAL_JOB_STATUSES:
            raise HTTPException(status_code=409, detail="active jobs cannot be deleted")
        if job_dir.exists():
            shutil.rmtree(job_dir)
        with sqlite3.connect(database) as connection:
            if tenant_id is None:
                connection.execute("DELETE FROM service_jobs WHERE id = ?", (job_id,))
            else:
                connection.execute(
                    "DELETE FROM service_jobs WHERE id = ? AND tenant_id = ?",
                    (job_id, tenant_id),
                )
        return Response(status_code=204)

    app.mount("/", StaticFiles(directory=_WEB_ROOT, html=True), name="web")
    return app


def create_web_app(**service_options: Any) -> FastAPI:
    """Create the secscan API and mount the browser UI at the site root."""
    job_root = Path(service_options.get("job_root", Path("/reports/jobs")))
    job_database = service_options.get("job_database")
    return mount_web_ui(
        create_app(**service_options),
        job_root=job_root,
        job_database=job_database,
    )
