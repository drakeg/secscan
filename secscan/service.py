from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path, PurePath
import secrets
import sqlite3
from threading import Lock
from typing import Any, Awaitable, Callable, Literal, Sequence
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.openapi.utils import get_openapi
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

from secscan.scanners.network import expand_network_range, validate_network_target
from secscan.scanners.repository import is_remote_repository_url, validate_remote_repository_url
from secscan.scanners.web_dast import validate_web_target
from secscan.tenancy import SYSTEM_TENANT_ID, request_tenant_id

JobStatus = Literal["queued", "running", "completed", "failed", "cancelled"]
ScannerName = Literal[
    "image",
    "filesystem",
    "repository",
    "sbom",
    "network",
    "network-range",
    "web-dast",
]
ScanRunner = Callable[[list[str]], int]
ARTIFACT_MANIFEST_NAME = "artifacts.json"
MIN_API_TOKEN_LENGTH = 32
MAX_API_TOKEN_LENGTH = 4096
ARTIFACT_PATHS = {
    ARTIFACT_MANIFEST_NAME: Path(ARTIFACT_MANIFEST_NAME),
    "trivy.json": Path("trivy.json"),
    "secscan.json": Path("secscan.json"),
    "secscan.html": Path("secscan.html"),
    "secscan.cdx.json": Path("secscan.cdx.json"),
    "secscan.spdx.json": Path("secscan.spdx.json"),
    "secscan.diff.json": Path("secscan.diff.json"),
}


class ScanSubmission(BaseModel):
    scanner: ScannerName
    target: str = Field(min_length=1)
    fail_on: Literal["NONE", "UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"] | None = None
    policy: str | None = None
    baseline: str | None = None
    timeout: int = Field(default=600, ge=1, le=86400)
    network_authorized: bool = False
    web_authorized: bool = False


@dataclass
class JobRecord:
    id: str
    status: JobStatus
    scanner: str
    target: str
    output_dir: str
    created_at: str
    started_at: str | None = None
    completed_at: str | None = None
    exit_code: int | None = None
    error: str | None = None
    tenant_id: str = SYSTEM_TENANT_ID


def _job_document(record: JobRecord) -> dict[str, object]:
    document = asdict(record)
    document.pop("tenant_id", None)
    return document


class JobStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.migrate()

    def _connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    def migrate(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                f"""
                CREATE TABLE IF NOT EXISTS service_jobs (
                    id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    scanner TEXT NOT NULL,
                    target TEXT NOT NULL,
                    output_dir TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    started_at TEXT,
                    completed_at TEXT,
                    exit_code INTEGER,
                    error TEXT,
                    tenant_id TEXT NOT NULL DEFAULT '{SYSTEM_TENANT_ID}'
                );
                CREATE INDEX IF NOT EXISTS service_jobs_created_at_idx
                    ON service_jobs(created_at DESC);
                CREATE INDEX IF NOT EXISTS service_jobs_status_created_at_idx
                    ON service_jobs(status, created_at DESC);
                """
            )
            columns = {
                str(row[1]) for row in connection.execute("PRAGMA table_info(service_jobs)").fetchall()
            }
            added_tenant_column = "tenant_id" not in columns
            if added_tenant_column:
                connection.execute(
                    f"ALTER TABLE service_jobs ADD COLUMN tenant_id TEXT NOT NULL DEFAULT '{SYSTEM_TENANT_ID}'"
                )
                auth_table = connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'auth_users'"
                ).fetchone()
                if auth_table is not None:
                    admin = connection.execute(
                        "SELECT id FROM auth_users WHERE role = 'admin' ORDER BY created_at ASC, id ASC LIMIT 1"
                    ).fetchone()
                    if admin is not None:
                        connection.execute(
                            "UPDATE service_jobs SET tenant_id = ? WHERE tenant_id = ?",
                            (str(admin["id"]), SYSTEM_TENANT_ID),
                        )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS service_jobs_tenant_created_at_idx ON service_jobs(tenant_id, created_at DESC)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS service_jobs_tenant_status_created_at_idx ON service_jobs(tenant_id, status, created_at DESC)"
            )

    def save(self, record: JobRecord) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO service_jobs (
                    id, status, scanner, target, output_dir, created_at,
                    started_at, completed_at, exit_code, error, tenant_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    status = excluded.status,
                    started_at = excluded.started_at,
                    completed_at = excluded.completed_at,
                    exit_code = excluded.exit_code,
                    error = excluded.error
                """,
                (
                    record.id,
                    record.status,
                    record.scanner,
                    record.target,
                    record.output_dir,
                    record.created_at,
                    record.started_at,
                    record.completed_at,
                    record.exit_code,
                    record.error,
                    record.tenant_id,
                ),
            )

    def get(self, job_id: str, *, tenant_id: str | None = None) -> JobRecord | None:
        with self._connect() as connection:
            if tenant_id is None:
                row = connection.execute("SELECT * FROM service_jobs WHERE id = ?", (job_id,)).fetchone()
            else:
                row = connection.execute(
                    "SELECT * FROM service_jobs WHERE id = ? AND tenant_id = ?",
                    (job_id, tenant_id),
                ).fetchone()
        return JobRecord(**dict(row)) if row else None

    def list(
        self,
        *,
        status: JobStatus | None = None,
        scanner: str | None = None,
        limit: int = 20,
        tenant_id: str | None = None,
    ) -> list[JobRecord]:
        predicates: list[str] = []
        parameters: list[object] = []
        if tenant_id is not None:
            predicates.append("tenant_id = ?")
            parameters.append(tenant_id)
        if status is not None:
            predicates.append("status = ?")
            parameters.append(status)
        if scanner is not None:
            predicates.append("scanner = ?")
            parameters.append(scanner)
        where = f" WHERE {' AND '.join(predicates)}" if predicates else ""
        parameters.append(limit)
        with self._connect() as connection:
            rows = connection.execute(
                f"SELECT * FROM service_jobs{where} ORDER BY created_at DESC LIMIT ?",
                tuple(parameters),
            ).fetchall()
        return [JobRecord(**dict(row)) for row in rows]

    def fail_interrupted(self) -> None:
        completed_at = _timestamp()
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE service_jobs
                SET status = 'failed', completed_at = ?,
                    error = 'service restarted before the job completed'
                WHERE status IN ('queued', 'running')
                """,
                (completed_at,),
            )


class JobManager:
    def __init__(
        self,
        root: Path,
        runner: ScanRunner,
        max_workers: int = 2,
        database: Path | None = None,
        allowed_input_roots: Sequence[Path] = (),
    ) -> None:
        if max_workers < 1:
            raise ValueError("max_workers must be at least 1")
        self.root = root.expanduser().resolve()
        self.allowed_input_roots = tuple(path.expanduser().resolve() for path in allowed_input_roots)
        database_path = database or self.root / "jobs.db"
        self.store = JobStore(database_path.expanduser().resolve())
        self.store.fail_interrupted()
        self.runner = runner
        self.executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="secscan")
        self._lock = Lock()

    def submit(self, request: ScanSubmission, *, tenant_id: str = SYSTEM_TENANT_ID) -> JobRecord:
        self._validate_submission(request)
        self._validate_input_paths(request)
        job_id = str(uuid4())
        output_dir = (self.root / job_id).resolve()
        if not output_dir.is_relative_to(self.root):
            raise ValueError("job output directory escaped the configured job root")
        record = JobRecord(
            id=job_id,
            status="queued",
            scanner=request.scanner,
            target=request.target,
            output_dir=str(output_dir),
            created_at=_timestamp(),
            tenant_id=tenant_id,
        )
        with self._lock:
            self.store.save(record)
        self.executor.submit(self._run, job_id, request)
        return record

    def _validate_submission(self, request: ScanSubmission) -> None:
        if request.scanner == "network":
            if not request.network_authorized:
                raise ValueError("network scans require explicit authorization acknowledgement")
            validate_network_target(request.target)
            return
        if request.scanner == "network-range":
            if not request.network_authorized:
                raise ValueError("network range scans require explicit authorization acknowledgement")
            expand_network_range(request.target)
            return
        if request.scanner == "web-dast":
            if not request.web_authorized:
                raise ValueError("web DAST scans require explicit authorization acknowledgement")
            validate_web_target(request.target)

    def _validate_input_paths(self, request: ScanSubmission) -> None:
        remote_repository = request.scanner == "repository" and is_remote_repository_url(request.target)
        if remote_repository:
            validate_remote_repository_url(request.target)
        if not self.allowed_input_roots:
            return
        inputs: list[tuple[str, str]] = []
        if request.scanner in ("filesystem", "sbom") or (
            request.scanner == "repository" and not remote_repository
        ):
            inputs.append(("target", request.target))
        if request.policy is not None:
            inputs.append(("policy", request.policy))
        if request.baseline is not None:
            inputs.append(("baseline", request.baseline))
        for field, value in inputs:
            if not self._is_allowed_input_path(value):
                raise ValueError(f"{field} is outside the configured input roots")

    def _is_allowed_input_path(self, value: str) -> bool:
        lexical_path = PurePath(value)
        if not lexical_path.is_absolute():
            return False
        for root in self.allowed_input_roots:
            try:
                relative = lexical_path.relative_to(PurePath(root))
            except ValueError:
                continue
            safe_parts = tuple(os.path.basename(part) for part in relative.parts)
            if safe_parts != relative.parts or any(part in ("", ".", "..") for part in safe_parts):
                continue
            resolved = root.joinpath(*safe_parts).resolve()
            if resolved.is_relative_to(root):
                return True
        return False

    def get(self, job_id: str, *, tenant_id: str | None = None) -> JobRecord | None:
        with self._lock:
            return self.store.get(job_id, tenant_id=tenant_id)

    def list(
        self,
        *,
        status: JobStatus | None = None,
        scanner: str | None = None,
        limit: int = 20,
        tenant_id: str | None = None,
    ) -> list[JobRecord]:
        with self._lock:
            return self.store.list(
                status=status,
                scanner=scanner,
                limit=limit,
                tenant_id=tenant_id,
            )

    def cancel(self, job_id: str, *, tenant_id: str | None = None) -> JobRecord | None:
        with self._lock:
            record = self.store.get(job_id, tenant_id=tenant_id)
            if record is None:
                return None
            if record.status != "queued":
                raise ValueError("only queued jobs can be cancelled")
            record.status = "cancelled"
            record.completed_at = _timestamp()
            self.store.save(record)
            return record

    def artifact_path(self, record: JobRecord, artifact_name: str) -> Path | None:
        relative_path = ARTIFACT_PATHS.get(artifact_name)
        if relative_path is None:
            return None
        job_dir = (self.root / record.id).resolve()
        recorded_dir = Path(record.output_dir).resolve()
        if job_dir != recorded_dir or not job_dir.is_relative_to(self.root):
            return None
        artifact = (job_dir / relative_path).resolve()
        if artifact.parent != job_dir or not artifact.is_relative_to(self.root):
            return None
        return artifact

    def _write_artifact_manifest(self, record: JobRecord) -> None:
        job_dir = (self.root / record.id).resolve()
        recorded_dir = Path(record.output_dir).resolve()
        if job_dir != recorded_dir or not job_dir.is_relative_to(self.root):
            raise ValueError("job output directory escaped the configured job root")
        job_dir.mkdir(exist_ok=True)
        artifacts: list[dict[str, object]] = []
        for name in sorted(ARTIFACT_PATHS):
            if name == ARTIFACT_MANIFEST_NAME:
                continue
            artifact = self.artifact_path(record, name)
            if artifact is None or not artifact.is_file():
                continue
            digest, size_bytes = _hash_file(artifact)
            artifacts.append(
                {
                    "name": name,
                    "size_bytes": size_bytes,
                    "sha256": digest,
                }
            )
        manifest = {
            "schema_version": 1,
            "job_id": record.id,
            "artifacts": artifacts,
        }
        temporary = job_dir / ".artifacts.json.tmp"
        temporary.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary.replace(job_dir / ARTIFACT_PATHS[ARTIFACT_MANIFEST_NAME])

    def artifact_etag(self, record: JobRecord, artifact_name: str) -> str | None:
        artifact = self.artifact_path(record, artifact_name)
        if artifact is None or not artifact.is_file():
            return None
        if artifact_name == ARTIFACT_MANIFEST_NAME:
            digest, _size_bytes = _hash_file(artifact)
            return _strong_etag(digest)
        manifest_path = self.artifact_path(record, ARTIFACT_MANIFEST_NAME)
        if manifest_path is None or not manifest_path.is_file():
            return None
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            if manifest.get("schema_version") != 1 or manifest.get("job_id") != record.id:
                return None
            for item in manifest.get("artifacts", []):
                if not isinstance(item, dict) or item.get("name") != artifact_name:
                    continue
                manifest_digest = item.get("sha256")
                size_bytes = item.get("size_bytes")
                if (
                    isinstance(manifest_digest, str)
                    and len(manifest_digest) == 64
                    and all(character in "0123456789abcdef" for character in manifest_digest)
                    and isinstance(size_bytes, int)
                    and size_bytes == artifact.stat().st_size
                ):
                    return _strong_etag(manifest_digest)
        except (OSError, UnicodeError, json.JSONDecodeError, AttributeError):
            return None
        return None

    def _run(self, job_id: str, request: ScanSubmission) -> None:
        with self._lock:
            record = self.store.get(job_id)
            if record is None or record.status != "queued":
                return
            record.status = "running"
            record.started_at = _timestamp()
            self.store.save(record)
        args = [
            "scan",
            request.scanner,
            request.target,
            "--output-dir",
            record.output_dir,
            "--timeout",
            str(request.timeout),
        ]
        if request.fail_on:
            args.extend(["--fail-on", request.fail_on])
        if request.policy:
            args.extend(["--policy", request.policy])
        if request.baseline:
            args.extend(["--baseline", request.baseline])
        try:
            record.exit_code = self.runner(args)
            record.status = "completed" if record.exit_code in (0, 2) else "failed"
            if record.status == "failed":
                record.error = f"scan exited with code {record.exit_code}"
        except Exception as exc:  # defensive worker boundary
            record.status = "failed"
            record.error = str(exc)
        finally:
            try:
                self._write_artifact_manifest(record)
            except Exception as exc:  # defensive artifact boundary
                record.status = "failed"
                manifest_error = f"failed to write artifact manifest: {exc}"
                record.error = f"{record.error}; {manifest_error}" if record.error else manifest_error
            record.completed_at = _timestamp()
            with self._lock:
                self.store.save(record)


def _timestamp() -> str:
    return datetime.now(UTC).isoformat()


def _hash_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size_bytes = 0
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
            size_bytes += len(chunk)
    return digest.hexdigest(), size_bytes


def _strong_etag(digest: str) -> str:
    return f'"sha256-{digest}"'


def _if_none_match_matches(header: str | None, etag: str) -> bool:
    if header is None:
        return False
    for candidate in header.split(","):
        candidate = candidate.strip()
        if candidate == "*":
            return True
        if candidate.startswith("W/"):
            candidate = candidate[2:].strip()
        if candidate == etag:
            return True
    return False


def _validated_api_token(api_token: str | None) -> str | None:
    if api_token is None or api_token == "":
        return None
    if (
        len(api_token) < MIN_API_TOKEN_LENGTH
        or len(api_token) > MAX_API_TOKEN_LENGTH
        or not api_token.isascii()
        or any(character.isspace() for character in api_token)
    ):
        raise ValueError("API token must contain 32-4096 non-whitespace ASCII characters")
    return api_token


def create_app(
    *,
    job_root: Path = Path("/reports/jobs"),
    max_workers: int = 2,
    job_database: Path | None = None,
    runner: ScanRunner | None = None,
    allowed_input_roots: Sequence[Path] = (),
    api_token: str | None = None,
) -> FastAPI:
    if runner is None:
        from secscan.cli import main

        runner = main
    validated_api_token = _validated_api_token(api_token)
    manager: JobManager | None = None
    manager_lock = Lock()

    def get_manager() -> JobManager:
        nonlocal manager
        with manager_lock:
            if manager is None:
                manager = JobManager(
                    job_root,
                    runner,
                    max_workers=max_workers,
                    database=job_database,
                    allowed_input_roots=allowed_input_roots,
                )
            return manager

    app = FastAPI(title="secscan API", version="1.0.0")

    @app.middleware("http")
    async def authenticate(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        protected_path = request.url.path.startswith("/api/v1/")
        if validated_api_token is not None and protected_path:
            authorization = request.headers.get("authorization", "")
            scheme, separator, credential = authorization.partition(" ")
            authenticated = (
                separator == " "
                and scheme.lower() == "bearer"
                and credential.isascii()
                and secrets.compare_digest(credential, validated_api_token)
            )
            if not authenticated:
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Not authenticated"},
                    headers={"WWW-Authenticate": "Bearer"},
                )
        return await call_next(request)

    if validated_api_token is not None:

        def authenticated_openapi() -> dict[str, Any]:
            if app.openapi_schema is not None:
                return app.openapi_schema
            schema = get_openapi(title=app.title, version=app.version, routes=app.routes)
            security_schemes = schema.setdefault("components", {}).setdefault("securitySchemes", {})
            security_schemes["BearerAuth"] = {"type": "http", "scheme": "bearer"}
            for path, operations in schema["paths"].items():
                if path.startswith("/api/v1/"):
                    for operation in operations.values():
                        if isinstance(operation, dict):
                            operation["security"] = [{"BearerAuth": []}]
            app.openapi_schema = schema
            return schema

        app.openapi = authenticated_openapi  # type: ignore[method-assign]

    @app.get("/healthz")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/api/v1/jobs", status_code=202)
    def submit_job(request: Request, submission: ScanSubmission) -> dict[str, object]:
        tenant_id = request_tenant_id(request) or SYSTEM_TENANT_ID
        try:
            record = get_manager().submit(submission, tenant_id=tenant_id)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return _job_document(record)

    @app.get("/api/v1/jobs")
    def list_jobs(
        request: Request,
        status: JobStatus | None = None,
        scanner: ScannerName | None = None,
        limit: int = Query(default=20, ge=1, le=100),
    ) -> list[dict[str, object]]:
        return [
            _job_document(record)
            for record in get_manager().list(
                status=status,
                scanner=scanner,
                limit=limit,
                tenant_id=request_tenant_id(request),
            )
        ]

    @app.get("/api/v1/jobs/{job_id}")
    def get_job(job_id: str, request: Request) -> dict[str, object]:
        record = get_manager().get(job_id, tenant_id=request_tenant_id(request))
        if record is None:
            raise HTTPException(status_code=404, detail="job not found")
        return _job_document(record)

    @app.delete("/api/v1/jobs/{job_id}")
    def cancel_job(job_id: str, request: Request) -> dict[str, object]:
        try:
            record = get_manager().cancel(job_id, tenant_id=request_tenant_id(request))
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        if record is None:
            raise HTTPException(status_code=404, detail="job not found")
        return _job_document(record)

    def artifact_response(job_id: str, name: str, request: Request) -> Response:
        manager = get_manager()
        record = manager.get(job_id, tenant_id=request_tenant_id(request))
        if record is None:
            raise HTTPException(status_code=404, detail="job not found")
        artifact = manager.artifact_path(record, name)
        if artifact is None or not artifact.is_file():
            raise HTTPException(status_code=404, detail="artifact not found")
        etag = manager.artifact_etag(record, name)
        headers = {"Cache-Control": "private, no-cache"}
        if etag is not None:
            headers["ETag"] = etag
            if _if_none_match_matches(request.headers.get("if-none-match"), etag):
                return Response(status_code=304, headers=headers)
        response = FileResponse(artifact, stat_result=artifact.stat(), headers=headers)
        if etag is None:
            del response.headers["etag"]
        return response

    @app.get("/api/v1/jobs/{job_id}/artifacts")
    def list_artifacts(job_id: str, request: Request) -> Response:
        return artifact_response(job_id, ARTIFACT_MANIFEST_NAME, request)

    @app.get("/api/v1/jobs/{job_id}/artifacts/{name}")
    def get_artifact(job_id: str, name: str, request: Request) -> Response:
        return artifact_response(job_id, name, request)

    @app.head("/api/v1/jobs/{job_id}/artifacts/{name}")
    def head_artifact(job_id: str, name: str, request: Request) -> Response:
        return artifact_response(job_id, name, request)

    return app


app = create_app()
