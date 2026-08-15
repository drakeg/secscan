# Service Mode and REST API

Sprint 9 adds a local long-running API without changing the standalone CLI.

## Start the service

### Docker Compose quick start

From the repository root, build and run the local service in the foreground:

```bash
docker compose up --build
```

Or start it in the background and wait until its health check passes:

```bash
docker compose up --build --wait
```

Then verify the API:

```bash
curl --fail http://127.0.0.1:8000/healthz
curl --fail http://127.0.0.1:8000/api/v1/jobs
```

OpenAPI documentation is at <http://127.0.0.1:8000/docs>. The repository is available read-only inside the service at `/workspace`, so a local filesystem smoke scan can be submitted with:

```bash
curl --fail -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H 'content-type: application/json' \
  -d '{"scanner":"filesystem","target":"/workspace","fail_on":"NONE","timeout":300}'
```

Copy the returned `id`, inspect it until terminal, and download its normalized report:

```bash
curl --fail http://127.0.0.1:8000/api/v1/jobs/JOB_ID
curl --fail http://127.0.0.1:8000/api/v1/jobs/JOB_ID/artifacts/secscan.json \
  --output ./secscan.compose.json
python -m json.tool ./secscan.compose.json
```

The first scan downloads the Trivy vulnerability database and can take longer. Later scans reuse the named cache volume.

Stop containers and the private Compose network while retaining reports, job metadata, and cache:

```bash
docker compose down
```

Start again with `docker compose up --wait` and query the same job ID to verify persistence. To follow logs, use `docker compose logs --follow service`.

The optional `SECSCAN_PORT` and `SECSCAN_WORKERS` environment variables override the host port and bounded worker count:

```bash
SECSCAN_PORT=8080 SECSCAN_WORKERS=1 docker compose up --build --wait
```

Deleting the named volumes permanently removes Compose-managed reports, SQLite job metadata, and the Trivy cache. Use this only when a full reset is intended:

```bash
docker compose down --volumes
```

The Compose service binds only to `127.0.0.1`, runs as non-root with all Linux capabilities dropped, uses a read-only root filesystem, and mounts the repository read-only. It does not mount the Docker socket. Do not change the bind address or expose the unauthenticated API to an untrusted network.

### Direct startup

```bash
secscan-service --host 0.0.0.0 --port 8000 --workers 2 --job-root ./reports/jobs
```

Docker example:

```bash
docker run --rm \
  -p 8000:8000 \
  -v secscan-reports:/reports \
  -v secscan-cache:/cache \
  --entrypoint secscan-service \
  secscan:dev --host 0.0.0.0 --port 8000 --workers 2
```

OpenAPI documentation is available at `/docs` while the service is running.

## Endpoints

- `GET /healthz`
- `POST /api/v1/jobs`
- `GET /api/v1/jobs`
- `GET /api/v1/jobs/{job_id}`
- `DELETE /api/v1/jobs/{job_id}`
- `GET /api/v1/jobs/{job_id}/artifacts/{name}`

Submit a scan:

```bash
curl -X POST http://localhost:8000/api/v1/jobs \
  -H 'content-type: application/json' \
  -d '{"scanner":"image","target":"alpine:3.20","fail_on":"HIGH"}'
```

Exit code `2` is a successfully completed job whose policy failed. Exit code `1` or an unexpected exception produces a failed job.

List the 10 newest completed image jobs:

```bash
curl 'http://localhost:8000/api/v1/jobs?status=completed&scanner=image&limit=10'
```

Results are newest first. `limit` must be between 1 and 100. Only queued jobs can be cancelled:

```bash
curl -X DELETE http://localhost:8000/api/v1/jobs/JOB_ID
```

Cancellation of a running, completed, failed, or already cancelled job returns `409`. Active scanner processes are not terminated.

## Security boundaries

This first increment is intended for trusted local networks and single-operator deployments. It does not provide authentication, authorization, uploads, remote target retrieval, tenant isolation, TLS termination, or distributed workers. Do not expose it directly to an untrusted network.

Artifact names are allow-listed and each job receives a UUID-scoped output directory. Worker concurrency is bounded by `--workers`.

## Persistence

Generated reports remain on disk under the configured job root. Job metadata is stored in `<job-root>/jobs.db` by default. Use `--job-database` to select another SQLite path; keep it on persistent storage when running in a disposable container.

Completed, failed, and cancelled records remain queryable after restart. Jobs found in `queued` or `running` state during startup are marked failed with a restart explanation. They are not replayed automatically.

## Cost

Service mode uses the existing local scanner, filesystem, and SQLite capabilities. Current and projected recurring infrastructure cost remains **$0**.

## Local validation procedure

Validate configuration and the automated contract:

```bash
docker compose config --quiet
pytest tests/test_compose.py tests/test_service.py
```

Then run the Compose quick start, health, filesystem job, artifact download, restart-persistence, and shutdown commands above. Confirm `docker compose ps` reports the service as healthy, the submitted job reaches `completed`, `secscan.compose.json` parses successfully, and the job remains queryable after container recreation.
