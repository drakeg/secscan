# Service Mode and REST API

Sprint 9 adds a local long-running API without changing the standalone CLI.

## Start the service

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
- `GET /api/v1/jobs/{job_id}`
- `GET /api/v1/jobs/{job_id}/artifacts/{name}`

Submit a scan:

```bash
curl -X POST http://localhost:8000/api/v1/jobs \
  -H 'content-type: application/json' \
  -d '{"scanner":"image","target":"alpine:3.20","fail_on":"HIGH"}'
```

Exit code `2` is a successfully completed job whose policy failed. Exit code `1` or an unexpected exception produces a failed job.

## Security boundaries

This first increment is intended for trusted local networks and single-operator deployments. It does not provide authentication, authorization, uploads, remote target retrieval, tenant isolation, TLS termination, or distributed workers. Do not expose it directly to an untrusted network.

Artifact names are allow-listed and each job receives a UUID-scoped output directory. Worker concurrency is bounded by `--workers`.

## Persistence

Generated reports remain on disk under the configured job root. Job status metadata is currently held in memory and is lost when the service restarts. Persistent job state and PostgreSQL remain later increments.

## Cost

Service mode uses the existing local scanner, filesystem, and SQLite capabilities. Current and projected recurring infrastructure cost remains **$0**.
