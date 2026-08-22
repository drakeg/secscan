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

Download the job's deterministic integrity manifest and verify the normalized report digest:

```bash
curl --fail http://127.0.0.1:8000/api/v1/jobs/JOB_ID/artifacts/artifacts.json \
  --output ./artifacts.compose.json
python -m json.tool ./artifacts.compose.json
python - ./artifacts.compose.json ./secscan.compose.json <<'PY'
import hashlib
import json
from pathlib import Path
import sys

manifest = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
expected = next(item["sha256"] for item in manifest["artifacts"] if item["name"] == "secscan.json")
actual = hashlib.sha256(Path(sys.argv[2]).read_bytes()).hexdigest()
assert actual == expected, (actual, expected)
print("secscan.json digest verified")
PY
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

### Optional trusted-LAN access

Compose remains bound to `127.0.0.1` by default. To test from another system on the same trusted network, copy `.env.example` to `.env`, generate a bearer token, and set `SECSCAN_BIND_ADDRESS` to the secscan host's exact private address. For example:

```dotenv
SECSCAN_BIND_ADDRESS=192.168.1.25
SECSCAN_PORT=8000
SECSCAN_API_TOKEN=REPLACE_WITH_A_GENERATED_TOKEN
```

Generate the token without placing it in shell history, paste it into `.env`, and start the service:

```bash
python -c 'import secrets; print(secrets.token_urlsafe(32))'
docker compose up --build --wait
```

Prefer the host's exact private address. `SECSCAN_BIND_ADDRESS=0.0.0.0` also works but publishes on every host interface and therefore has a broader exposure boundary. Configure the host firewall to allow the configured TCP port (8000 by default) only from the intended private subnet or test system. Do not forward the port on a router, publish it through public DNS, or expose it to the internet. The service provides no TLS, user accounts, or tenant isolation.

From a second trusted system, replace `192.168.1.25` with the configured address:

```bash
curl --fail http://192.168.1.25:8000/healthz
curl --include http://192.168.1.25:8000/api/v1/jobs
curl --fail http://192.168.1.25:8000/api/v1/jobs \
  -H 'Authorization: Bearer REPLACE_WITH_THE_SAME_TOKEN'
```

The first request should succeed, the unauthenticated API request should return `401`, and the authenticated request should return the job list. Open `http://192.168.1.25:8000/` in a browser, select **API token**, and enter the same token; it remains in that browser tab's session storage. When testing is complete, run `docker compose down`, remove the LAN firewall rule, and restore `SECSCAN_BIND_ADDRESS=127.0.0.1`.

### Optional local bearer token

The default remains unauthenticated and localhost-only. To require a bearer token for API and documentation routes, generate a temporary token and pass it to Compose:

```bash
export SECSCAN_API_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
docker compose up --build --wait
```

The health check and API documentation remain public. API routes require the token:

```bash
curl --fail http://127.0.0.1:8000/healthz
curl --fail http://127.0.0.1:8000/openapi.json --output /tmp/secscan-openapi.json
curl --include http://127.0.0.1:8000/api/v1/jobs
curl --fail http://127.0.0.1:8000/api/v1/jobs \
  -H "Authorization: Bearer ${SECSCAN_API_TOKEN}"
```

The unauthenticated request should return `401` with `WWW-Authenticate: Bearer`; the authenticated request should return the job list. Include the same header when submitting jobs, polling status, or downloading artifacts. The interactive `/docs` page advertises bearer authorization so you can enter the token for its API calls. Stop the stack and remove the token from the shell when finished:

```bash
docker compose down
unset SECSCAN_API_TOKEN
```

Tokens must contain 32–4096 non-whitespace ASCII characters. Compose passes the value as a container environment variable rather than a command argument. A user with access to the local Docker daemon can inspect container configuration and should already be considered fully trusted. This control reduces accidental local access; it does not replace TLS or make the service safe for an untrusted network.

Deleting the named volumes permanently removes Compose-managed reports, SQLite job metadata, and the Trivy cache. Use this only when a full reset is intended:

```bash
docker compose down --volumes
```

The Compose service binds to `127.0.0.1` unless `SECSCAN_BIND_ADDRESS` is explicitly changed. It runs as non-root with all Linux capabilities dropped, uses a read-only root filesystem, and mounts the repository read-only. It does not mount the Docker socket. Non-loopback binding is only for deliberate testing on a trusted, firewall-restricted LAN and should use bearer authentication.

Compose also configures `/workspace` as the only allowed local input root. Filesystem, repository, and SBOM targets, plus optional policy and baseline files, must use absolute paths that resolve beneath that mount. Image references are not filesystem paths and remain available. Relative paths, traversal, and symlinks that resolve outside `/workspace` are rejected before a job is recorded.

### Direct startup

```bash
secscan-service --host 0.0.0.0 --port 8000 --workers 2 --job-root ./reports/jobs
```

Direct startup remains unrestricted for backward compatibility. To apply the same boundary, repeat `--allowed-input-root` for each trusted input tree:

```bash
secscan-service --allowed-input-root ./source --allowed-input-root ./policies
```

Direct startup also reads optional bearer authentication from `SECSCAN_API_TOKEN` using the same validation and route boundaries as Compose.

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
- `GET /api/v1/jobs/{job_id}/artifacts`
- `GET /api/v1/jobs/{job_id}/artifacts/{name}`
- `HEAD /api/v1/jobs/{job_id}/artifacts/{name}`

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

This service is intended for trusted local networks and single-operator deployments. Optional bearer authentication is a single shared local secret; it does not provide users, authorization, tenant isolation, TLS termination, token lifecycle management, or distributed workers. Do not expose the service directly to an untrusted network.

Artifact names are allow-listed and each job receives a UUID-scoped output directory. Worker concurrency is bounded by `--workers`.

After scanner execution, the service hashes only existing regular files from its constant artifact allow-list. `artifacts.json` uses schema version 1, stable artifact-name ordering, byte sizes, and lowercase SHA-256 digests. The manifest does not include itself and is written atomically before the terminal job state is persisted. It is integrity evidence for transport or storage verification, not a signature or proof of origin.

The manifest is also discoverable without knowing its filename:

```bash
curl --fail http://127.0.0.1:8000/api/v1/jobs/JOB_ID/artifacts \
  --output ./artifacts.discovered.json
```

Manifested artifact downloads include a strong ETag derived from the recorded SHA-256 digest. Inspect headers without downloading the body, then make a conditional request:

```bash
curl --fail --head \
  http://127.0.0.1:8000/api/v1/jobs/JOB_ID/artifacts/secscan.json

curl --include \
  -H 'If-None-Match: "sha256-DIGEST_FROM_ETAG"' \
  http://127.0.0.1:8000/api/v1/jobs/JOB_ID/artifacts/secscan.json
```

A matching condition returns `304 Not Modified` with no body. With bearer authentication enabled, include the same `Authorization` header used for other API calls. Legacy artifacts without a valid manifest remain downloadable but do not receive an invented ETag.

## Persistence

Generated reports remain on disk under the configured job root. Job metadata is stored in `<job-root>/jobs.db` by default. Use `--job-database` to select another SQLite path; keep it on persistent storage when running in a disposable container.

Completed, failed, and cancelled records remain queryable after restart. Jobs found in `queued` or `running` state during startup are marked failed with a restart explanation. They are not replayed automatically.

## Cost

Service mode uses the existing local scanner, filesystem, and SQLite capabilities. Current and projected recurring infrastructure cost remains **$0**.

## Local validation procedure

Validate configuration and the automated contract:

```bash
docker compose config --quiet
pytest tests/test_compose.py tests/test_service.py tests/test_service_cli.py
```

Then run the Compose quick start, health, filesystem job, report and manifest downloads, digest verification, restart-persistence, and shutdown commands above. Confirm `docker compose ps` reports the service as healthy, the submitted job reaches `completed`, both JSON files parse successfully, the digest matches, and the job remains queryable after container recreation.

For LAN validation, follow the optional trusted-LAN procedure from both the host and one second system. Confirm the resolved Compose configuration publishes the expected private host address, the GUI loads remotely, health remains reachable, the unauthenticated jobs request returns `401`, and the authenticated request succeeds. Restore the loopback binding and firewall after the test.

Call the artifact collection endpoint and compare its JSON with the downloaded `artifacts.json`. Use the `HEAD` and conditional commands above with the returned ETag. Confirm `HEAD` has no body and the matching conditional request returns `304` with no body.

Repeat the optional-token startup and three `curl` checks above. Confirm health remains public, the missing-token request returns `401`, the authenticated request succeeds, and `docker compose down` followed by `unset SECSCAN_API_TOKEN` restores a clean shell and stopped stack.

Verify the input boundary while Compose is running. An allowed submission returns `202`; a path outside `/workspace` returns `422` and creates no job:

```bash
curl --fail -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H 'content-type: application/json' \
  -d '{"scanner":"filesystem","target":"/workspace","fail_on":"NONE"}'

curl --include -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H 'content-type: application/json' \
  -d '{"scanner":"filesystem","target":"/etc"}'
```

The second response should report that `target` is outside the configured input roots. Run `curl --fail http://127.0.0.1:8000/api/v1/jobs` before and after it if you want to confirm the rejected request was not persisted.
