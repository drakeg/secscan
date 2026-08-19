# Web GUI

The `secscan-service` command serves both the REST API and a browser interface.

Start the local service with Docker Compose:

```bash
docker compose up --build --wait
```

Open `http://127.0.0.1:8000/` in a browser. The existing API remains available beneath `/api/v1`, and interactive API documentation remains available at `/docs`.

## Current GUI capabilities

- view queued, running, completed, and failed job counts
- browse recent and historical scan jobs
- submit image, filesystem, repository, and SBOM scans
- configure the policy threshold, timeout, policy path, and baseline path
- inspect job status and normalized severity counts from `secscan.json`
- download generated scan artifacts
- use an existing `SECSCAN_API_TOKEN` without persisting it beyond the current browser tab

Local path scans remain constrained by the service's `--allowed-input-root` configuration. The default Compose configuration exposes the repository read-only at `/workspace`.

## Architecture

The browser UI is intentionally a thin client over the existing service API. Scanner execution, job persistence, path validation, artifact validation, and API authentication remain in `secscan.service`.

`secscan.web.create_web_app()` creates the existing service application and mounts packaged static assets at `/` after the API routes. This keeps the REST API stable and avoids maintaining separate scanner behavior for the CLI and GUI.

This first increment deliberately does not add SaaS tenancy, user accounts, billing, or remote repository credentials. Those concerns should be introduced behind explicit organization/user/integration models rather than embedded into the local job model.
