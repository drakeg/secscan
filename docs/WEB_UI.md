# Web GUI

The `secscan-service` command serves both the REST API and a browser interface.

## Local testing with Docker Compose

From the repository root, build and start the service:

```bash
docker compose up --build --wait
```

Open `http://127.0.0.1:8000/` in a browser. The REST API remains available beneath `/api/v1`, interactive API documentation remains available at `/docs`, and the repository is mounted read-only inside the container as `/workspace`.

A simple end-to-end GUI test is:

1. Open **New scan**.
2. Select **Filesystem** or **Repository**.
3. Use `/workspace` as the target.
4. Start the scan.
5. Open the completed job and inspect/filter the findings and generated artifacts.

To scan a different local directory through the GUI, set `SECSCAN_WORKSPACE` before starting Compose:

```bash
SECSCAN_WORKSPACE=/absolute/path/to/project docker compose up --build --wait
```

That directory is still mounted read-only at `/workspace`; only `/reports` and `/cache` are writable persistent volumes.

The HTTP port and worker count can also be changed without editing Compose:

```bash
SECSCAN_PORT=8080 SECSCAN_WORKERS=4 docker compose up --build --wait
```

If `SECSCAN_API_TOKEN` is configured, enter the same token using the GUI's **API token** button. The browser stores it only in `sessionStorage` for that tab.

### Compare the GUI with the CLI

Compose also includes an opt-in `cli` profile using the same locally built image, cache, reports volume, and read-only workspace. This is useful when validating that the GUI and CLI produce the same scanner behavior.

```bash
docker compose --profile tools run --rm cli \
  scan filesystem /workspace \
  --output-dir /reports/manual-filesystem \
  --fail-on HIGH
```

For another local source tree:

```bash
SECSCAN_WORKSPACE=/absolute/path/to/project \
  docker compose --profile tools run --rm cli \
  scan repository /workspace \
  --output-dir /reports/manual-repository
```

Stop the local service with:

```bash
docker compose down
```

Use `docker compose down -v` only when you intentionally want to remove the persistent scan reports and vulnerability database cache as well.

## Current GUI capabilities

- view queued, running, completed, and failed job counts
- browse recent and historical scan jobs
- submit image, filesystem, repository, and SBOM scans
- configure the policy threshold, timeout, policy path, and baseline path
- inspect normalized severity counts from `secscan.json`
- search findings by vulnerability ID, package, title, target, or version
- filter findings by severity and whether a fixed version is available
- open advisory URLs directly from finding rows
- visualize baseline comparison totals and browse new, resolved, and unchanged findings
- download generated scan artifacts
- use an existing `SECSCAN_API_TOKEN` without persisting it beyond the current browser tab

Local path scans remain constrained by the service's `--allowed-input-root` configuration. The default Compose configuration exposes only the selected workspace beneath `/workspace`.

## Architecture

The browser UI remains a thin client over the existing service API and normalized artifacts. Scanner execution, job persistence, path validation, artifact validation, and API authentication remain in `secscan.service`.

`secscan.web.create_web_app()` creates the existing service application and mounts packaged static assets at `/` after the API routes. This keeps the REST API stable and avoids maintaining separate scanner behavior for the CLI and GUI.

The local Compose environment deliberately retains restrictive defaults: the service binds to loopback, the workspace is read-only, capabilities are dropped, `no-new-privileges` is enabled, and the container root filesystem is read-only. These constraints should remain the baseline as secscan evolves toward a hosted multi-tenant service.

This increment does not add SaaS tenancy, user accounts, billing, or remote repository credentials. Those concerns should be introduced behind explicit organization/user/integration models rather than embedded into the local job model.
