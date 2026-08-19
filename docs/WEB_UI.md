# Web GUI

The `secscan-service` command serves both the REST API and a browser interface.

## Local testing with Docker Compose

Docker Compose automatically reads a `.env` file from the repository root. Start by copying the provided example:

```bash
cp .env.example .env
```

Then edit `.env` for the local instance you want to run. The available settings are:

```dotenv
SECSCAN_COMPOSE_PROJECT=secscan-local
SECSCAN_PORT=8000
SECSCAN_WORKSPACE=.
SECSCAN_WORKERS=2
SECSCAN_API_TOKEN=
```

`.env` is ignored by Git so local paths, ports, and tokens are not committed. `.env.example` contains safe defaults and is intended to stay in the repository.

From the repository root, build and start the service:

```bash
docker compose up --build --wait
```

Open `http://127.0.0.1:8000/` in a browser, or use the port configured in `SECSCAN_PORT`. The REST API remains available beneath `/api/v1`, interactive API documentation remains available at `/docs`, and the configured workspace is mounted read-only inside the container as `/workspace`.

A simple end-to-end GUI test is:

1. Open **New scan**.
2. Select **Filesystem** or **Repository**.
3. Use `/workspace` as the target.
4. Start the scan.
5. Open the completed job and inspect/filter the findings and generated artifacts.

To scan a different local directory through the GUI, set an absolute path in `.env`:

```dotenv
SECSCAN_WORKSPACE=/absolute/path/to/project
```

That directory is still mounted read-only at `/workspace`; only `/reports` and `/cache` are writable persistent volumes.

The HTTP port and worker count can also be changed in `.env` without editing Compose:

```dotenv
SECSCAN_PORT=8080
SECSCAN_WORKERS=4
```

Environment variables supplied directly on the command line still override `.env` when you need a one-off setting.

### Run multiple local secscan instances at once

Each Compose instance needs both a unique host port and a unique Compose project name. `SECSCAN_PORT` controls the browser/API port, while `SECSCAN_COMPOSE_PROJECT` isolates that instance's containers, network, report volume, and cache volume.

For example, one checkout could use:

```dotenv
SECSCAN_COMPOSE_PROJECT=secscan-project-a
SECSCAN_PORT=8001
SECSCAN_WORKSPACE=/absolute/path/to/project-a
SECSCAN_WORKERS=2
SECSCAN_API_TOKEN=
```

A second checkout could use:

```dotenv
SECSCAN_COMPOSE_PROJECT=secscan-project-b
SECSCAN_PORT=8002
SECSCAN_WORKSPACE=/absolute/path/to/project-b
SECSCAN_WORKERS=2
SECSCAN_API_TOKEN=
```

Run `docker compose up --build --wait` in each checkout. The GUIs are then available independently at `http://127.0.0.1:8001/` and `http://127.0.0.1:8002/`, with separate scan history, reports, and vulnerability caches.

Use the same `.env` file when stopping a specific instance:

```bash
docker compose down
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

For another local source tree, set `SECSCAN_WORKSPACE` in `.env` and run:

```bash
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
