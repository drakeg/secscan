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
SECSCAN_GITHUB_TOKEN=
```

`.env` is ignored by Git so local paths, ports, and tokens are not committed. `.env.example` contains safe defaults and is intended to stay in the repository.

`SECSCAN_GITHUB_TOKEN` is optional. When set, it is available only to the server/container and enables cloning private `github.com` repositories. Prefer a fine-grained token with read-only Contents access and scope it only to repositories secscan needs. Do not enter Git credentials in the browser or repository URL.

From the repository root, build and start the service:

```bash
docker compose up --build --wait
```

Open `http://127.0.0.1:8000/` in a browser, or use the port configured in `SECSCAN_PORT`. The REST API remains available beneath `/api/v1`, interactive API documentation remains available at `/docs`, and the configured workspace is mounted read-only inside the container as `/workspace`.

A simple end-to-end GUI test is:

1. Open **New scan**.
2. Select **Filesystem** or **Repository**.
3. For a local scan use `/workspace`; for a remote repository use an HTTPS Git URL such as `https://github.com/example/project.git`.
4. For a private GitHub repository, set `SECSCAN_GITHUB_TOKEN` in `.env` before starting Compose; the target remains the normal credential-free GitHub URL.
5. Start the scan.
6. Open the completed job and inspect/filter the findings and generated artifacts.
7. Return to the Dashboard and confirm the latest target posture appears in the severity totals and priority chart.

Remote repository scans are shallow-cloned into temporary storage. In the default Compose configuration `/tmp` is a 512 MB tmpfs, providing a practical storage boundary for temporary checkouts. Remote URLs must use HTTPS and must not contain embedded credentials, query strings, or fragments.

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
SECSCAN_GITHUB_TOKEN=
```

A second checkout could use:

```dotenv
SECSCAN_COMPOSE_PROJECT=secscan-project-b
SECSCAN_PORT=8002
SECSCAN_WORKSPACE=/absolute/path/to/project-b
SECSCAN_WORKERS=2
SECSCAN_API_TOKEN=
SECSCAN_GITHUB_TOKEN=
```

Run `docker compose up --build --wait` in each checkout. The GUIs are then available independently at `http://127.0.0.1:8001/` and `http://127.0.0.1:8002/`, with separate scan history, reports, and vulnerability caches.

Use the same `.env` file when stopping a specific instance:

```bash
docker compose down
```

If `SECSCAN_API_TOKEN` is configured, enter the same token using the GUI's **API token** button. The browser stores it only in `sessionStorage` for that tab. `SECSCAN_GITHUB_TOKEN` is different: it stays server-side and is never entered into the browser UI.

### Compare the GUI with the CLI

Compose also includes an opt-in `cli` profile using the same locally built image, cache, reports volume, read-only workspace, and optional GitHub token. This is useful when validating that the GUI and CLI produce the same scanner behavior.

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

A public or authenticated GitHub repository can be compared from the same image using the same credential-free target URL:

```bash
docker compose --profile tools run --rm cli \
  scan repository https://github.com/example/project.git \
  --output-dir /reports/manual-remote-repository
```

Stop the local service with:

```bash
docker compose down
```

Use `docker compose down -v` only when you intentionally want to remove the persistent scan reports and vulnerability database cache as well.

## Dashboard behavior

The Dashboard is intended to answer what needs attention first rather than simply count historical findings.

- Critical, High, Medium, and Low headline totals use the latest completed report for each unique scanner/target pair.
- The vulnerability-mix chart shows the aggregate severity distribution of those latest reports.
- **Most urgent targets** ranks targets by Critical findings first, then High, Medium, and total findings.
- Historical rescans of the same target are not double-counted in current-posture charts.
- Scan-history rows show compact Critical/High/Medium/Low counts for each completed report.
- The browser retrieves a lightweight `/api/v1/jobs/{job_id}/summary` response rather than downloading every full report for dashboard rendering.

## Current GUI capabilities

- view queued, running, completed, and failed job counts
- see current Critical, High, Medium, and Low vulnerability totals on the front-page dashboard
- visualize current vulnerability mix and the most urgent targets to fix first
- browse recent and historical scan jobs with per-scan severity counts
- submit image, filesystem, local repository, remote repository, and SBOM scans
- use HTTPS GitHub, GitLab, Azure DevOps, and compatible Git URLs for public repository scans
- use server-side `SECSCAN_GITHUB_TOKEN` authentication for private `github.com` repository scans
- configure the policy threshold, timeout, policy path, and baseline path
- inspect normalized severity counts from `secscan.json`
- search findings by vulnerability ID, package, title, target, or version
- filter findings by severity and whether a fixed version is available
- open advisory URLs directly from finding rows
- visualize baseline comparison totals and browse new, resolved, and unchanged findings
- download generated scan artifacts
- delete completed/failed/cancelled scan history and artifacts with confirmation
- use an existing `SECSCAN_API_TOKEN` without persisting it beyond the current browser tab

Local path scans remain constrained by the service's `--allowed-input-root` configuration. The default Compose configuration exposes only the selected workspace beneath `/workspace`. Validated HTTPS repository URLs are handled separately and are not treated as local filesystem paths.

## Architecture

The browser UI remains a thin client over the existing service API and normalized artifacts. Scanner execution, job persistence, local path validation, artifact validation, and API authentication remain in `secscan.service`.

Remote repository URLs are validated at the service boundary, then the repository scanner performs a non-interactive shallow Git clone into temporary storage and feeds that checkout through the existing local repository/Trivy path. The temporary checkout is removed after each scanner operation. GitHub credentials are read only from the server environment, injected into the clone process as process-local Git configuration, and never added to job targets or command-line arguments.

`secscan.web.create_web_app()` creates the existing service application and mounts packaged static assets at `/` after the API routes. The web layer also exposes lightweight dashboard summaries and safe stored-scan deletion helpers while leaving scanner behavior in the core service/scanner modules.

The local Compose environment deliberately retains restrictive defaults: the service binds to loopback, the workspace is read-only, capabilities are dropped, `no-new-privileges` is enabled, the container root filesystem is read-only, and `/tmp` is bounded. These constraints should remain the baseline as secscan evolves toward a hosted multi-tenant service.

This increment does not add SaaS tenancy, user accounts, billing, GitHub App/OAuth installation flows, GitLab/Azure DevOps private credentials, or tenant credential storage. Those concerns should be introduced behind explicit organization/user/integration models rather than embedded into scan job targets.
