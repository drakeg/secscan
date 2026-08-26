# Web GUI

The `secscan-service` command serves both the REST API and a browser interface. The browser is the primary interactive operator experience; the CLI remains available for automation, troubleshooting, and scanner validation.

## Local testing with Docker Compose

Docker Compose automatically reads a `.env` file from the repository root. Start by copying the provided example:

```bash
cp .env.example .env
```

Then edit `.env` for the local instance you want to run. The available settings include:

```dotenv
SECSCAN_COMPOSE_PROJECT=secscan-local
SECSCAN_PORT=8000
SECSCAN_BIND_ADDRESS=127.0.0.1
SECSCAN_WORKSPACE=.
SECSCAN_WORKERS=2
SECSCAN_API_TOKEN=
SECSCAN_GITHUB_TOKEN=
SECSCAN_SSH_DIR=./.secscan-ssh
SECSCAN_SSH_USER=
SECSCAN_SSH_KEY=/run/secscan-ssh/id_ed25519
SECSCAN_SSH_KNOWN_HOSTS=/run/secscan-ssh/known_hosts
SECSCAN_SSH_PORT=22
```

`.env` is ignored by Git so local paths, ports, and tokens are not committed. `.env.example` contains safe defaults and is intended to stay in the repository. The default `.secscan-ssh/` credential directory is also ignored by Git.

`SECSCAN_GITHUB_TOKEN` is optional. When set, it is available only to the server/container and enables cloning private `github.com` repositories. Prefer a fine-grained token with read-only Contents access and scope it only to repositories secscan needs. Do not enter Git credentials in the browser or repository URL.

The `SECSCAN_SSH_*` settings are optional and enable authenticated Linux-host assessments. SSH private keys and `known_hosts` contents stay on the service host and are mounted read-only into the container. They are never entered into or returned to the browser. See [Linux Host Scanning](LINUX_HOST_SCANNING.md) for account, key, host-verification, and least-privilege guidance.

From the repository root, build and start the service:

```bash
docker compose up --build --wait
```

Open `http://127.0.0.1:8000/` in a browser, or use the address and port configured in `SECSCAN_BIND_ADDRESS` and `SECSCAN_PORT`. Loopback remains the default. For testing from another trusted LAN system, set the host's exact private IP, configure a strong `SECSCAN_API_TOKEN`, restrict the port with the host firewall, and follow the host/second-device procedure in [Service Mode](SERVICE_MODE.md). The REST API remains available beneath `/api/v1`, interactive API documentation remains available at `/docs`, and the configured workspace is mounted read-only inside the container as `/workspace`.

A simple end-to-end GUI test is:

1. Open **New scan**.
2. Select the scan type you need.
3. Enter its target and any optional policy/baseline settings.
4. For active network or authenticated Linux-host assessments, acknowledge that you own or are explicitly authorized to assess the target.
5. Start the scan.
6. Open the auto-refreshing job detail page and inspect/filter findings and generated artifacts.
7. Return to the Dashboard and confirm the latest target posture appears in severity totals and priority charts.

Remote repository scans are shallow-cloned into temporary storage. In the default Compose configuration `/tmp` is a 512 MB tmpfs, providing a practical storage boundary for temporary checkouts. Remote URLs must use HTTPS and must not contain embedded credentials, query strings, or fragments.

### Agentless server/network scans

The GUI exposes **Server / Network — Agentless assessment** for the Nmap/Nuclei single-host scanner. Enter exactly one hostname or IP address. The form displays an active-assessment warning and requires an explicit confirmation that you own the target or have authorization to security-test it.

The browser sends `network_authorized: true` only after that checkbox is selected. The service independently validates both the acknowledgement and the target before it persists the job. URLs, CIDRs, malformed targets, and unresolvable targets are rejected. The acknowledgement is a local-operator safety control, not an identity, entitlement, or tenant-authorization system.

For a safe local demonstration, use the private opt-in Compose fixture documented in [Network Scanning](NETWORK_SCANNING.md). Do not use unrelated public systems as test targets.

Once queued, a network assessment uses the normal auto-refreshing scan-detail path. Normalized Nmap/Nuclei findings appear in the same severity cards and findings table, completed jobs receive the same severity chips in history, and their latest posture contributes to the existing dashboard charts.

### Authenticated Linux server scans

The GUI exposes **Linux server — Authenticated assessment** for the existing SSH-based `linux-host` scanner. The browser submits one hostname/IP plus ordinary scan options and an explicit authorization acknowledgement. It does **not** submit an SSH username, key, password, `known_hosts` contents, or arbitrary SSH flags.

Prepare a host-only credential directory, for example:

```bash
mkdir -p .secscan-ssh
cp /path/to/id_ed25519 .secscan-ssh/id_ed25519
cp /path/to/known_hosts .secscan-ssh/known_hosts
chmod 600 .secscan-ssh/id_ed25519
```

Then configure the service in `.env`:

```dotenv
SECSCAN_SSH_DIR=./.secscan-ssh
SECSCAN_SSH_USER=secscan-audit
SECSCAN_SSH_KEY=/run/secscan-ssh/id_ed25519
SECSCAN_SSH_KNOWN_HOSTS=/run/secscan-ssh/known_hosts
SECSCAN_SSH_PORT=22
```

`SECSCAN_SSH_DIR` is mounted read-only at `/run/secscan-ssh` for both the service and optional CLI profile. The GUI queries a protected capability endpoint that reports only whether the server-side SSH integration is configured. If required settings/files are unavailable, Linux-host submission is rejected before a job is persisted.

When configured, Linux-host jobs reuse the same job history, auto-refreshing detail page, severity chips, current-posture dashboard, policy, baseline, report, and artifact paths as other scans. The scanner itself retains key-only authentication, strict host-key verification, fixed read-only remote commands, and the security boundaries documented in [Linux Host Scanning](LINUX_HOST_SCANNING.md).

This shared service-side SSH configuration is deliberately a local/single-operator model. A future subscription/multi-user deployment will require explicit organization/user/asset/integration models plus tenant-aware encrypted secret storage; browser credential fields are not the intended future design.

### Local path selection

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

If `SECSCAN_API_TOKEN` is configured, enter the same token using the GUI's **API token** button. The browser stores it only in `sessionStorage` for that tab. `SECSCAN_GITHUB_TOKEN` and SSH credentials are different: they stay server-side and are never entered into the browser UI.

### Compare the GUI with the CLI

Compose includes an opt-in `cli` profile using the same locally built image, cache, reports volume, read-only workspace, optional GitHub token, and optional read-only SSH credential directory. This is useful for validation and automation, but routine interactive scanning is intended to use the GUI.

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

Network GUI/API behavior can be compared against the CLI using only an authorized target. For local validation, prefer the private `network-fixture` procedure in `docs/NETWORK_SCANNING.md`.

Linux-host GUI behavior can be compared with the CLI using the same server-side `SECSCAN_SSH_*` settings and read-only credential directory documented above.

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

Network and Linux-host reports use this existing normalized path; there is no separate dashboard or result schema for either scanner.

## Current GUI capabilities

- view queued, running, completed, and failed job counts
- see current Critical, High, Medium, and Low vulnerability totals on the front-page dashboard
- visualize current vulnerability mix and the most urgent targets to fix first
- browse recent and historical scan jobs with per-scan severity counts
- submit image, filesystem, local repository, remote repository, SBOM, authorized single-host network, and authenticated Linux-host scans
- use HTTPS GitHub, GitLab, Azure DevOps, and compatible Git URLs for public repository scans
- use server-side `SECSCAN_GITHUB_TOKEN` authentication for private `github.com` repository scans
- run an agentless Nmap/Nuclei assessment against one authorized hostname or IP with an explicit acknowledgement
- run a read-only SSH-authenticated Linux posture assessment against one authorized hostname or IP using server-side credentials
- configure the policy threshold, timeout, policy path, and baseline path
- inspect normalized severity counts from `secscan.json`
- search findings by vulnerability ID, package, title, target, or version
- filter findings by severity and whether a fixed version is available
- open advisory URLs directly from finding rows
- visualize baseline comparison totals and browse new, resolved, and unchanged findings
- download generated scan artifacts
- delete completed/failed/cancelled scan history and artifacts with confirmation
- use an existing `SECSCAN_API_TOKEN` without persisting it beyond the current browser tab

Local path scans remain constrained by the service's `--allowed-input-root` configuration. The default Compose configuration exposes only the selected workspace beneath `/workspace`. Validated HTTPS repository URLs and validated single-host network/Linux-host targets are handled separately and are not treated as local filesystem paths.

## Architecture

The browser UI remains a thin client over service APIs and normalized artifacts. Scanner execution, job persistence, local path validation, network/host target validation, artifact validation, and API authentication remain server-side.

Remote repository URLs are validated at the service boundary, then the repository scanner performs a non-interactive shallow Git clone into temporary storage and feeds that checkout through the existing local repository path. The temporary checkout is removed after each scanner operation. GitHub credentials are read only from the server environment, injected into the clone process as process-local Git configuration, and never added to job targets or command-line arguments.

Network targets are validated with the same single-host validator used by the scanner before a service job is persisted. The web form requires explicit operator acknowledgement, but it does not introduce users, roles, target ownership verification, tenant isolation, or hosted egress policy. Those controls are required before network submission could be offered to untrusted hosted tenants.

Linux-host web submission uses the same target validator and an explicit authorization acknowledgement. The service exposes only a boolean readiness capability to the browser; SSH credential paths/contents remain server configuration. The resulting job is handed to the normal service job pipeline and existing `linux-host` scanner.

`secscan.web.create_web_app()` creates the existing service application and mounts packaged static assets at `/` after the API routes. The web layer also exposes lightweight dashboard summaries, Linux-host web integration, and safe stored-scan deletion helpers while leaving scanner behavior in scanner modules.

The local Compose environment deliberately retains restrictive defaults: the service binds to loopback unless LAN access is explicitly configured, the workspace and SSH credential directory are read-only, capabilities are dropped, `no-new-privileges` is enabled, the container root filesystem is read-only, and `/tmp` is bounded. A non-loopback bind does not add TLS, user accounts, or tenant isolation and must not be treated as an internet-exposure mode.

This increment does not add SaaS tenancy, user accounts, billing, persistent Asset records, tenant credential storage, GitHub App/OAuth installation flows, GitLab/Azure DevOps private credentials, or internet-facing deployment controls. Those concerns should be introduced behind explicit organization/user/asset/integration models rather than embedded into scan job targets.
