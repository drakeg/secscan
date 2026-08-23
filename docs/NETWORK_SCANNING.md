# Agentless network and host assessments

`secscan scan network` is the first non-repository assessment mode. It is intended for systems you own or are explicitly authorized to assess. Sprint 35 also exposes the same single-host scanner through the local REST API and web GUI with an explicit authorization acknowledgement.

## What it does

A network assessment combines two engines:

- **Nmap** discovers exposed TCP services and performs light service/version detection across the top 1000 ports.
- **Nuclei** runs signed/community vulnerability templates against the supplied host and normalizes matched vulnerabilities into the standard secscan finding model. The container pins Nuclei v3.11.1 and the official `nuclei-templates` v10.4.7 corpus. Nuclei v3.11.1 includes the patched `kin-openapi` dependency required by secscan's container vulnerability gate.

The resulting `secscan.json` can therefore be compared, filtered, subjected to policy, and displayed alongside repository/container findings. Service-submitted network jobs use the same job history, artifact manifest, conditional downloads, severity summary, dashboard, and auto-refreshing job-detail path as other scanners.

## CLI examples

```bash
secscan scan network server.example.com --output-dir /reports/server-example
```

or by IP address:

```bash
secscan scan network 192.0.2.10 --output-dir /reports/server-192-0-2-10
```

With Docker Compose:

```bash
docker compose --profile tools run --rm cli \
  scan network server.example.com \
  --output-dir /reports/server-example
```

The standalone CLI retains its existing behavior. The explicit `network_authorized` acknowledgement described below is a service/API boundary and is not a new CLI flag.

## REST API

A service-submitted network assessment must include `network_authorized: true`. This is an explicit operator acknowledgement, not an identity or entitlement system.

```bash
curl --fail -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H 'content-type: application/json' \
  -d '{"scanner":"network","target":"server.example.com","network_authorized":true,"fail_on":"NONE","timeout":600}'
```

When `SECSCAN_API_TOKEN` is enabled, include the same bearer header required by the other `/api/v1/*` routes. Network jobs can be filtered with the existing list endpoint:

```bash
curl --fail 'http://127.0.0.1:8000/api/v1/jobs?scanner=network&limit=20'
```

The service validates the authorization acknowledgement and the single hostname/IP target before the job record is created. Missing acknowledgement, URLs, CIDRs, malformed inputs, and unresolvable targets return `422` and do not create a job.

## Web GUI

Open **New scan**, choose **Server / Network — Agentless assessment**, and enter one hostname or IP address. The GUI displays an active-assessment warning and requires checking the authorization confirmation before it will submit the job.

After submission, the normal job-detail page auto-refreshes while the assessment runs. Normalized Nmap/Nuclei findings appear in the existing severity cards and findings table, network jobs appear in scan history with severity counts, and the latest completed report for each target contributes to the current-posture dashboard.

The browser acknowledgement does not make secscan suitable for untrusted users or public deployment. It is a deliberate friction point for the local operator while a future tenant/asset authorization model remains out of scope.

## Safety and scope

The network target intentionally accepts **one hostname or one IP address only**. URLs, CIDR blocks, arbitrary Nmap flags, target lists, and shell fragments are rejected. This avoids turning the local service into an unrestricted network-scanning interface while the asset and authorization model is still being built.

Nuclei is invoked with Interactsh disabled. Nmap runs service detection without requiring privileged container capabilities.

The Docker image stores the reviewed template corpus at `/opt/nuclei-templates` and passes that path explicitly on every scan. The build pins both the human-readable release tag and its reviewed full Git commit SHA. It fetches the tag, verifies that the tag still resolves to that exact commit, and fails closed if they differ. Automatic engine and template update checks are disabled, so a running image does not silently replace its assessment logic. Updating templates requires reviewing the upstream release, changing both Docker arguments, rebuilding, and passing the full repository and container validation gates. The upstream `templates-checksum.txt`, secscan version marker, and secscan commit marker are retained in the image for inspection.

Network scans actively connect to the authorized target. Image builds need access to GitHub to retrieve the pinned official corpus; ordinary scan startup does not need to install templates.

Only assess hosts and networks you own or have explicit authorization to test.

The service still binds to loopback by default. If trusted-LAN access is deliberately enabled, retain bearer authentication and host-firewall scoping as documented in `SERVICE_MODE.md`. Do not expose the service directly to the internet. The service has no TLS, user accounts, tenant isolation, target ownership proof, or hosted egress controls.

## Finding semantics

Nmap-discovered open services are recorded as informational/Low exposure findings such as `OPEN-TCP-22`. They are not automatically treated as exploitable vulnerabilities; they make externally reachable attack surface visible in the same dashboard.

Nuclei matches retain their template severity (Critical, High, Medium, Low, or Unknown) and template identifier.

## Local validation

### CLI/container boundary

Build the image, start the opt-in private-network HTTP fixture, confirm the bundled versions, and scan only that fixture:

```bash
docker compose --profile network-test up --build --detach --wait network-fixture
docker compose --profile tools run --rm --entrypoint sh cli -c \
  'nuclei -version && cat /opt/nuclei-templates/.secscan-template-version && cat /opt/nuclei-templates/.secscan-template-commit && test -s /opt/nuclei-templates/templates-checksum.txt'
docker compose --profile tools run --rm cli \
  scan network network-fixture \
  --output-dir /reports/network-compose \
  --fail-on NONE
docker compose --profile network-test down
```

The fixture has no published host port, runs without capabilities on the private Compose network, and exists only when its profile is selected. Confirm the version marker prints `v10.4.7`, the commit marker prints `83234ce456da3e90dda86dfbc5e605e64a846df3`, the scan creates `secscan.json`, and the logs do not report downloading or updating templates. Repeating the scan with the same image uses the same corpus. The ordinary `docker compose up --build --wait` path remains unchanged and does not start the fixture.

### Service/API boundary

Start the normal service and the private fixture, then submit only the fixture hostname through the API:

```bash
cp .env.example .env
docker compose up --build --wait
docker compose --profile network-test up --detach --wait network-fixture
curl --fail -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H 'content-type: application/json' \
  -d '{"scanner":"network","target":"network-fixture","network_authorized":true,"fail_on":"NONE","timeout":600}'
```

Copy the returned job ID and use the standard service commands to poll it and inspect `secscan.json` plus `artifacts.json`. Also confirm that omitting `network_authorized`, submitting a URL such as `http://network-fixture`, or submitting a CIDR returns `422` and creates no job.

The GUI can be validated against the same fixture by selecting **Server / Network — Agentless assessment**, entering `network-fixture`, checking the authorization box, and confirming that the detail page auto-refreshes to a terminal state and the job appears in history/dashboard summaries.

Clean up both components:

```bash
docker compose --profile network-test down
docker compose down
```

## Roadmap

This is the foundation for broader secscan asset assessments. Planned follow-up modes include:

- authenticated Linux host assessment (package inventory, patch state, SSH/firewall/hardening checks)
- persistent Assets that can be reassessed over time
- EC2 assessment combining AWS configuration with host/network posture
- Windows host/endpoints
- web/API DAST
- explicit bounded network ranges with authorization controls

Current and projected recurring secscan infrastructure/service cost remains **$0**. No hosted scanner, cloud service, or paid network-analysis service is required for this assessment mode.
