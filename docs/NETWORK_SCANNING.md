# Agentless network and host assessments

`secscan scan network` is the first non-repository assessment mode. It is intended for systems you own or are explicitly authorized to assess.

## What it does

A network assessment combines two engines:

- **Nmap** discovers exposed TCP services and performs light service/version detection across the top 1000 ports.
- **Nuclei** runs signed/community vulnerability templates against the supplied host and normalizes matched vulnerabilities into the standard secscan finding model. The container pins Nuclei v3.11.1 and the official `nuclei-templates` v10.4.7 corpus. Nuclei v3.11.1 includes the patched `kin-openapi` dependency required by secscan's container vulnerability gate.

The resulting `secscan.json` can therefore be compared, filtered, subjected to policy, and displayed alongside repository/container findings.

## Example

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

## Safety and scope

The initial network target intentionally accepts **one hostname or one IP address only**. URLs, CIDR blocks, arbitrary Nmap flags, and shell fragments are rejected. This avoids turning the web/service layer into an unrestricted network-scanning interface while the asset and authorization model is still being built.

Nuclei is invoked with Interactsh disabled for this initial mode. Nmap runs service detection without requiring privileged container capabilities.

The Docker image stores the reviewed template corpus at `/opt/nuclei-templates` and passes that path explicitly on every scan. The build pins both the human-readable release tag and its reviewed full Git commit SHA. It fetches the tag, verifies that the tag still resolves to that exact commit, and fails closed if they differ. Automatic engine and template update checks are disabled, so a running image does not silently replace its assessment logic. Updating templates requires reviewing the upstream release, changing both Docker arguments, rebuilding, and passing the full repository and container validation gates. The upstream `templates-checksum.txt`, secscan version marker, and secscan commit marker are retained in the image for inspection.

Network scans still make outbound requests to the authorized target. Image builds need access to GitHub to retrieve the pinned official corpus; ordinary scan startup does not need to install templates.

Only assess hosts and networks you own or have explicit authorization to test.

## Finding semantics

Nmap-discovered open services are recorded as informational/Low exposure findings such as `OPEN-TCP-22`. They are not automatically treated as exploitable vulnerabilities; they make externally reachable attack surface visible in the same dashboard.

Nuclei matches retain their template severity (Critical, High, Medium, Low, or Unknown) and template identifier.

## Local validation

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

The fixture has no published host port, runs without capabilities on the private Compose network, and exists only when its profile is selected. Confirm the version marker prints `v10.4.7`, the commit marker prints `83234ce456da3e90dda86dfbc5e605e64a846df3`, the scan creates `secscan.json`, and the logs do not report downloading or updating templates. Repeating the scan with the same image uses the same corpus. The ordinary `docker compose up --build` path remains unchanged and does not start the fixture.

## Roadmap

This is the foundation for broader secscan asset assessments. Planned follow-up modes include:

- authenticated Linux host assessment (package inventory, patch state, SSH/firewall/hardening checks)
- EC2 assessment combining AWS configuration with host/network posture
- Windows host/endpoints
- web/API DAST
- explicit bounded network ranges with authorization controls
- persistent Assets that can be reassessed over time
