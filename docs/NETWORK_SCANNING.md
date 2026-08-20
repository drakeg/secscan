# Agentless network and host assessments

`secscan scan network` is the first non-repository assessment mode. It is intended for systems you own or are explicitly authorized to assess.

## What it does

A network assessment combines two engines:

- **Nmap** discovers exposed TCP services and performs light service/version detection across the top 1000 ports.
- **Nuclei** runs signed/community vulnerability templates against the supplied host and normalizes matched vulnerabilities into the standard secscan finding model.

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

Only assess hosts and networks you own or have explicit authorization to test.

## Finding semantics

Nmap-discovered open services are recorded as informational/Low exposure findings such as `OPEN-TCP-22`. They are not automatically treated as exploitable vulnerabilities; they make externally reachable attack surface visible in the same dashboard.

Nuclei matches retain their template severity (Critical, High, Medium, Low, or Unknown) and template identifier.

## Roadmap

This is the foundation for broader secscan asset assessments. Planned follow-up modes include:

- authenticated Linux host assessment (package inventory, patch state, SSH/firewall/hardening checks)
- EC2 assessment combining AWS configuration with host/network posture
- Windows host/endpoints
- web/API DAST
- explicit bounded network ranges with authorization controls
- persistent Assets that can be reassessed over time
