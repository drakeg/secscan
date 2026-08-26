# Sprint 39 — GUI Linux Host Assessments

## Goal

Make the existing SSH-authenticated `linux-host` scanner available from the browser as a normal secscan workflow while keeping SSH private-key material entirely server-side.

The product direction is GUI-first. The CLI remains useful for automation, troubleshooting, and scanner validation, but an operator should not need to use it for routine Linux-host assessments.

## User stories

1. As an operator, I can choose **Linux server — Authenticated assessment** from **New scan** and submit one authorized hostname/IP.
2. As an operator, I can see whether authenticated Linux scanning is configured before submitting the scan.
3. As an operator, the resulting job appears in the same scan history, auto-refreshing detail view, severity summaries, dashboard prioritization, policy, baseline, and artifact workflow as other scans.
4. As a security reviewer, I can verify that the browser never receives or submits SSH private keys, known-hosts contents, passwords, or arbitrary SSH options.
5. As a local Docker Compose user, I can provide an SSH key and `known_hosts` file through a dedicated read-only host directory mount.

## Planned implementation

- add `linux-host` to the New Scan selector
- add a Linux-host-specific authorization acknowledgement
- expose a web/API capability endpoint that reports only whether server-side SSH configuration is ready
- expose a web/API submission endpoint that accepts target and normal scan options but no credential fields
- reuse the existing service job manager and `linux-host` scanner rather than introducing a parallel results model
- pass SSH configuration to the service only through `SECSCAN_SSH_*` environment settings
- add `SECSCAN_SSH_DIR`, mounted read-only at `/run/secscan-ssh`, for local Compose operation
- keep the same credential mount available to the optional CLI profile for parity/testing
- ignore the default local `.secscan-ssh/` directory in Git
- add success/failure/security regression coverage

## Acceptance criteria

- the GUI visibly offers **Linux server — Authenticated assessment**
- the browser form contains no private-key, known-hosts, password, or arbitrary SSH-option input
- an explicit authorization acknowledgement is required before submission
- missing/invalid server-side SSH configuration is rejected before a job is persisted
- malformed, URL, CIDR, or unresolvable targets are rejected through the existing single-host validator
- configured Linux-host submissions create ordinary jobs with scanner value `linux-host`
- jobs use the existing background execution, history, dashboard, summary, report, policy, baseline, and artifact paths
- the service credential directory is mounted read-only
- `.env.example` documents server-side SSH configuration without containing credential material
- the default credential directory is ignored by Git
- localhost remains the default service binding and authenticated trusted-LAN behavior remains unchanged
- current and projected recurring infrastructure/service cost remains **$0**
- Python 3.12/3.14 preflight, applicable Compose/container validation, CodeQL, and the container vulnerability gate pass before merge

## Security boundaries

- SSH credentials are operator/server configuration, never browser payload data
- private-key and known-hosts **contents** are never persisted in service jobs, findings, reports, or history
- public-key authentication and strict host-key verification remain mandatory
- password auth, keyboard-interactive auth, SSH-agent forwarding, arbitrary SSH flags, bastion/proxy configuration, sudo, remediation, and agent installation remain out of scope
- this local single-operator credential model is not a future SaaS tenant credential vault; hosted/multi-user operation will require explicit user/organization/asset/integration models and encrypted secret-management boundaries
- only systems the operator owns or is explicitly authorized to assess may be targeted

## Local Compose setup

Create a host-only credential directory outside version control (the default `.secscan-ssh/` path is ignored):

```bash
mkdir -p .secscan-ssh
cp /path/to/id_ed25519 .secscan-ssh/id_ed25519
cp /path/to/known_hosts .secscan-ssh/known_hosts
chmod 600 .secscan-ssh/id_ed25519
```

Configure `.env`:

```dotenv
SECSCAN_SSH_DIR=./.secscan-ssh
SECSCAN_SSH_USER=secscan-audit
SECSCAN_SSH_KEY=/run/secscan-ssh/id_ed25519
SECSCAN_SSH_KNOWN_HOSTS=/run/secscan-ssh/known_hosts
SECSCAN_SSH_PORT=22
```

Then use the normal GUI startup path:

```bash
docker compose up --build --wait
```

Open the GUI, choose **Linux server — Authenticated assessment**, enter one hostname/IP, acknowledge authorization, and start the scan.

## Cost outlook

This Sprint uses the existing local service, Docker Compose environment, OpenSSH client, SQLite job store, reports, and scanner implementation. No hosted credential store, cloud resource, paid scanner, or recurring service is introduced. Current and projected recurring secscan infrastructure/service cost remains **$0**.
