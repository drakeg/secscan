# Product Roadmap and Sprint Plans

## Product goal

Deliver a portable, open-source vulnerability-management platform that begins as a reliable Dockerized scanner and grows toward multi-target scanning, history, automation, and AWS-aware prioritization.

## Delivery principles

- Preserve local, no-cloud operation as the baseline.
- Keep scanner-specific behavior behind adapters and scanner plugins.
- Normalize all findings into a secscan-owned schema.
- Require automated packaging, test, and container validation before feature growth.
- Model current and projected operating costs before introducing paid infrastructure.
- Capture new ideas in the backlog instead of expanding an active sprint.

## Completed work

### Sprint 0 — Foundation and Planning

Established the repository, Agile workflow, architecture, roadmap, Definition of Done, Trivy strategy, and $0 infrastructure baseline.

### Sprint 1 — Dockerized Scanner MVP

Delivered public image scanning, normalized JSON, severity policy enforcement, deterministic exit codes, non-root execution, and a supported rootless-Docker workflow.

### Sprint 2 — SBOM and Human-Readable Reporting

Delivered raw Trivy JSON, normalized secscan JSON, CycloneDX JSON, and a standalone HTML report.

### Sprint 3 — Engineering Foundation and Continuous Integration

Delivered CI for Ruff, mypy, pytest, wheel integrity, clean installation, container startup, CodeQL, Dependabot, and fixable-critical container vulnerability enforcement.

### Sprint 4A — Scanner Plugin Architecture

Delivered scanner-neutral contracts, an explicit registry, the image scanner plugin, registry-driven CLI dispatch, and nested-module packaging controls.

### Sprint 4B — Filesystem Scanning

Delivered the filesystem scanner plugin, read-only mount guidance, Trivy filesystem and CycloneDX adapters, path validation, and target-aware reports.

### Sprint 4C — Policy Configuration and Suppressions

Delivered safe YAML policies, threshold precedence, expiring auditable suppressions, policy metadata, and strict validation.

### Sprint 5 — Finding Comparison and Baselines

Delivered stable finding fingerprints, `--baseline`, new/resolved/unchanged classification, `secscan.diff.json`, strict baseline validation, and same-output-path baseline safety.

### Sprint 5.5 — Local Scan History

Delivered a versioned SQLite history store, automatic scan metadata recording, `secscan history`, `secscan show`, migration tests, and local-only operation.

### Sprint 6 — Repository Scanning

Delivered a repository scanner plugin for checked-out source trees using the existing normalization, policy, baseline, reporting, history, and exit-code pipelines.

### Sprint 7 — SBOM Ingestion

Delivered CycloneDX JSON validation, Trivy SBOM vulnerability scanning, normalized findings, standard artifact preservation, and scanner-neutral policy, baseline, history, and reporting integration.

### Sprint 8 — Policy v2

Delivered typed, explainable rules for packages, vulnerability IDs, severities, fix availability, and vulnerability age while preserving existing policy compatibility.

### Sprint 14 — Local Historical Trends

Delivered bounded exact-cohort severity trends from local SQLite history with console and versioned JSON output.

### Sprint 15 — SPDX JSON SBOM Ingestion

Delivered SPDX 2.2/2.3 JSON scanning, format-specific preserved artifacts, history integration, and constant-path service downloads.

### Sprint 16 — SBOM Package and License Inventory

Delivered deterministic local package and declared-license inventory for supported CycloneDX and SPDX JSON.

### Sprint 17 — SBOM Inventory Comparison

Delivered deterministic comparison of normalized SBOM inventories with strict package identity validation.

### Sprint 18 — SBOM Declared-License Policy

Delivered strict exact-string declared-license policy with deterministic evidence and CI-friendly exit codes.

### Sprint 19 — Guarded GitHub Release Artifacts

Delivered exact version-tag validation, verified Python release artifacts, deterministic SHA-256 checksums, and least-privilege GitHub Release automation.

### Sprint 20 — Auditable License-Policy Exceptions

Delivered exact package/license exceptions with required reasons, expirations, strict identity precedence, and deterministic suppression evidence.

### Sprint 21 — Finding-Level History Transitions

Delivered transactional finding observations, safe version 1 database migration, and deterministic latest-transition evidence for exact cohorts.

### Sprint 22 — Bounded Finding Observation Timing

Delivered censored-aware bounded finding episodes and scan-to-scan observed resolution metrics without claiming authoritative MTTR.

### Sprint 23 — Docker Compose Local Evaluation

Delivered a secure, persistent, one-command Docker Compose environment for locally testing the service API and real scanner jobs.

### Sprint 24 — Service Local-Input Boundaries

Delivered configurable service input roots, Compose confinement to `/workspace`, and traversal and symlink-escape rejection before job persistence.

### Sprint 25 — Service Artifact Integrity Manifests

Delivered deterministic service artifact manifests with byte sizes, SHA-256 digests, atomic persistence, and local Compose verification procedures.

### Sprint 26 — Optional Local API Bearer Authentication

Delivered opt-in shared bearer protection for local API routes with constant-time comparison, public health and documentation routes, and unchanged zero-configuration Compose behavior.

### Sprint 27 — Artifact Discovery and Conditional Downloads

Delivered stable artifact-manifest discovery, manifest-backed strong ETags, `HEAD` downloads, conditional revalidation, and legacy-artifact compatibility.

### Local Web and Broader Assessment Increments

Delivered the first local web GUI, richer searchable results and dashboard summaries, configurable Compose evaluation, safe terminal-job deletion, public and private GitHub repository scanning, comprehensive Trivy/Semgrep/Gitleaks/Checkov repository assessment, and single-host Nmap/Nuclei network assessment.

### Sprint 28 — Deterministic Nuclei Templates

Delivered an official version-pinned Nuclei template corpus in the container, an explicit read-only runtime path with updates disabled, an opt-in private Compose fixture, and documented local validation.

### Sprint 29 — Immutable Nuclei Template Provenance

Delivered a fail-closed binding between the documented Nuclei template release and one reviewed full Git commit SHA, with runtime provenance markers and Compose verification.

### Sprint 30 — Opt-in Trusted-LAN Access

Delivered an explicit private-address Compose binding override while retaining the loopback default, with bearer-token, firewall, second-device, and cleanup procedures.

### Sprint 31 — Verifiable GHCR Container Releases

Delivered exact-version Linux/AMD64 GHCR publication, an immutable digest release asset, GitHub build provenance, and local verification and cost controls.

### Sprint 32 — Digest-Pinned Compose Consumption

Delivered a shared release-digest override for the Compose service and CLI with explicit pull/no-build procedures while retaining local builds as the default.

### Sprint 33 — Multi-Architecture GHCR Releases

Delivered one exact-version AMD64/ARM64 OCI image index with an immutable digest, unchanged provenance wiring, native local ARM64 validation, and platform verification procedures.

### Sprint 34 — Checksummed Release Source SBOM

Delivered a machine-readable SPDX 2.3 JSON source inventory for stable releases using pinned `anchore/sbom-action@v0.24.0` and Syft `v1.42.3`. The SBOM is generated from the clean tagged checkout, staged as `release-dist/secscan-source.spdx.json`, covered by the same deterministic `SHA256SUMS` manifest as the wheel and source distribution, and uploaded only through the existing guarded GitHub Release step. Action-managed artifact/release uploads and dependency submission remain disabled. Branch preflight, release-focused tests, container smoke checks, CI, and CodeQL passed with no release tag or package publication during validation.

## Current sprint

### Sprint 35 — Web/API Single-Host Network Assessments

#### Goal

Make the existing deterministic Nmap/Nuclei single-host assessment usable from the local secscan REST API and browser GUI without weakening the scanner's current target, authorization, deployment, or cost boundaries.

#### User stories

1. As a local operator, I can select a server/network assessment in the web GUI, enter one hostname or IP address that I am authorized to test, and launch the existing network scanner.
2. As an API user, I can submit and filter `network` jobs through the same job endpoints used by other scanner types.
3. As an operator, invalid or unacknowledged network targets are rejected before job persistence, and completed network findings flow through the existing job detail, history, severity, artifact, and dashboard views.
4. As a maintainer, I can demonstrate the service path safely against the existing private Compose network fixture without scanning public infrastructure.

#### Planned implementation

- extend the service request and list-filter scanner contracts to include `network`
- validate network targets at the service boundary with the existing single-host validator before a job is persisted
- require an explicit authorization acknowledgement for service-submitted network scans while leaving existing CLI behavior unchanged
- add a **Server / Network — Agentless assessment** option to the New Scan GUI with hostname/IP guidance and a network-only authorization checkbox
- reuse the existing normalized `secscan.json`, summary endpoint, dashboard, history, artifact, polling, policy, and baseline behavior instead of adding network-specific result storage
- document REST, GUI, Docker Compose fixture, authentication, trusted-LAN, and cleanup procedures
- add focused service and web regression tests for accepted/rejected submissions, filtering, UI behavior, and preservation of existing scanner contracts

#### Acceptance criteria

- `POST /api/v1/jobs` accepts `scanner: network` only for one valid resolvable hostname/IP and an explicit authorization acknowledgement
- missing authorization, URLs, CIDRs, malformed targets, and unresolvable targets return `422` and create no job
- `GET /api/v1/jobs?scanner=network` filters network jobs using the existing newest-first and limit semantics
- the web GUI exposes the network option, provides target-specific guidance, requires acknowledgement before submission, and opens the normal auto-refreshing job detail view
- completed network reports appear in existing severity counts, scan history, current-posture dashboard, findings filters, and artifact downloads without a parallel result model
- the documented Compose validation uses only the opt-in private `network-fixture`; normal `docker compose up --build --wait` does not start that fixture
- existing image, filesystem, repository, and SBOM API/UI behavior remains compatible
- focused tests, `git diff --check`, `bash scripts/preflight.sh`, applicable Docker/Compose validation, GitHub CI, and CodeQL pass before merge
- no release tag, package publication, cloud resource, paid service, or recurring infrastructure cost is introduced

#### Security and operational boundaries

- network assessment remains active probing and is only for systems the operator owns or has explicit authorization to assess
- only one hostname or IP is accepted; CIDRs, target lists, URLs, arbitrary Nmap/Nuclei arguments, Interactsh, and browser-supplied scanner flags remain out of scope
- the authorization checkbox/field records operator acknowledgement; it is not an identity, entitlement, or tenant authorization system
- localhost remains the default service bind; trusted-LAN access remains explicit, bearer-token protected, firewall constrained, and unsuitable for internet exposure
- service-side target validation does not make public-target scanning safe for a future multi-tenant hosted service; tenant authorization and egress controls must precede that use case
- scanner binaries and Nuclei templates are unchanged in this sprint

#### Validation plan

Automated validation covers service model acceptance, pre-persistence rejection, scanner filtering, command construction, and packaged web assets. Local integration validation will start the normal service plus the opt-in private Compose fixture, submit `network-fixture` through the authenticated or localhost API, wait for a terminal job, inspect `secscan.json` and `artifacts.json`, confirm dashboard compatibility, and then remove the fixture. Existing quick-start and cleanup commands remain valid.

#### Cost outlook

Sprint 35 reuses the local service, SQLite, Docker Compose network, bundled Nmap/Nuclei binaries, and pinned local template corpus. Current and projected recurring secscan infrastructure/service cost remains **$0**. Operators remain responsible for their own network usage; no third-party hosted scanner or cloud resource is enabled.

#### Out of scope

- persistent Asset records or an asset inventory database
- authenticated Linux/Windows host inspection, agents, SSH/WinRM credentials, or endpoint management
- CIDR/range scanning, discovery, scheduling, recurring scans, or distributed workers
- AWS EC2 correlation, cloud posture scanning, web/API DAST expansion, or new scanner engines
- SaaS users, organizations, tenant isolation, billing, TLS/ingress, or internet exposure

## Planned feature sprints

### Sprint 9 — Service Mode and API

Delivered a long-running local API, background jobs, bounded concurrency, health and job status endpoints, and allow-listed artifact downloads while preserving the standalone CLI.

### Sprint 10 — Persistent Service Job Management

Delivered SQLite-backed service job metadata, restart recovery, filtered recent-job listing, and safe queued-job cancellation.

#### Stories and acceptance criteria

- submitted jobs are recorded before worker execution and remain queryable after restart
- jobs interrupted by a restart are marked failed rather than replayed automatically
- `GET /api/v1/jobs` returns newest-first results with optional `status`, `scanner`, and bounded `limit` filters
- `DELETE /api/v1/jobs/{job_id}` cancels only queued jobs and rejects running or terminal jobs
- the existing submit, status, artifact, CLI, and scanner behavior remains compatible
- SQLite and the local filesystem remain the only service-state dependencies
- restart recovery, filtering, cancellation races, and endpoint responses have automated tests
- documentation, branch preflight, CI, and CodeQL pass before merge

#### Security and cost boundaries

- active scanner processes are never terminated through the API
- cancelled jobs are retained for auditability; this sprint adds no deletion endpoint
- interrupted work is not automatically replayed against potentially changed targets
- current and projected recurring infrastructure cost remains **$0**

### Sprint 11 — AWS Asset Discovery

Delivered read-only discovery of exact ECR repositories across approved accounts and regions with versioned inventory output and documented least-privilege IAM.

#### Stories and acceptance criteria

- YAML configuration requires explicit account IDs, regions, and exact repository names
- same-account discovery verifies the caller account before accessing ECR
- cross-account discovery uses one explicitly configured role ARN and short-lived credentials
- paginated `DescribeImages` results produce a versioned JSON inventory with immutable digest URIs
- discovery does not enumerate repositories, pull images, start scans, or mutate AWS resources
- credential-free tests cover configuration validation, repository scoping, pagination, output, and account rejection
- local automated and optional live AWS testing procedures are documented
- least-privilege IAM, security boundaries, and the projected cost remain documented
- branch preflight, CI, and CodeQL pass before merge

#### Security and cost boundaries

- credentials and session tokens are never persisted
- exact repository allow-lists prevent unbounded discovery
- output is treated as security-sensitive infrastructure inventory
- current and projected recurring secscan infrastructure cost remains **$0**

### Sprint 12 — Authenticated ECR Scanning

Delivered authenticated scanning of one explicitly selected immutable ECR image through the existing image, policy, baseline, reporting, SBOM, history, and exit-code pipeline.

#### Stories and acceptance criteria

- `secscan scan ecr` requires an exact digest URI present in a schema-versioned inventory
- the inventory account, region, and repository are rechecked against the AWS allow-list
- same-account scans use the standard AWS credential chain or configured profile
- cross-account scans use short-lived assumed-role credentials
- AWS credentials are passed only through the Trivy child-process environment and are never written to commands, reports, history, or logs
- existing policy, baseline, JSON, HTML, CycloneDX, history, timeout, and exit-code behavior remains available
- credential-free tests cover inventory selection, allow-list rejection, credential handling, CLI parsing, and child-process isolation
- local automated and optional live ECR testing procedures remain documented
- least-privilege pull permissions, security boundaries, and potential data-transfer costs are documented
- branch preflight, CI, and CodeQL pass before merge

#### Security and cost boundaries

- only one exact inventory digest is scanned per command
- batch selection, scheduling, repository enumeration, and service-mode ECR scans remain out of scope
- credentials and authorization tokens are never persisted
- current recurring secscan infrastructure cost remains **$0**; users retain responsibility for AWS data-transfer and registry costs

### Sprint 13 — Bounded ECR Batch Scanning

Delivered sequential batches of up to 20 explicitly selected immutable ECR inventory URIs with isolated artifacts, shared history, and a machine-readable batch manifest.

#### Stories and acceptance criteria

- users repeat `--image-uri` to select exact digest URIs from the versioned inventory
- selections must be unique, present in the inventory, approved by configuration, and limited to 20
- the complete inventory and allow-list selection is validated before the first scan starts
- scans run sequentially and reuse authenticated ECR scanning without adding a scheduler or queue
- each image writes to a deterministic index-and-digest directory beneath an initially empty output root
- batch history uses one shared SQLite database unless history is disabled or another path is supplied
- `batch.json` records each selected URI, output directory, status, exit code, and the aggregate exit code
- aggregate exit code is `1` for any operational failure, otherwise `2` for any policy failure, otherwise `0`
- credential-free tests cover bounds, duplicates, CLI selection, output isolation, manifests, and exit aggregation
- local automated and optional live batch testing procedures remain documented
- branch preflight, CI, and CodeQL pass before merge

#### Security and cost boundaries

- no tag, wildcard, repository-wide, or implicit “all images” selection is supported
- concurrency, scheduling, retries, resume, and service-mode batch submission remain out of scope
- the output root must be empty to prevent accidental artifact overwrite
- current recurring secscan infrastructure cost remains **$0**; users retain responsibility for per-image AWS data-transfer and registry costs

## Future epics and backlog

- additional SBOM formats beyond CycloneDX JSON and SPDX 2.x JSON
- richer SBOM license governance and dependency intelligence
- vulnerability-to-inventory and other cross-source correlation
- additional private registry authentication
- container releases, immutable image digests, signatures, and provenance
- richer remediation analytics after scan cadence and censoring are accounted for
- additional scanner adapters such as Syft and Grype
- risk scoring, KEV, and EPSS enrichment
- EC2 inventory or snapshot-based scanning
- ECS and EKS workload association
- persistent assets and reassessment workflows
- authenticated Linux and Windows host assessment
- bounded network-range assessment with explicit authorization controls
- web/API DAST expansion
- multi-user access and tenant isolation
- Jira, Slack, ServiceNow, SIEM, and GitHub integrations
- signed policy bundles and enterprise governance

## Backlog rules

The roadmap is directional. A future sprint becomes committed only after planning confirms its stories, acceptance criteria, dependencies, security implications, validation strategy, and projected operating costs. Ideas discovered during a sprint are added to the backlog rather than changing the active sprint scope.
