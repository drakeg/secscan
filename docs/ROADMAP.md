# Product Roadmap and Sprint Plans

## Product goal

Deliver a portable, open-source vulnerability-management platform that begins as a reliable Dockerized scanner and grows toward multi-target scanning, history, automation, and AWS-aware prioritization.

## Delivery principles

- Preserve local, no-cloud operation as the baseline.
- Keep scanner-specific behavior behind adapters and scanner plugins.
- Normalize all findings into a secscan-owned schema.
- Require automated packaging, test, and container validation before feature growth.
- Model current and projected operating costs before introducing paid infrastructure.

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

## Current sprint

### Sprint 5.5 — Local Scan History

#### Goal

Persist successfully completed scan metadata in a local, versioned SQLite database and expose terminal-friendly history inspection without adding cloud infrastructure.

#### User stories

1. As an operator, I can automatically retain a record of completed scans.
2. As a security owner, I can list recent targets and severity totals without opening JSON files.
3. As an auditor, I can inspect one scan's versions, policy threshold, duration, and artifact paths.
4. As a maintainer, I can evolve the database through deterministic schema migrations.

#### Planned implementation

- SQLite-backed `HistoryStore`
- internal `schema_migrations` table and migration version 1
- automatic recording after successful artifact generation
- `secscan history` with configurable limit
- `secscan show <id>`
- `--history-db` and per-scan `--no-history`
- scan metadata, severity totals, versions, duration, and artifact paths
- unit tests for migration, persistence, listing, lookup, and validation
- wheel and container package-integrity coverage
- README, architecture, history guide, and Definition of Done updates

#### Acceptance criteria

- first use creates and migrates an empty database safely
- repeated use does not reapply migrations
- failed or incomplete scans are not recorded
- successful image and filesystem scans are recordable
- history is ordered newest-first
- unknown scan IDs fail clearly with exit code `1`
- `--no-history` leaves the database unchanged
- CI and CodeQL pass before merge
- no AWS resources or paid infrastructure are introduced

#### Out of scope

- storing individual findings in SQLite
- automatic retention or deletion
- trend charts and remediation-time calculations
- multi-user access or remote databases
- PostgreSQL and service mode

#### Cost outlook

Current and projected recurring infrastructure cost remains **$0**. SQLite is embedded in Python and the database remains local.

## Planned feature sprints

### Sprint 6 — Repository Scanning

Add a repository scanner plugin and reuse normalization, policy, baseline, reporting, and history pipelines.

### Sprint 7 — SBOM Ingestion

Scan existing CycloneDX and supported SBOM artifacts without requiring the original image or filesystem.

### Sprint 8 — Policy v2

Add fix-availability, age, package, and richer vulnerability rules with explainable evaluation.

### Sprint 9 — Service Mode and API

Add a long-running API, background jobs, bounded concurrency, health endpoints, and an optional PostgreSQL backend while preserving the standalone CLI.

### Sprint 10 — AWS Asset Discovery

Discover approved ECR assets across configured accounts and regions using documented least-privilege IAM permissions and an explicit cost model.

## Future epics

- private registry and ECR authentication
- release automation, immutable images, provenance, and checksums
- historical trends and mean time to remediation
- additional scanner adapters such as Syft and Grype
- EC2 inventory or snapshot-based scanning
- ECS and EKS workload association
- web dashboard and multi-user access
- Jira, Slack, ServiceNow, SIEM, and GitHub integrations
- signed policy bundles and enterprise governance

## Backlog rules

The roadmap is directional. A future sprint becomes committed only after planning confirms its stories, acceptance criteria, dependencies, security implications, validation strategy, and projected operating costs.
