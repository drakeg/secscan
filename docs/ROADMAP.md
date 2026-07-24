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

## Current sprint

### Sprint 7 — SBOM Ingestion

#### Goal

Allow secscan to ingest an existing CycloneDX JSON SBOM and process its vulnerability results through the same scanner-neutral pipeline used by image, filesystem, and repository scans.

#### User stories

1. As an operator, I can scan an existing CycloneDX SBOM without access to the original image or filesystem.
2. As a CI user, I can apply existing policy thresholds and suppressions to SBOM-derived findings.
3. As a security owner, I can compare SBOM scans against baselines and retain them in local history.
4. As an auditor, I receive the same normalized JSON, HTML, raw result, and CycloneDX artifact contract.

#### Planned implementation

- built-in `SBOMScanner` plugin
- `secscan scan sbom <file>`
- CycloneDX JSON validation
- Trivy SBOM vulnerability adapter
- normalized findings through the existing model
- preservation of the validated input as `secscan.cdx.json`
- policy, baseline, history, reporting, and exit-code integration
- missing, malformed, invalid-format, empty-component, and successful-input tests
- wheel and container package-integrity coverage
- README, architecture, and SBOM scanning documentation

#### Acceptance criteria

- valid CycloneDX JSON is accepted
- missing files, malformed JSON, and non-CycloneDX documents fail clearly with exit code `1`
- Trivy SBOM results normalize through the existing finding model
- policy exit code `2` behavior remains unchanged
- baseline comparison and SQLite history work without scanner-specific changes
- the input SBOM is preserved as the standard CycloneDX artifact
- CI and CodeQL pass before merge
- no AWS resources or paid infrastructure are introduced

#### Out of scope

- SPDX input
- license inventory or compliance analysis
- package additions, removals, upgrades, or downgrade intelligence
- SBOM-to-SBOM package diffing
- signed attestations or signature verification
- cross-source correlation

#### Cost outlook

Current and projected recurring infrastructure cost remains **$0**. SBOM ingestion is local and uses the bundled Trivy engine.

## Planned feature sprints

### Sprint 8 — Policy v2

Add fix-availability, age, package, and richer vulnerability rules with explainable evaluation.

### Sprint 9 — Service Mode and API

Add a long-running API, background jobs, bounded concurrency, health endpoints, and an optional PostgreSQL backend while preserving the standalone CLI.

### Sprint 10 — AWS Asset Discovery

Discover approved ECR assets across configured accounts and regions using documented least-privilege IAM permissions and an explicit cost model.

## Future epics and backlog

- SPDX and additional SBOM formats
- SBOM package and license intelligence
- cross-source correlation
- private registry and ECR authentication
- release automation, immutable images, provenance, and checksums
- historical trends and mean time to remediation
- additional scanner adapters such as Syft and Grype
- risk scoring, KEV, and EPSS enrichment
- EC2 inventory or snapshot-based scanning
- ECS and EKS workload association
- web dashboard and multi-user access
- Jira, Slack, ServiceNow, SIEM, and GitHub integrations
- signed policy bundles and enterprise governance

## Backlog rules

The roadmap is directional. A future sprint becomes committed only after planning confirms its stories, acceptance criteria, dependencies, security implications, validation strategy, and projected operating costs. Ideas discovered during a sprint are added to the backlog rather than changing the active sprint scope.
