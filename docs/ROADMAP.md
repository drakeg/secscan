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

## Current sprint

### Sprint 8 — Policy v2

#### Goal

Add typed, explainable policy rules for fix availability, vulnerability age, package, vulnerability ID, and severity while preserving complete compatibility with existing threshold and suppression policy files.

#### User stories

1. As a security owner, I can apply stricter thresholds to selected packages or vulnerabilities.
2. As an operator, I can fail scans on findings that have a fix available.
3. As a risk owner, I can enforce remediation expectations based on vulnerability age when publication data is available.
4. As an auditor, I can see exactly which rule matched each finding and why.
5. As an existing user, my current policy files continue to work unchanged.

#### Planned implementation

- typed `PolicyRule` model
- exact package, vulnerability, and severity match conditions
- `fix_available` condition derived from normalized fixed-version metadata
- `max_age_days` condition using optional normalized publication dates
- deterministic suppression-before-rule precedence
- rule-specific `fail_on` thresholds and reasons
- strict unknown-key and type validation
- conflicting duplicate rule detection
- explainable `rule_matches` metadata in `secscan.json`
- backward-compatibility and failure-path tests
- policy, roadmap, architecture, and README updates

#### Acceptance criteria

- existing `policy.fail_on` and `suppressions` files parse and behave unchanged
- a rule requires at least one match condition
- all configured rule conditions must match the same finding
- active suppressions prevent rule matches for the suppressed finding
- missing publication dates do not satisfy age rules
- global threshold or any matching rule may produce exit code `2`
- invalid or conflicting rules fail clearly with exit code `1`
- report metadata explains every rule match
- branch preflight, CI, and CodeQL pass before merge
- no AWS resources or paid infrastructure are introduced

#### Out of scope

- wildcard or regular-expression matching
- KEV, EPSS, exploitability, or internet-exposure enrichment
- centrally signed or remotely distributed policy bundles
- approval workflows or multi-user policy governance
- risk-score aggregation

#### Cost outlook

Current and projected recurring infrastructure cost remains **$0**. Policy evaluation remains local and introduces no external services.

## Planned feature sprints

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
