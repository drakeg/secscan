# Product Roadmap and Sprint Plans

## Product goal

Deliver a portable, open-source security scanning platform that begins as a Dockerized local scanner and grows toward continuous vulnerability management with AWS-aware context.

## Scope guardrails

The early product is not intended to reproduce every Amazon Inspector capability. The first usable release focuses on repeatable scanning, normalized findings, reports, and policy enforcement. Cloud discovery, persistence, exposure analysis, and contextual risk scoring are separate later increments.

---

## Sprint 0 — Foundation and Planning

### Goal

Create a clear product direction, delivery process, repository structure, and technical decisions sufficient to begin implementation without unnecessary rework.

### Planned outcomes

- establish the GitHub repository and branch workflow
- document product vision and scope boundaries
- define the Agile process and Definition of Done
- document the initial architecture
- select the initial scan engine strategy
- record unresolved decisions such as license, supported platforms, and release registry
- create the initial product backlog

### Acceptance criteria

- repository has a documented vision and roadmap
- Sprint 1 has testable scope and acceptance criteria
- initial architecture separates scanner adapters from project-owned models
- no cloud resources are required
- projected recurring infrastructure cost is $0

### Risks and decisions

- **Decision:** begin with Trivy to reduce MVP complexity.
- **Decision:** normalize engine output into a secscan-owned schema.
- **Open:** choose an open-source license before the first public release.
- **Open:** decide whether the first published image will use GitHub Container Registry, Docker Hub, or both.

---

## Sprint 1 — Dockerized Scanner MVP

### Goal

Run one Docker command against a public container image and receive machine-readable scan output with a policy-based exit code.

### User stories

1. As a developer, I can scan a public OCI/container image without installing a scanner locally.
2. As a CI operator, I can fail a build when findings meet a configured severity threshold.
3. As a security analyst, I can retain the raw scanner result and a normalized secscan result.

### Planned implementation

- multi-stage Dockerfile with pinned scanner and runtime versions
- small CLI/entrypoint with `scan image` command
- Trivy adapter isolated behind an internal interface
- project-owned normalized finding schema
- JSON output directory contract
- severity threshold policy
- deterministic exit codes
- unit tests for normalization and policy evaluation
- smoke test against a known public image

### Acceptance criteria

- `docker build` succeeds on a supported Linux development system
- a documented `docker run` command scans `alpine` or another agreed test image
- raw Trivy JSON and normalized secscan JSON are written to a mounted output directory
- the result includes target, package, vulnerability ID, installed version, fixed version when known, severity, and source
- `--fail-on critical` returns nonzero only when matching findings exist
- scanner or input failures return a different exit code from policy violations
- no Docker socket is required for registry-based public image scanning

### Out of scope

- HTML reports
- filesystem targets
- private registries
- scan history
- AWS discovery
- web dashboard

### Cost outlook

- local development and GitHub source hosting: $0
- optional CI usage: within included GitHub Actions allowances until usage exceeds the account plan
- no AWS monthly cost

---

## Sprint 2 — SBOM and Human-Readable Reporting

### Goal

Produce portable SBOM artifacts and a useful report that a human can review without parsing JSON.

### Planned implementation

- CycloneDX JSON SBOM generation
- HTML report generation from normalized data
- summary counts by severity and fix availability
- report metadata including scan time, target reference, digest, engine version, and database timestamp
- report templates kept separate from scan logic
- artifact validation tests

### Acceptance criteria

- one scan can emit raw findings, normalized findings, CycloneDX SBOM, and HTML
- HTML report renders without an external service
- report distinguishes fixable and currently unfixable findings
- malformed or incomplete engine output produces an explicit error rather than a partial success

---

## Sprint 3 — Filesystem Scanning and Policy Configuration

### Goal

Scan mounted source trees or filesystems safely and apply reusable policy files.

### Planned implementation

- `scan filesystem` target
- read-only mount documentation and validation
- YAML policy schema
- ignored vulnerability rules with required reason and optional expiration
- configurable severity and fix-availability gates
- policy validation command

### Acceptance criteria

- scanner can inspect a mounted directory without write access
- policy file errors are actionable
- expired suppressions are surfaced
- output clearly records which findings were suppressed and why

---

## Sprint 4 — CI/CD Integration and Release Automation

### Goal

Make secscan easy to consume in automated build pipelines and publish reproducible releases.

### Planned implementation

- GitHub Actions CI for linting, unit tests, image build, and smoke tests
- image vulnerability scan of secscan itself
- versioned release workflow
- software provenance and image digest publication
- example GitHub Actions consumer workflow
- release notes and upgrade guidance

### Acceptance criteria

- pull requests run automated validation
- tagged releases publish an immutable versioned image
- released images are referenced by semantic version and digest
- consumers can copy a documented workflow and receive scan artifacts

### Cost outlook

Expected to remain $0 at low usage under included GitHub quotas. Document actual usage before enabling high-frequency or multi-architecture builds.

---

## Sprint 5 — Private Registry and ECR Support

### Goal

Scan authenticated images without embedding credentials in secscan artifacts or logs.

### Planned implementation

- Docker credential/helper compatibility
- Amazon ECR authentication path
- credential redaction tests
- registry timeout and retry handling
- digest-first target identity

### Acceptance criteria

- private ECR image can be scanned using temporary AWS credentials
- secrets are not present in logs or reports
- target digest is retained even when a mutable tag is supplied

### Cost outlook

- secscan adds no mandatory AWS service
- ECR storage and data transfer depend on the user's existing usage
- optional CI runners may add cost at scale

---

## Sprint 6 — Scan History and Comparison

### Goal

Persist scan metadata and show what is new, resolved, or unchanged between scans.

### Planned implementation

- storage abstraction
- initial local SQLite implementation
- scan identity and target history
- finding fingerprint strategy
- baseline comparison command
- retention configuration

### Acceptance criteria

- repeated scans of the same digest do not create ambiguous duplicate identities
- reports classify new, resolved, and persistent findings
- local operation remains possible without cloud services

---

## Sprint 7 — Service Mode and API

### Goal

Offer secscan as a long-running service while retaining the standalone CLI.

### Planned implementation

- REST API for submitting and retrieving scans
- background job execution
- health and readiness endpoints
- bounded concurrency and resource limits
- PostgreSQL storage option
- authentication design spike

### Acceptance criteria

- service can queue and execute scans without blocking request handling
- job and scanner failures are observable
- standalone CLI behavior remains supported

### Cost outlook

Local Docker Compose remains $0 beyond host resources. AWS deployment costs will be modeled before implementation, including minimum, expected, and growth scenarios.

---

## Sprint 8 — AWS Asset Discovery

### Goal

Discover approved AWS container assets and schedule scans without attempting full Inspector parity.

### Planned implementation

- AWS account and region configuration
- ECR repository/image discovery
- least-privilege IAM policy documentation
- EventBridge or scheduled discovery design
- account/region/registry metadata in target identity
- cost model before provisioning

### Acceptance criteria

- secscan can list and selectively scan ECR images in configured accounts and regions
- IAM permissions are documented and testable
- no resources are deployed without explicit configuration

---

## Sprint 9 — Continuous Rescanning and Notifications

### Goal

Re-evaluate relevant assets as vulnerability intelligence changes and surface meaningful deltas.

### Planned implementation

- scheduler and rescan policy
- vulnerability database freshness tracking
- event-driven and periodic rescan comparison
- notification adapters
- deduplication and noise controls

### Acceptance criteria

- an unchanged image can produce a new finding when vulnerability data changes
- duplicate notifications are suppressed
- notification content identifies the actionable change

---

## Sprint 10 — Exposure Context and Risk Prioritization

### Goal

Add AWS context that helps prioritize findings rather than merely ranking CVSS severity.

### Planned implementation

- research spike for VPC, security group, load balancer, and public exposure relationships
- exposure evidence model
- configurable contextual score
- transparent explanation of score inputs
- initial EC2/ECS/EKS scope decision

### Acceptance criteria

- contextual scores are reproducible and explainable
- raw severity remains visible and is never silently replaced
- unavailable context is represented as unknown rather than assumed safe

---

## Future epics

- additional scanning engines such as Syft/Grype
- EC2 inventory or snapshot-based scanning
- ECS and EKS workload association
- web dashboard and multi-user access
- organization-wide delegated administration
- exploit intelligence enrichment
- remediation workflow integrations
- signed policy bundles and enterprise governance

## Backlog rules

The roadmap is directional. A future sprint is not considered committed until sprint planning confirms its stories, acceptance criteria, dependencies, security review, and projected operating costs.
