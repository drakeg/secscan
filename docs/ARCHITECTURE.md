# secscan Architecture

## Purpose

This document is the living technical blueprint for secscan. It records current boundaries, data flow, module ownership, validation expectations, and the intended evolution from a standalone scanner into a portable vulnerability-management platform.

## Architectural objectives

- Run as a self-contained, non-root Docker image.
- Support rootful and rootless Docker without requiring privileged mode.
- Avoid the Docker socket for normal image and filesystem workflows.
- Keep target behavior in scanner plugins and engine behavior behind adapters.
- Own stable request, result, finding, and policy models.
- Produce deterministic artifacts for humans, CI systems, and future APIs.
- Preserve local, no-cloud operation as the baseline.
- Fail packaging, test, and container validation before merge.

## Current data flow

```text
CLI / future API / scheduled job
              |
              v
         ScanRequest
              |
              v
       ScannerRegistry
          /       \
         v         v
 ImageScanner   FilesystemScanner
         \         /
          v       v
         Trivy adapter
              |--------------------> raw Trivy JSON
              |--------------------> CycloneDX JSON SBOM
              v
          Normalizer
              |
              v
          ScanResult
              |
              +--------------------> normalized reports
              v
       YAML policy loader
              |
              v
       Policy evaluator
        /           \
       v             v
active findings   suppressed findings + audit metadata
       |
       +----------------------------> summary and exit code
```

The CLI owns argument parsing and presentation. Scanner plugins own target validation and orchestration. Engine adapters own subprocess details. Normalization, reporting, and policy remain project-level concerns.

## Repository layout

```text
secscan/
├── Dockerfile
├── pyproject.toml
├── README.md
├── secscan/
│   ├── cli.py
│   ├── models.py
│   ├── normalize.py
│   ├── policy.py
│   ├── report.py
│   ├── trivy.py
│   └── scanners/
│       ├── base.py
│       ├── registry.py
│       ├── image.py
│       └── filesystem.py
├── scripts/
│   └── verify_wheel.py
├── tests/
├── docs/
│   ├── POLICIES.md
│   └── ...
└── .github/
```

## Architectural rules

### Plugins never depend on the CLI

Scanner plugins accept `ScanRequest` values and return `ScanResult` values. They do not import argparse, print user-facing output, choose exit codes, or load policy files.

### Plugins never generate project reports

A scanner returns raw traceability data, normalized findings, and scanner metadata. The report layer writes normalized JSON and HTML. CycloneDX generation is an engine-native scanner capability. Scanner plugins choose the SBOM artifact name so native SPDX input can be preserved without mislabeling it as CycloneDX.

### Normalization is mandatory

Every scanner returns secscan-owned `Finding` objects. Policy and report code do not branch on Trivy or another engine-specific result shape.

### Tools are adapters

`ImageScanner` and `FilesystemScanner` are target plugins. Trivy is the initial engine adapter beneath both plugins. A future engine may replace or complement Trivy without changing the registry, policy layer, or report layer.

### Policy evaluation is scanner-neutral

Policies consume normalized findings after scanning. The same threshold and suppression rules apply to image and filesystem scans.

### Findings are never silently hidden

Suppressions remove findings only from policy-failure evaluation. The normalized report retains the complete finding set and adds policy metadata describing suppressed vulnerability IDs, package names, reasons, and expiration dates.

## Core contracts

### `ScanRequest`

An immutable request containing the scanner name, target reference or path, timeout, and optional output location.

### `ScanResult`

An immutable result containing the original request, normalized findings, raw engine payload, and scanner metadata.

### `Policy`

An immutable policy containing:

- default `fail_on` threshold
- ordered suppression rules

### `Suppression`

A rule containing an exact vulnerability ID, optional exact package name, required reason, and required expiration date.

### `PolicyEvaluation`

A deterministic partition of normalized findings into active and suppressed findings.

## Policy precedence and semantics

Threshold precedence is:

1. explicit CLI `--fail-on`
2. YAML `policy.fail_on`
3. built-in `CRITICAL`

For each finding, the first active matching suppression is used. Matching requires the exact vulnerability ID and, when configured, the exact package name. A rule is active through its expiration date and ignored afterward.

Malformed YAML, unsupported thresholds, missing reasons, missing expirations, and invalid dates are operational errors and return exit code `1`.

## Module responsibilities

### `cli.py`

- parse commands and options
- create `ScanRequest`
- resolve scanners through the registry
- load policies and apply CLI threshold overrides
- invoke reporting and policy using `ScanResult`
- translate results into documented exit codes

### `scanners/image.py`

Own container-image orchestration and delegate vulnerability and SBOM operations to the Trivy adapter.

### `scanners/filesystem.py`

Validate and resolve filesystem paths, delegate vulnerability and SBOM operations, and normalize results. The plugin does not modify the target.

### `trivy.py`

Invoke Trivy image and filesystem modes safely, capture raw JSON, generate CycloneDX output, enforce timeouts, and distinguish operational failure from discovered findings.

### `normalize.py`

Convert engine-specific output into stable `Finding` values and calculate severity summaries.

### `policy.py`

- safely load YAML with `safe_load`
- validate thresholds and suppression schema
- parse ISO expiration dates
- partition normalized findings into active and suppressed sets
- evaluate severity thresholds against active findings

### `report.py`

Write project artifacts from normalized data without rerunning or reinterpreting the scanner.

### `sbom_inventory.py`

Read an already supported local SBOM format and normalize source-declared package identity and license values. Inventory extraction is independent of Trivy, policy, reports, and SQLite. It does not infer effective licensing or compliance.

### `sbom_inventory_compare.py`

Strictly load two version 1 normalized inventory documents and classify exact package identities. PURLs take precedence; packages without PURLs fall back to exact name and version. Duplicate identities are rejected. Comparison is deterministic and informational and does not correlate version upgrades, vulnerabilities, or dependency graphs.

### `license_policy.py`

Strictly load local declared-license policy and evaluate a version 1 normalized inventory. Allow and deny entries match exact, case-sensitive source strings; expressions are opaque. Temporary exceptions match one exact PURL or name/version fallback identity plus one exact license, and require a reason and expiration. The evaluator emits deterministic violation and suppression evidence but does not interpret compatibility, obligations, or legal compliance.

## Artifact contract

A successful scan produces the applicable artifacts:

- `trivy.json` — raw engine findings
- `secscan.json` — normalized findings plus policy evaluation metadata
- `secscan.cdx.json` — CycloneDX SBOM
- `secscan.spdx.json` — preserved SPDX input for SPDX SBOM scans
- `secscan.html` — self-contained human-readable report

Artifact names and exit semantics remain stable.

`secscan inventory sbom` is a separate read-only projection. It writes `secscan.inventory.json` by default and does not create scan artifacts or history records.

`secscan compare inventory` reads two such projections and writes `secscan.inventory.diff.json`. It does not alter scan policy exit codes or persist state.

`secscan check inventory` writes `secscan.inventory.policy.json` and returns policy exit code `2` when violations exist. It shares the inventory validation boundary but remains separate from vulnerability scan policy and history.

## Exit-code contract

- `0` — scan completed and effective policy passed
- `1` — input, policy, scanner, artifact, registry, or internal operational failure
- `2` — scan completed successfully but active findings violated policy

A discovered or suppressed vulnerability is not the same as a broken scan.

## Packaging and CI contract

Every pull request validates:

```text
source modules and scanner subpackages
    -> Ruff, mypy, and pytest
    -> wheel build and manifest verification
    -> clean wheel installation and imports
    -> Docker image build and CLI startup
    -> fixable-critical self-scan
    -> CodeQL
```

Runtime dependencies such as the YAML parser must be installed from the wheel dependency metadata and verified through clean installation.

## Security boundaries

### Policy files

- load with the safe YAML loader
- treat malformed policy input as an operational failure
- mount policies read-only in containers
- do not allow executable expressions or arbitrary Python objects
- require auditable reasons and expiration dates for suppressions

### Filesystem targets

- mount container targets read-only with `:ro`
- write only to designated report and cache locations
- do not attempt privilege escalation or bypass host permissions
- handle raw scanner output as security-sensitive data

### Docker socket

Normal image and filesystem scanning do not require `/var/run/docker.sock`.

### Rootless Docker

Docker-managed named volumes are the supported path for report and cache persistence. The project does not require `0777`, `--privileged`, or disabling SELinux.

### Plugin loading

Only trusted built-in plugins are registered. Arbitrary plugin loading remains out of scope.

### Supply chain

- base images and scanner versions are pinned
- the container bundles a reviewed Nuclei template corpus bound to both a release tag and full Git commit SHA, fails closed if they differ, and disables runtime update checks
- Python wheels are built and inspected
- CI actions are version-pinned
- release images are scanned
- stable releases publish one exact-version Linux AMD64/ARM64 GHCR index, record its immutable digest, and attach GitHub build provenance

## Release artifact boundary

Stable version tags invoke a dedicated least-privilege workflow. A standard-library script verifies that the immutable tag name exactly matches `project.version` and creates a deterministic checksum manifest from explicit regular-file inputs. The workflow runs repository preflight, builds and verifies Python artifacts, publishes exactly Linux AMD64 and ARM64 variants as one exact-version GHCR index, records the fully qualified index digest as a release asset, attaches GitHub provenance to the same registry digest, and then creates the GitHub Release. The workflow publishes no mutable or architecture-specific aliases and grants package, identity-token, and attestation writes only to the release job. Key-managed signing, other architectures or registries, deployment, and package-index publication remain outside this boundary.

## Coding and design standards

- Python 3.12 is the current runtime baseline.
- Public functions and contracts use type annotations.
- New target integrations implement `Scanner`.
- New engines remain adapters beneath scanner plugins.
- New policy rules operate on normalized findings.
- Tests accompany new behavior and failure paths.
- Security and cost implications are documented in every sprint and PR.
- Unrelated files are not changed as part of a focused increment.

## Future service architecture

```text
API -> job queue -> scanner registry/workers -> normalized findings store
                              |                         |
                              v                         v
                         artifact store          comparison/risk engine
                                                         |
                                                         v
                                                  dashboard/alerts
```

Cloud components remain optional. Storage, queue, discovery, policy distribution, and notification integrations must retain local interfaces for development and small deployments.

### Local service job state

The service stores job metadata in SQLite and report artifacts in UUID-scoped directories. A submitted record is persisted before worker execution. After execution it atomically writes a versioned manifest of allow-listed regular artifacts with deterministic names, sizes, and SHA-256 digests before persisting terminal state. The API exposes that manifest as an artifact collection, maps recorded digests to strong ETags, and supports `HEAD` and conditional revalidation without adding a cache service. Terminal records survive restarts; non-terminal records found at startup are failed explicitly instead of being replayed. The API can cancel queued work, but it does not terminate running scanners.

The supported Docker Compose evaluation stack runs this service as the image's non-root user, binds the API to host loopback by default, drops all capabilities, makes the container root filesystem read-only, and mounts only named report/cache volumes plus the repository at read-only `/workspace`. Service and CLI default to the locally built `secscan:local` image but can share one explicitly configured release digest; the trusted-release procedure pulls first and disables builds so the selected digest cannot be replaced by checkout contents. The isolated network fixture always remains local. An explicit `SECSCAN_BIND_ADDRESS` override permits trusted-LAN evaluation without changing the container listener; non-loopback use requires operator-managed bearer authentication and firewall scoping and remains unsuitable for internet exposure. Service-side resolved-path validation limits local targets, policies, and baselines to `/workspace`; image references remain non-path inputs. A Python standard-library health check avoids adding runtime tools. Compose never mounts the Docker socket and introduces no separate database, queue, or cloud dependency.

Optional local bearer authentication protects API routes with one operator-supplied shared token while leaving `/healthz` and local API documentation public. The OpenAPI document advertises the bearer scheme for interactive local testing. The service validates token shape at startup and uses constant-time comparison. Compose passes the token through the container environment, not command arguments; local Docker administrators remain trusted. This is defense in depth for a localhost service, not user authorization, tenant isolation, TLS, or an internet-exposure boundary.

### AWS discovery boundary

AWS discovery is a read-only inventory adapter outside the scanner registry. Explicit YAML configuration bounds account, region, and ECR repository access. The adapter verifies same-account identities or assumes one exact cross-account role, then maps paginated `DescribeImages` metadata into a versioned local JSON artifact. Inventory discovery does not imply image authentication, pulling, or scanning.

Authenticated ECR scanning is an explicit bridge from one immutable inventory URI to the existing image scanner. The bridge revalidates the asset against configuration, prepares a minimal AWS child-process environment, and delegates to the standard scanner pipeline. Credentials do not enter command arguments, normalized models, reports, or history.

Bounded ECR batching is a sequential CLI orchestrator over that bridge. It validates 1–20 explicit URIs before execution, gives each scan an isolated digest-scoped artifact directory, shares one history database, and writes an aggregate manifest. It is not a scheduler, distributed queue, or implicit inventory selector.

Historical reports are read-only projections over scan history. Aggregate trends use a bounded exact cohort. History migration version 2 transactionally stores stable normalized finding fingerprints for new scans; legacy rows are explicitly marked as lacking observations. `finding-changes` compares the two latest finding-enabled records. `finding-timing` builds bounded presence episodes, marks oldest-window observations as left-censored, and measures only scan-to-scan observed resolution intervals. It does not claim exact first-seen, fix time, or authoritative MTTR.

The SBOM scanner recognizes CycloneDX JSON and SPDX 2.2/2.3 JSON from mutually exclusive top-level format markers. Both formats use the same Trivy SBOM vulnerability adapter and normalized pipeline. The validated source document is copied byte-for-byte to a format-specific constant artifact path; service downloads explicitly allow-list both names.

### Network assessment boundary

The network scanner accepts one resolvable hostname or IP address and invokes Nmap and Nuclei through fixed argument lists. The image pins the Nuclei binary and binds the official template release tag to one full reviewed Git commit SHA; the build fails if the tag resolves elsewhere. Nuclei receives the read-only bundled path explicitly with automatic update checks disabled. This makes the assessment corpus a fail-closed image-build dependency rather than mutable runtime state. Interactsh, CIDRs, target lists, arbitrary scanner arguments, and web/API submission remain outside this boundary. Network assessment actively connects to the supplied system and is only for targets the operator is authorized to test.
