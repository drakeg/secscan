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

A scanner returns raw traceability data, normalized findings, and scanner metadata. The report layer writes normalized JSON and HTML. CycloneDX generation is an engine-native scanner capability, but the caller chooses the destination and artifact name.

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

## Artifact contract

A successful image or filesystem scan produces:

- `trivy.json` — raw engine findings
- `secscan.json` — normalized findings plus policy evaluation metadata
- `secscan.cdx.json` — CycloneDX SBOM
- `secscan.html` — self-contained human-readable report

Artifact names and exit semantics remain stable.

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
- Python wheels are built and inspected
- CI actions are version-pinned
- release images are scanned
- future release work adds signatures, provenance, and immutable digests

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
