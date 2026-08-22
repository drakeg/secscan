# secscan

`secscan` is an open-source, container-first security scanner that uses scanner plugins and a Trivy adapter to normalize vulnerability findings into a stable secscan schema, write machine-readable and HTML reports, retain local scan history, and return CI-friendly policy exit codes.

Development is delivered incrementally using Agile sprints. See [`docs/ROADMAP.md`](docs/ROADMAP.md), [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), and [`docs/AGILE.md`](docs/AGILE.md).

## Build

```bash
docker build -t secscan:dev .
```

A successful scan creates four artifacts:

- `trivy.json` — raw Trivy vulnerability output
- `secscan.json` — normalized secscan findings and policy metadata
- `secscan.cdx.json` — generated CycloneDX JSON SBOM, or a preserved CycloneDX input

SPDX input scans preserve the input as `secscan.spdx.json` instead.
- `secscan.html` — self-contained browser report

A scan using `--baseline` also creates `secscan.diff.json`. Completed scans are recorded in `secscan.db` unless `--no-history` is supplied.

## AWS ECR discovery

Create a read-only inventory from explicitly approved accounts, regions, and repositories:

```bash
secscan discover ecr \
  --config ./aws-discovery.yaml \
  --output ./reports/ecr-assets.json
```

Discovery does not enumerate repositories, pull images, or start scans. See [AWS ECR Asset Discovery](docs/AWS_ECR_DISCOVERY.md) for configuration, least-privilege IAM, costs, and step-by-step local testing procedures.

Scan one exact digest from that inventory:

```bash
secscan scan ecr \
  '123456789012.dkr.ecr.us-east-1.amazonaws.com/platform/api@sha256:FULL_DIGEST' \
  --inventory ./reports/ecr-assets.json \
  --aws-config ./aws-discovery.yaml \
  --output-dir ./reports/ecr-scan \
  --fail-on HIGH
```

The image must still be approved by the AWS configuration. Temporary credentials are passed only to Trivy's child-process environment.

Run a sequential batch of up to 20 explicit immutable URIs:

```bash
secscan batch ecr \
  --image-uri 'COPY_FIRST_EXACT_IMAGE_URI' \
  --image-uri 'COPY_SECOND_EXACT_IMAGE_URI' \
  --inventory ./reports/ecr-assets.json \
  --aws-config ./aws-discovery.yaml \
  --output-root ./reports/ecr-batch \
  --fail-on HIGH
```

The output root must be empty. Each scan gets isolated artifacts, while `batch.json` and a shared `secscan.db` summarize the run. See [AWS ECR Discovery and Authenticated Scanning](docs/AWS_ECR_DISCOVERY.md) for exit-code behavior and local/live test procedures.

## Image scanning

```bash
docker volume create secscan-reports
docker volume create secscan-cache

docker run --rm \
  -v secscan-reports:/reports \
  -v secscan-cache:/cache \
  secscan:dev scan image alpine:3.20 \
    --output-dir /reports \
    --fail-on CRITICAL
```

## Filesystem scanning

Mount the target read-only. The scanner writes only to `/reports` and `/cache`:

```bash
docker run --rm \
  -v "$PWD:/scan:ro" \
  -v secscan-reports:/reports \
  -v secscan-cache:/cache \
  secscan:dev scan filesystem /scan \
    --output-dir /reports \
    --fail-on CRITICAL
```

For a local Python installation:

```bash
secscan scan filesystem . --output-dir ./reports --fail-on HIGH
```

## Repository scanning

Scan a checked-out source repository with Trivy repository mode:

```bash
secscan scan repository . --output-dir ./reports --fail-on HIGH
```

Remote public repositories can be scanned directly with an HTTPS Git URL:

```bash
secscan scan repository https://github.com/example/project.git \
  --output-dir ./reports \
  --fail-on HIGH
```

Private `github.com` repositories use the server-side `SECSCAN_GITHUB_TOKEN` environment variable. Keep the scan target credential-free:

```bash
export SECSCAN_GITHUB_TOKEN='github_pat_your_token_here'
secscan scan repository https://github.com/example/private-project.git \
  --output-dir ./reports \
  --fail-on HIGH
unset SECSCAN_GITHUB_TOKEN
```

For Docker Compose, copy `.env.example` to `.env` and set `SECSCAN_GITHUB_TOKEN` there. Prefer a fine-grained GitHub token with **Contents: Read-only** access scoped only to the repositories secscan needs. Never place a token in the repository URL or commit a populated `.env` file.

With Docker, local repositories remain read-only mounts:

```bash
docker run --rm \
  -v "$PWD:/repo:ro" \
  -v secscan-reports:/reports \
  -v secscan-cache:/cache \
  secscan:dev scan repository /repo \
    --output-dir /reports \
    --fail-on HIGH
```

See [Repository Scanning](docs/REPOSITORY_SCANNING.md) for remote-clone behavior and [GitHub Repository Authentication](docs/GITHUB_AUTH.md) for token setup, permissions, Docker Compose/CLI usage, security details, and troubleshooting.

## Network assessment

Assess one hostname or IP address that you own or are explicitly authorized to test:

```bash
docker compose --profile tools run --rm cli \
  scan network AUTHORIZED_HOSTNAME_OR_IP \
  --output-dir /reports/network-compose \
  --fail-on NONE
```

The image bundles pinned Nmap and Nuclei versions plus an official Nuclei template release bound to a reviewed full Git commit; scans do not install or update templates at runtime. URLs, CIDRs, target lists, arbitrary scanner flags, and web/API network submissions are not supported. See [Network Scanning](docs/NETWORK_SCANNING.md) for provenance, safety boundaries, and local validation.

## SBOM scanning

Scan an existing CycloneDX or SPDX 2.2/2.3 JSON SBOM:

```bash
secscan scan sbom build.cdx.json \
  --output-dir ./reports \
  --fail-on HIGH
```

With Docker, mount the SBOM read-only:

```bash
docker run --rm \
  -v "$PWD/build.cdx.json:/input/build.cdx.json:ro" \
  -v secscan-reports:/reports \
  -v secscan-cache:/cache \
  secscan:dev scan sbom /input/build.cdx.json \
    --output-dir /reports \
    --fail-on HIGH
```

The validated input is preserved byte-for-byte as `secscan.cdx.json` or `secscan.spdx.json`, according to its format. See [SBOM Scanning](docs/SBOM_SCANNING.md) for validation rules and automated/manual local test procedures.

Extract a deterministic package and declared-license inventory without invoking Trivy:

```bash
secscan inventory sbom build.spdx.json \
  --output ./reports/secscan.inventory.json
```

The inventory retains source-declared license strings and package PURLs but does not make license-compliance judgments.

Compare two normalized inventory snapshots:

```bash
secscan compare inventory \
  ./baseline/secscan.inventory.json \
  ./current/secscan.inventory.json \
  --output ./reports/secscan.inventory.diff.json
```

Comparison reports added, removed, declared-license-changed, and unchanged packages. Differences are informational; malformed or ambiguous inventories return an operational error. See [SBOM Scanning](docs/SBOM_SCANNING.md) for identity rules and local test procedures.

Evaluate exact source-declared license strings against a local policy:

```bash
secscan check inventory ./reports/secscan.inventory.json \
  --policy ./license-policy.yaml \
  --output ./reports/secscan.inventory.policy.json
```

A policy violation returns exit code `2`; invalid policy or inventory input returns `1`. Auditable expiring exceptions can suppress one exact package/license violation. License expressions remain opaque strings, and the result is policy evidence rather than a legal-compliance determination. See [Policy Configuration](docs/POLICIES.md) for the schema and local testing procedures.

## YAML policies

A policy can define the default threshold and temporary, auditable suppressions:

```yaml
policy:
  fail_on: HIGH

suppressions:
  - vulnerability: CVE-2026-12345
    package: openssl
    reason: Vendor patch is scheduled
    expires: 2026-09-30
```

Run it with any scanner:

```bash
secscan scan image alpine:3.20 --policy policy.yaml
secscan scan filesystem . --policy policy.yaml
secscan scan repository . --policy policy.yaml
secscan scan sbom build.cdx.json --policy policy.yaml
```

An explicitly supplied `--fail-on` overrides the policy threshold. Active suppressions are applied before exit-code evaluation, expired suppressions are ignored, and suppression details remain visible in `secscan.json`. See [Policy Configuration](docs/POLICIES.md).

## Baseline comparison

Compare a current scan against a previous normalized report:

```bash
secscan scan image alpine:3.20 \
  --baseline previous/secscan.json \
  --output-dir reports
```

`secscan.diff.json` classifies findings as `new`, `resolved`, or `unchanged` using a stable fingerprint based on vulnerability ID, package, target, and package type. Comparison is informational and does not change the existing policy exit code. See [Finding Baselines](docs/BASELINES.md).

## Local scan history

Successful scans are recorded after report and SBOM generation completes. For scan commands, the default database is `<output-dir>/secscan.db`.

```bash
secscan history --history-db ./reports/secscan.db
secscan show 1 --history-db ./reports/secscan.db
secscan trends --history-db ./reports/secscan.db --scanner image --target alpine:3.20
secscan finding-changes --history-db ./reports/secscan.db --scanner image --target alpine:3.20
secscan finding-timing --history-db ./reports/secscan.db --scanner image --target alpine:3.20 --limit 20
```

Use an explicit database path when needed:

```bash
secscan scan image alpine:3.20 \
  --output-dir ./reports \
  --history-db ./state/secscan.db
```

`trends` summarizes aggregate changes; `finding-changes` classifies the latest stable fingerprints; `finding-timing` summarizes bounded observed episodes while excluding censored/open data from its mean. Each can write versioned JSON with `--output`. Skip recording with `--no-history`. See [Local Scan History](docs/HISTORY.md) for interpretation, migration behavior, limitations, and automated/manual testing procedures.

## Copy reports from a rootless Docker volume

```bash
mkdir -p reports

docker run --rm \
  -v secscan-reports:/source:ro \
  -v "$PWD/reports:/destination" \
  alpine:3.20 \
  sh -c 'cp /source/* /destination/'
```

Open `reports/secscan.html` in a browser to review the vulnerability report.

## Exit codes

- `0`: scan or history/trend command completed successfully and policy passed
- `1`: scanner, policy, baseline, history, target, input, registry, or output error
- `2`: scan completed but active findings met or exceeded the effective threshold

The vulnerability database cache is stored under `/cache` and should be persisted between scans.

## Python support

- Minimum supported Python: 3.12
- Container runtime: Python 3.14
- CI validates both Python 3.12 and 3.14

## Local development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
ruff check .
mypy
pytest
secscan --help
```

## Docker Compose local service

Build and start a healthy local API with persistent reports, job metadata, and scanner cache:

```bash
cp .env.example .env
# Optional for private github.com repositories:
# SECSCAN_GITHUB_TOKEN=github_pat_your_token_here

docker compose up --build --wait
curl --fail http://127.0.0.1:8000/healthz
```

The stack is localhost-only by default, non-root, capability-free, and mounts this repository read-only at `/workspace` for filesystem/repository/SBOM testing. Service-controlled local paths are limited to that mount, executed jobs provide discoverable SHA-256 artifact manifests and conditional downloads, and optional environment variables can protect API access, authenticate private GitHub clones, and deliberately bind to a trusted private-LAN address. See [Web GUI](docs/WEB_UI.md), [GitHub Repository Authentication](docs/GITHUB_AUTH.md), and [Service Mode](docs/SERVICE_MODE.md) for configuration, LAN security boundaries, and host/second-device testing procedures.

## Releases

Stable `vMAJOR.MINOR.PATCH` tags trigger guarded GitHub release packaging when the tag exactly matches `project.version`. Releases include a verified wheel, source distribution, `SHA256SUMS`, and a Linux/AMD64 GHCR image with an immutable digest record and GitHub build provenance. See [Release Artifacts](docs/RELEASES.md) for local dry-run, publication, digest-pinned container and attestation verification, and failure-recovery procedures.

## Current boundaries

The built-in scanners support public and explicitly inventoried ECR container images, including bounded sequential batches, plus local filesystem paths, local/remote source repositories, and CycloneDX or SPDX 2.2/2.3 JSON SBOM files. Public HTTPS GitHub, GitLab, Azure DevOps, and compatible Git repositories can be scanned remotely; private `github.com` repositories can use server-side `SECSCAN_GITHUB_TOKEN` authentication. Private GitLab/Azure DevOps authentication and provider OAuth/App integrations remain later increments. Supported SBOMs can produce, compare, and apply exact declared-license policy to local normalized inventories. YAML scan policies support severity thresholds and expiring vulnerability suppressions. Baseline comparison classifies current and previous findings. Local SQLite stores scan history, supports exact-cohort severity trends, and persists service job metadata. AWS discovery inventories explicitly approved ECR repositories. Richer license governance, dependency-graph analysis, scheduled AWS scanning, tenant credential storage, and contextual risk scoring remain later increments.

## Security notes

- Container image scanning does not require mounting the Docker socket.
- Filesystem, repository, and SBOM targets, policy files, and baseline files should be mounted read-only.
- Never put Git credentials in repository URLs; use server-side provider configuration such as `SECSCAN_GITHUB_TOKEN`.
- Keep `.env` out of source control and use narrowly scoped, read-only GitHub credentials.
- Suppressions require a reason and expiration date.
- Baseline, comparison, history, SBOM, and report artifacts should be treated as security-sensitive inventory.
- The secscan image defaults to non-root UID `10001`.
- Rootless Docker users should use Docker-managed named volumes for `/reports` and `/cache`.
- Do not use `--privileged`, disable SELinux, or make project directories permanently world-writable.

## Documentation

- [Agile delivery model](docs/AGILE.md)
- [Product roadmap and sprint plans](docs/ROADMAP.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Policy configuration](docs/POLICIES.md)
- [Finding baselines](docs/BASELINES.md)
- [Local scan history](docs/HISTORY.md)
- [AWS ECR asset discovery and local testing](docs/AWS_ECR_DISCOVERY.md)
- [Repository scanning](docs/REPOSITORY_SCANNING.md)
- [GitHub repository authentication](docs/GITHUB_AUTH.md)
- [Web GUI and Docker Compose testing](docs/WEB_UI.md)
- [Agentless network assessment and local testing](docs/NETWORK_SCANNING.md)
- [SBOM scanning](docs/SBOM_SCANNING.md)
- [Release artifacts and testing](docs/RELEASES.md)
- [Service mode and REST API](docs/SERVICE_MODE.md)
- [Definition of done](docs/DEFINITION_OF_DONE.md)

## License

A project license has not yet been selected. Until one is added, normal copyright restrictions apply.
