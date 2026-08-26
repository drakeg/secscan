# Sprint 38 — Fast Local Builds and CI

## Goal

Reduce normal Docker Compose and GitHub CI iteration time without weakening secscan's scanner pinning, security gates, deterministic validation, local-first operation, or $0 recurring-cost baseline.

## Measured baseline

The Sprint 37 container CI job took about 5 minutes 46 seconds. The main Docker build consumed about 4 minutes 52 seconds because CI explicitly used `docker build --no-cache`. The largest repeated work was building Nuclei and its pinned template corpus (about 3 minutes 28 seconds), building Gitleaks (about 42 seconds), and installing runtime scanner dependencies including Semgrep and Checkov (about 51 seconds). The final Trivy self-scan also downloads its vulnerability database on every run.

Open `agent/**` pull requests currently trigger the same CI workflow once for the branch push and again for the pull request, doubling CI consumption for the same commit.

## User stories

1. As a developer, an application-only change should reuse expensive scanner/tool layers during `docker compose up --build --wait` instead of rebuilding Nuclei, Gitleaks, Semgrep, and Checkov unnecessarily.
2. As a maintainer, pull-request validation should run once per commit rather than duplicating the same CI suite for both branch push and pull-request events.
3. As a maintainer, GitHub-hosted CI should reuse safe BuildKit and Python dependency caches while preserving the complete validation gates.
4. As a security reviewer, the final container must still receive a fresh bounded vulnerability gate and no security test may be removed merely to improve elapsed time.

## Planned implementation

- stop forcing `--no-cache` for the ordinary PR container build
- use Docker Buildx with GitHub Actions cache import/export for reusable pinned tool layers
- add BuildKit cache mounts for expensive Go and pip dependency/build caches where they do not alter produced artifacts
- keep scanner versions and Nuclei template commit pinning unchanged
- run normal CI on pull requests and pushes to `main`, eliminating duplicate `agent/**` push validation while a PR is open
- enable pip dependency caching for the Python 3.12/3.14 validation matrix without reducing version coverage
- constrain the final Trivy image gate to vulnerability scanning, since that gate specifically rejects fixable CRITICAL vulnerabilities
- cache Trivy's vulnerability database with a bounded freshness key if it can be done without accepting indefinitely stale vulnerability data
- preserve `docker compose up --build --wait` as the supported local workflow and document warm-versus-cold build expectations

## Acceptance criteria

- normal PR CI does not deliberately invalidate Docker's build cache
- the same PR commit does not run duplicate full CI suites solely because it was both pushed to an `agent/**` branch and associated with a pull request
- expensive pinned scanner layers are reusable when their inputs do not change
- Python 3.12 and 3.14 validation remains present
- container CLI startup, Compose configuration, service health, authenticated Linux-host fixture, and fixable-critical container vulnerability gates remain present
- the vulnerability self-scan explicitly scans vulnerabilities rather than performing unrelated secret scanning of the built image
- a deliberate clean-build path remains documented for troubleshooting/release-quality verification
- `docker compose up --build --wait` remains valid and localhost remains the default service binding
- focused tests, `git diff --check`, full `bash scripts/preflight.sh`, applicable Docker/Compose validation, GitHub CI, and CodeQL pass before merge
- current and projected recurring secscan infrastructure/service cost remains $0; GitHub cache usage remains within the repository's existing GitHub Actions allowance

## Security and operational boundaries

- no scanner/version/template pin is loosened for speed
- no test or security gate is removed merely to reduce runtime
- cached data is treated as an optimization, not a source of authority; cache misses must still produce correct builds
- vulnerability database caching must have an explicit freshness boundary
- release builds retain their existing provenance, digest, multi-architecture, SBOM, and guarded publication controls
- no third-party hosted build/cache service or paid dependency is introduced

## Validation plan

Compare a cold run with a subsequent app-only or documentation-only run. Record the container build duration and whether expensive scanner stages are cache hits. Verify one CI workflow is associated with each PR commit, Python 3.12/3.14 preflight still passes, Compose service/SSH-fixture smoke tests pass, the image vulnerability gate passes, and CodeQL passes.

## Cost outlook

The implementation uses GitHub Actions/BuildKit caching already available to the repository and local Docker cache. Current and projected recurring secscan infrastructure/service cost remains **$0**. Cache retention and eviction remain subject to GitHub's existing Actions cache quotas and policies.

## Out of scope

- changing scanner functionality or adding new scanner engines
- replacing pinned scanner builds with unverified binaries
- removing Python-version coverage, container smoke tests, CodeQL, or vulnerability enforcement
- changing release publication behavior
- paid build runners, remote builders, commercial caches, or cloud infrastructure
