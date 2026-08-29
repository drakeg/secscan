# Sprint 56 — Additional Scanner Adapters

## Goal

Add one complementary open-source vulnerability engine without replacing the existing Trivy path or inflating a single scan with duplicate findings from multiple engines.

## Scope

This sprint adds a dedicated `image-grype` CLI scanner backed by pinned Grype `v0.116.1` from Anchore's published container image.

The adapter:

- accepts one container image reference through the normal secscan scanner interface
- invokes Grype with a fixed JSON-output command rather than exposing arbitrary engine flags
- normalizes Grype vulnerability matches into secscan-owned `Finding` records
- preserves the raw Grype JSON as `grype.json`
- reuses secscan's existing Trivy CycloneDX generator so the normal scan artifact/history contract remains complete
- participates in normal secscan policy, baseline, history, JSON, HTML, and SBOM reporting through the existing CLI pipeline
- remains a separate scanner identity from the existing Trivy-backed `image` scanner

Keeping Grype separate is intentional. It lets operators compare engines or choose independent coverage without silently double-counting overlapping Trivy and Grype results in one report.

## Out of scope

- replacing Trivy
- merging Trivy and Grype findings into one deduplicated multi-engine image report
- service/browser submission for `image-grype`
- Grype database mirroring or offline database lifecycle management
- Syft integration; secscan already has Trivy-based SBOM generation and a dedicated SBOM ingestion path, so adding Syft in the same increment would not provide enough independent value to justify the extra image/build surface
- paid services or recurring infrastructure

## Security and correctness boundaries

- Grype `v0.116.1` is pinned as a Docker build stage rather than downloaded at runtime or compiled ad hoc in the final image.
- The adapter constructs a fixed argv list and does not invoke a shell.
- Engine output is parsed as JSON and rejected if it is malformed or has an unexpected top-level type.
- Unknown Grype severities fail closed to secscan `UNKNOWN`.
- Grype failures and timeouts fail the scan rather than returning partial success.
- No credentials, registry tokens, arbitrary Grype flags, or database-update controls are added by this sprint.
- Scanner-specific raw artifact names are honored by the CLI; Grype evidence is written as `grype.json` rather than `trivy.json`.

## CI security repair

The first container self-scan correctly rejected Grype `v0.104.1` because that binary embedded `google.golang.org/grpc v1.74.0`, affected by CRITICAL `CVE-2026-33186` and fixed in grpc `1.79.3`.

The security gate was not weakened or suppressed. The branch was repaired by moving to Grype `v0.116.1`, whose module graph uses `google.golang.org/grpc v1.82.1`. The Docker build now copies the published Anchore binary from the versioned Grype image instead of compiling Grype from source, which also avoids the expensive Go compilation stage in CI.

## Cost

Current and projected recurring secscan service cost remains **$0**. Grype is open source and runs inside the existing local/container execution model.

## Acceptance criteria

- `secscan scan image-grype <image>` is exposed through the scanner registry.
- Grype findings normalize into secscan findings with vulnerability ID, package, installed/fixed versions, severity, target, package type, and advisory URL when present.
- Raw engine evidence uses `grype.json` rather than masquerading as Trivy output.
- The normal scan pipeline produces its CycloneDX SBOM for `image-grype` using the existing Trivy SBOM generator.
- Unit tests cover normalization, unknown-severity handling, fixed command construction, raw artifact identity, and SBOM integration.
- Wheel verification requires the adapter module.
- Docker uses pinned Grype `v0.116.1` and verifies it during image construction.
- Python 3.12/3.14 quality/package checks, Docker/Compose smoke, Trivy self-scan, CodeQL workflow, and the separate GitHub Advanced Security CodeQL check are green before the PR is marked ready.
