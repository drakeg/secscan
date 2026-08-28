# Sprint 56 — Additional Scanner Adapters

## Goal

Add one complementary open-source vulnerability engine without replacing the existing Trivy path or inflating a single scan with duplicate findings from multiple engines.

## Scope

This sprint adds a dedicated `image-grype` CLI scanner backed by a pinned Grype executable in the secscan container.

The adapter:

- accepts one container image reference through the normal secscan scanner interface
- invokes Grype with a fixed JSON-output command rather than exposing arbitrary engine flags
- normalizes Grype vulnerability matches into secscan-owned `Finding` records
- preserves the raw Grype JSON as `grype.json`
- participates in normal secscan policy, baseline, history, JSON, and HTML reporting through the existing CLI pipeline
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

- Grype is pinned in the Docker build rather than downloaded at runtime.
- The adapter constructs a fixed argv list and does not invoke a shell.
- Engine output is parsed as JSON and rejected if it is malformed or has an unexpected top-level type.
- Unknown Grype severities fail closed to secscan `UNKNOWN`.
- Grype failures and timeouts fail the scan rather than returning partial success.
- No credentials, registry tokens, arbitrary Grype flags, or database-update controls are added by this sprint.

## Cost

Current and projected recurring secscan service cost remains **$0**. Grype is open source and runs inside the existing local/container execution model.

## Acceptance criteria

- `secscan scan image-grype <image>` is exposed through the scanner registry.
- Grype findings normalize into secscan findings with vulnerability ID, package, installed/fixed versions, severity, target, package type, and advisory URL when present.
- Raw engine evidence uses `grype.json` rather than masquerading as Trivy output.
- Unit tests cover normalization, unknown-severity handling, fixed command construction, and the deliberate lack of SBOM generation.
- Wheel verification requires the adapter module.
- Docker builds a pinned Grype version and verifies it during image construction.
- Python 3.12/3.14 quality/package checks, Docker/Compose smoke, Trivy self-scan, CodeQL workflow, and the separate GitHub Advanced Security CodeQL check are green before the PR is marked ready.
