# Releases and Semantic Versioning

This is the root release-policy entrypoint for secscan. Detailed build, SBOM, immutable GHCR image publication, validation, recovery and rollback instructions remain in [docs/RELEASES.md](docs/RELEASES.md). Do not replace or bypass those safeguards.

## Version classes

- **MAJOR:** incompatible CLI, API, report schema or persisted-data behavior requiring consumer migration.
- **MINOR:** backward-compatible features such as additional scanners, authorized APIs or report capabilities.
- **PATCH:** backwards-compatible correctness fixes, dependency/security upgrades, or documentation adjustments when a release is warranted.

Before 1.0, document any breaking change explicitly and explain migration impact. `pyproject.toml` currently declares `0.1.0`; this is not proof of a published release.

## Release readiness

A release requires meaningful customer/operator value, reviewed PRs, passing required CI/CodeQL, reproducible test evidence, updated README badges/documentation, security review, release notes and a correct version tag. Do **not** release merely because a sprint finishes or a PR merges. The guarded `.github/workflows/release.yml` publishes only on an exact matching `vMAJOR.MINOR.PATCH` tag and checks the declared project version.

No latest published GitHub Release was found during the 2026-11-19 audit. Do not display a latest-release badge until one is verified. Never fabricate the success of a release pipeline. Follow [docs/RELEASES.md](docs/RELEASES.md) for detailed procedure and rollback.
