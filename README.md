# secscan

`secscan` is an open-source, container-first security scanner intended to provide a practical subset of Amazon Inspector-style capabilities using open-source scanning engines and a project-owned normalization, policy, and reporting layer.

## Product vision

Start with a portable Docker image that can scan a container image or mounted filesystem and produce:

- CycloneDX SBOM output
- normalized JSON vulnerability findings
- a readable HTML report
- CI-compatible exit codes based on policy

The project will then grow incrementally toward registry integration, scan history, AWS asset discovery, continuous rescanning, exposure context, and risk prioritization.

## Current status

The project is in **Sprint 0 — Foundation and Planning**. No production scanner has been released yet.

## Planned command experience

```bash
# Scan a container image
secscan scan image nginx:latest --output /reports

# Scan a mounted filesystem
secscan scan filesystem /scan --output /reports

# Generate an SBOM without vulnerability evaluation
secscan sbom image nginx:latest --format cyclonedx

# Fail CI when findings violate policy
secscan scan image nginx:latest --fail-on critical
```

## Documentation

- [Agile delivery model](docs/AGILE.md)
- [Product roadmap and sprint plans](docs/ROADMAP.md)
- [Initial architecture](docs/ARCHITECTURE.md)
- [Definition of done](docs/DEFINITION_OF_DONE.md)

## Initial technical direction

The first implementation will use Trivy as the scanning engine while translating its output into a stable, project-owned finding model. This keeps the first release small while preserving the option to add or replace engines such as Syft and Grype later.

## Repository workflow

- `main` remains releasable.
- Work is performed on focused feature branches.
- Changes are merged through pull requests.
- Each sprint ends with demonstrable, documented functionality.

## License

A project license has not yet been selected. License selection is an explicit Sprint 0 decision and must be completed before the first public release.
