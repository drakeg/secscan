# Repository Scanning Sprint

## Goal

Add a built-in repository scanner that reuses the existing plugin, normalization, reporting, policy, baseline, and history pipelines.

## Acceptance criteria

- `secscan scan repository <path>` scans a readable local directory.
- Missing paths and non-directory targets fail with exit code `1`.
- Repository findings use the normalized secscan schema.
- Existing report, SBOM, policy, baseline, history, and exit-code behavior remains available.
- Repository source is expected to be mounted read-only in Docker.
- Wheel, clean-install, container, CI, and CodeQL checks include the new scanner module.

## Out of scope

- Cloning remote repository URLs
- Git credentials or SSH keys
- Branch or commit selection
- Private repository authentication
- Commit metadata capture
- Secret-scanning policy extensions

## Cost outlook

Current and projected recurring infrastructure cost remains **$0**. Repository scanning is local and introduces no cloud resources or paid dependencies.
