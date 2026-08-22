# Release Artifacts

The guarded tag-driven GitHub Release workflow publishes Python artifacts and one verifiable Linux/AMD64 container image. A successful release contains:

- the secscan wheel
- the Python source distribution
- `SHA256SUMS` covering both artifacts
- `CONTAINER_IMAGE` containing the immutable GHCR `name@sha256:digest` reference
- generated GitHub release notes

The same workflow publishes the image under the exact version tag without the leading `v` and attaches GitHub build provenance to its registry digest. It does not publish `latest`, major, minor, branch, or pull-request aliases. Multi-architecture publication, Docker Hub, PyPI, deployment, and key-managed signing remain out of scope.

## Release guard

The workflow accepts only an exact stable tag in `vMAJOR.MINOR.PATCH` form, such as `v0.1.0`. The version after `v` must exactly equal `[project].version` in `pyproject.toml`. Prerelease suffixes, build metadata, leading-zero versions, and mismatches fail before release creation.

The workflow then:

1. checks out the tagged commit
2. installs the existing development dependencies
3. validates the tag/version pair
4. runs the complete repository preflight
5. builds a wheel and source distribution in `release-dist`
6. verifies wheel contents
7. writes deterministic SHA-256 checksums
8. logs in to GHCR with the workflow token
9. builds and pushes the exact-version Linux/AMD64 image with OCI labels
10. writes its fully qualified digest reference to `CONTAINER_IMAGE`
11. generates GitHub build provenance for that same image digest and pushes it to GHCR
12. creates the GitHub Release and uploads the Python artifacts, checksums, and container reference

The workflow defaults to `contents: read`; only the release job receives `contents: write`, `packages: write`, `id-token: write`, and `attestations: write`. GHCR authentication uses the ephemeral workflow token and does not require a repository secret. GitHub currently documents Container registry storage and bandwidth as free; repository owners should still retain a zero-dollar Packages budget and review GitHub's billing policy before each release because hosted-service terms can change.

## Local dry run

From a clean checkout with development dependencies installed:

```bash
python scripts/release_artifacts.py verify-tag v0.1.0 pyproject.toml
bash scripts/preflight.sh
python -m build --sdist --wheel --outdir release-dist
python scripts/verify_wheel.py release-dist/secscan-*.whl
python scripts/release_artifacts.py checksums release-dist/SHA256SUMS release-dist/secscan-*.whl release-dist/secscan-*.tar.gz
docker build --build-arg SECSCAN_VERSION=0.1.0 --tag secscan-release-test:0.1.0 .
docker run --rm secscan-release-test:0.1.0 --version
```

Replace `v0.1.0` with the intended tag. Inspect the manifest:

```bash
cat release-dist/SHA256SUMS
```

Run the release-tool unit and failure-path tests independently:

```bash
pytest tests/test_release_artifacts.py
pytest tests/test_release_workflow.py
```

## Publish procedure

1. Update `project.version` in a reviewed pull request.
2. Merge only after branch CI and CodeQL pass.
3. Confirm `main` is clean and the intended commit is checked out.
4. Run the local dry run using the intended version tag.
5. Create an annotated tag without moving or reusing an existing release tag:

```bash
git tag -a v0.1.0 -m "secscan v0.1.0"
git push origin v0.1.0
```

The tag push starts the Release workflow. No GitHub Release is created if tag validation, preflight, Python packaging, container publication, digest recording, or provenance generation fails.

## Post-release verification

Download the wheel, source archive, and `SHA256SUMS` into one directory. On Linux:

```bash
sha256sum --check SHA256SUMS
```

On macOS:

```bash
shasum -a 256 --check SHA256SUMS
```

Both artifact lines must report `OK`. Also install the wheel in a disposable environment and verify startup:

```bash
python -m venv /tmp/secscan-release-test
/tmp/secscan-release-test/bin/pip install ./secscan-*.whl
/tmp/secscan-release-test/bin/secscan --version
```

Inspect `CONTAINER_IMAGE`; it must contain one fully qualified digest reference, for example `ghcr.io/drakeg/secscan@sha256:...`. Pull and smoke-test that immutable reference rather than relying on the version tag:

```bash
container_image=$(cat CONTAINER_IMAGE)
docker pull "$container_image"
docker run --rm "$container_image" --version
docker inspect --format '{{index .RepoDigests 0}}' "$container_image"
gh attestation verify "oci://$container_image" --repo drakeg/secscan
```

Confirm the reported repository digest matches `CONTAINER_IMAGE` and GitHub verifies the attestation against this repository. If the package is private, authenticate to GHCR with a token that has read-package access before pulling.

## Failure and recovery

- If validation fails, correct the project version or choose the correct new tag. Do not move a published release tag.
- If packaging fails before release creation, fix the repository through a pull request, increment the version when appropriate, and create a new tag.
- If container publication or attestation fails, inspect the workflow before retrying; do not create or move another tag while the original run is recoverable.
- If the final GitHub Release command fails after publication, inspect the workflow and registry first. Confirm whether the image, attestation, or release already exists before rerunning the failed job.
- Never overwrite release assets silently. Treat a published tag and its checksums as immutable.

GitHub-hosted release automation introduces no secscan runtime infrastructure. Repository owners remain responsible for GitHub Actions, Packages, storage, transfer, release, and attestation limits that apply to their account.
