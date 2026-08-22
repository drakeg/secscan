# Release Artifacts

The guarded tag-driven GitHub Release workflow publishes Python artifacts and one verifiable multi-architecture container image for Linux AMD64 and ARM64. A successful release contains:

- the secscan wheel
- the Python source distribution
- `SHA256SUMS` covering both artifacts
- `CONTAINER_IMAGE` containing the immutable GHCR `name@sha256:digest` reference
- generated GitHub release notes

The same workflow publishes one OCI image index under the exact version tag without the leading `v` and attaches GitHub build provenance to the index digest. The index contains exactly `linux/amd64` and `linux/arm64`. It does not publish `latest`, major, minor, branch, pull-request, or architecture-specific aliases. Additional architectures, Docker Hub, PyPI, deployment, and key-managed signing remain out of scope.

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
9. registers ARM64 emulation and builds the native AMD64 and emulated ARM64 variants with OCI labels
10. pushes both variants as one exact-version OCI index
11. writes the fully qualified index digest reference to `CONTAINER_IMAGE`
12. generates GitHub build provenance for that same index digest and pushes it to GHCR
13. creates the GitHub Release and uploads the Python artifacts, checksums, and container reference

The workflow defaults to `contents: read`; only the release job receives `contents: write`, `packages: write`, `id-token: write`, and `attestations: write`. GHCR authentication uses the ephemeral workflow token and does not require a repository secret. GitHub currently documents Container registry storage and bandwidth as free; repository owners should still retain a zero-dollar Packages budget and review GitHub's billing policy before each release because hosted-service terms can change.

## Local dry run

From a clean checkout with development dependencies installed:

```bash
python scripts/release_artifacts.py verify-tag v0.1.0 pyproject.toml
bash scripts/preflight.sh
python -m build --sdist --wheel --outdir release-dist
python scripts/verify_wheel.py release-dist/secscan-*.whl
python scripts/release_artifacts.py checksums release-dist/SHA256SUMS release-dist/secscan-*.whl release-dist/secscan-*.tar.gz
docker buildx build --load --platform "linux/$(docker info --format '{{.Architecture}}')" --build-arg SECSCAN_VERSION=0.1.0 --tag secscan-release-test:0.1.0 .
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

Inspect the release index and require both supported platforms beneath the recorded digest:

```bash
docker buildx imagetools inspect "$container_image"
docker pull --platform linux/amd64 "$container_image"
docker pull --platform linux/arm64 "$container_image"
```

The manifest output must list exactly `linux/amd64` and `linux/arm64` runtime manifests, apart from any registry-generated attestation descriptors. Run `docker run --rm "$container_image" --version` on one compatible AMD64 host and one compatible ARM64 host; each must select its native platform and report the release version.

### Run the immutable release with Compose

Copy the exact line from `CONTAINER_IMAGE` into the repository's `.env` file:

```dotenv
SECSCAN_IMAGE=ghcr.io/drakeg/secscan@sha256:REPLACE_WITH_RELEASE_DIGEST
```

If the package is private, log in to GHCR first without storing the token in `.env`. Then pull the selected digest and start Compose with local builds disabled:

```bash
docker compose pull service cli
docker compose up --no-build --wait
curl --fail http://127.0.0.1:8000/healthz
docker compose exec service secscan --version
docker compose run --rm --no-deps cli --version
```

Confirm both version commands match the release, `docker compose images` reports the expected digest, and the health request succeeds. Recreate the service and repeat the checks to verify the digest selection remains stable:

```bash
docker compose up --no-build --wait --force-recreate
docker compose images
curl --fail http://127.0.0.1:8000/healthz
```

Do not omit `--no-build` on the trusted-release path: the Compose file intentionally retains its local build definition for normal development. When finished, run `docker compose down` and remove `SECSCAN_IMAGE` from `.env` to restore the default local-build workflow. Named report and cache volumes remain unless `docker compose down --volumes` is deliberately used.

## Failure and recovery

- If validation fails, correct the project version or choose the correct new tag. Do not move a published release tag.
- If packaging fails before release creation, fix the repository through a pull request, increment the version when appropriate, and create a new tag.
- If container publication or attestation fails, inspect the workflow before retrying; do not create or move another tag while the original run is recoverable.
- If the final GitHub Release command fails after publication, inspect the workflow and registry first. Confirm whether the image, attestation, or release already exists before rerunning the failed job.
- Never overwrite release assets silently. Treat a published tag and its checksums as immutable.

GitHub-hosted release automation introduces no secscan runtime infrastructure. Repository owners remain responsible for GitHub Actions, Packages, storage, transfer, release, and attestation limits that apply to their account.
