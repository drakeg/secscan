# Release Artifacts

Sprint 19 adds a guarded tag-driven GitHub Release workflow for Python artifacts. A successful release contains:

- the secscan wheel
- the Python source distribution
- `SHA256SUMS` covering both artifacts
- generated GitHub release notes

Container publication, PyPI publication, signatures, attestations, and provenance are not part of this sprint.

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
8. creates the GitHub Release and uploads all three files

The workflow defaults to `contents: read`; only the release job receives `contents: write`. It does not request an identity token, package permission, or access to repository secrets.

## Local dry run

From a clean checkout with development dependencies installed:

```bash
python scripts/release_artifacts.py verify-tag v0.1.0 pyproject.toml
bash scripts/preflight.sh
python -m build --sdist --wheel --outdir release-dist
python scripts/verify_wheel.py release-dist/secscan-*.whl
python scripts/release_artifacts.py checksums release-dist/SHA256SUMS release-dist/secscan-*.whl release-dist/secscan-*.tar.gz
```

Replace `v0.1.0` with the intended tag. Inspect the manifest:

```bash
cat release-dist/SHA256SUMS
```

Run the release-tool unit and failure-path tests independently:

```bash
pytest tests/test_release_artifacts.py
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

The tag push starts the Release workflow. No GitHub Release is created if tag validation, preflight, build, or wheel verification fails.

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

## Failure and recovery

- If validation fails, correct the project version or choose the correct new tag. Do not move a published release tag.
- If packaging fails before release creation, fix the repository through a pull request, increment the version when appropriate, and create a new tag.
- If the final GitHub Release command fails after validation, inspect the workflow log and confirm whether a release exists before rerunning the failed job.
- Never overwrite release assets silently. Treat a published tag and its checksums as immutable.

GitHub-hosted release automation introduces no secscan runtime infrastructure. Repository owners remain responsible for any GitHub usage or retention limits that apply to their account.
