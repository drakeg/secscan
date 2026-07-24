# Repository Scanning

`secscan` can scan a local source repository through the built-in `repository` scanner plugin.

## Local usage

```bash
secscan scan repository . \
  --output-dir ./reports \
  --fail-on HIGH
```

The command uses Trivy repository mode and produces the same normalized JSON, HTML, CycloneDX, policy, baseline, and history outputs as the image and filesystem scanners.

## Docker usage

Mount the repository read-only:

```bash
docker run --rm \
  -v "$PWD:/repo:ro" \
  -v secscan-reports:/reports \
  -v secscan-cache:/cache \
  secscan:dev scan repository /repo \
    --output-dir /reports \
    --fail-on HIGH
```

## Target validation

The repository target must:

- exist
- be a directory
- be readable by the secscan process

secscan does not clone remote repositories in this increment. Clone or check out the desired revision first, then scan the local directory.

## Security boundaries

- Mount source repositories read-only when using Docker.
- Do not mount SSH keys, Git credentials, or the Docker socket into the scanner container.
- Treat generated reports, SBOMs, history databases, and baseline files as security-sensitive inventory.
- The scanner runs as non-root UID `10001` in the provided image.

## Current limitations

This increment does not include remote Git URLs, private-repository authentication, branch selection, commit metadata capture, or secret scanning policy controls. Those capabilities remain future work.
