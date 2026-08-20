# Repository Scanning

`secscan` can scan either a local source repository or a public remote HTTPS Git repository through the built-in `repository` scanner plugin.

## Web GUI / service usage

Choose **Repository** on the New scan page and enter either a local path or a public Git URL.

Examples:

```text
https://github.com/example/project.git
https://gitlab.com/example/project.git
https://dev.azure.com/example/project/_git/repository
/workspace
```

For remote repositories, secscan validates the URL, performs a shallow single-branch clone into an isolated temporary directory, runs the existing repository scanner, and removes the temporary checkout when that scanner operation finishes. Reports and SBOM artifacts remain in the normal job output directory.

Only HTTPS URLs are accepted. Embedded usernames, passwords, personal access tokens, query strings, and URL fragments are rejected so credentials do not become part of job history or logs.

## CLI usage

Local repositories continue to work exactly as before:

```bash
secscan scan repository . \
  --output-dir ./reports \
  --fail-on HIGH
```

Remote public repositories can also be used as repository targets when `git` is available:

```bash
secscan scan repository https://github.com/example/project.git \
  --output-dir ./reports \
  --fail-on HIGH
```

The scanner uses Trivy repository mode and produces the same normalized JSON, HTML, CycloneDX, policy, baseline, and history outputs as the image and filesystem scanners.

## Docker usage

The provided secscan image includes `git` and CA certificates for public HTTPS repository cloning.

For a local repository, mount it read-only:

```bash
docker run --rm \
  -v "$PWD:/repo:ro" \
  -v secscan-reports:/reports \
  -v secscan-cache:/cache \
  secscan:dev scan repository /repo \
    --output-dir /reports \
    --fail-on HIGH
```

For a public remote repository, no source mount is required:

```bash
docker run --rm \
  -v secscan-reports:/reports \
  -v secscan-cache:/cache \
  secscan:dev scan repository https://github.com/example/project.git \
    --output-dir /reports \
    --fail-on HIGH
```

## Target validation

A local repository target must:

- exist
- be a directory
- be readable by the secscan process

A remote repository target must:

- use HTTPS
- include a hostname and repository path
- omit embedded credentials
- omit query strings and fragments

The remote clone uses `git clone --depth 1 --single-branch --no-tags` and disables interactive Git credential prompts.

## Security boundaries

- Mount local source repositories read-only when using Docker.
- Do not place tokens or passwords inside repository URLs.
- Do not mount SSH keys, Git credentials, or the Docker socket into the scanner container.
- Remote repository support currently targets public HTTPS repositories only.
- Treat generated reports, SBOMs, history databases, and baseline files as security-sensitive inventory.
- The scanner runs as non-root UID `10001` in the provided image.

## Current limitations

Private-repository authentication, provider OAuth/App integrations, explicit branch/tag selection, commit metadata capture, repository-size quotas, and tenant-specific credential storage are not included yet. Those should be implemented as dedicated integrations before a hosted multi-tenant service accepts private repositories.
