# Repository Scanning

`secscan` can scan either a local source repository or a remote HTTPS Git repository through the built-in `repository` scanner plugin.

## Web GUI / service usage

Choose **Repository** on the New scan page and enter either a local path or an HTTPS Git URL.

Examples:

```text
https://github.com/example/project.git
https://gitlab.com/example/project.git
https://dev.azure.com/example/project/_git/repository
/workspace
```

For remote repositories, secscan validates the URL, performs a shallow single-branch clone into an isolated temporary directory, runs the existing repository scanner, and removes the temporary checkout when that scanner operation finishes. Reports and SBOM artifacts remain in the normal job output directory.

Only HTTPS URLs are accepted. Embedded usernames, passwords, personal access tokens, query strings, and URL fragments are rejected so credentials do not become part of job history or logs.

## Private GitHub repositories

GitHub repositories can be authenticated using the server-side `SECSCAN_GITHUB_TOKEN` environment variable. The browser still submits only the normal repository URL, for example:

```text
https://github.com/example/private-project.git
```

For Docker Compose, copy `.env.example` to `.env` and set:

```dotenv
SECSCAN_GITHUB_TOKEN=github_pat_your_token_here
```

Prefer a fine-grained GitHub token with read-only **Contents** access and scope it only to repositories secscan needs to inspect. Do not commit the populated `.env` file.

The token is not added to the repository URL, scan request, job database, report, or Git command arguments. It is converted to a GitHub authorization header and supplied only through the environment of the short-lived `git clone` process. Secscan also disables interactive prompts, credential helpers, and system/global Git configuration for remote clones. Clone errors are defensively redacted before they can be stored on a failed job.

For complete setup instructions, recommended token permissions, Docker Compose and CLI examples, security details, and authentication troubleshooting, see [GitHub Repository Authentication](GITHUB_AUTH.md).

GitLab, Azure DevOps, and generic HTTPS Git repositories remain public-only in this increment. Their future private-repository support should plug into the same provider authentication boundary rather than changing scan-job payloads.

## CLI usage

Local repositories continue to work exactly as before:

```bash
secscan scan repository . \
  --output-dir ./reports \
  --fail-on HIGH
```

Remote repositories can also be used as repository targets when `git` is available:

```bash
secscan scan repository https://github.com/example/project.git \
  --output-dir ./reports \
  --fail-on HIGH
```

For a private GitHub repository, export the token before running the same command:

```bash
export SECSCAN_GITHUB_TOKEN=github_pat_your_token_here
secscan scan repository https://github.com/example/private-project.git \
  --output-dir ./reports \
  --fail-on HIGH
unset SECSCAN_GITHUB_TOKEN
```

The scanner uses Trivy repository mode and produces the same normalized JSON, HTML, CycloneDX, policy, baseline, and history outputs as the image and filesystem scanners.

## Docker usage

The provided secscan image includes `git` and CA certificates for HTTPS repository cloning.

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

For a public remote repository, no source mount is required. For a private GitHub repository, pass `SECSCAN_GITHUB_TOKEN` through the container environment or use the provided Compose `.env` workflow; never put it in the target URL.

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

The remote clone uses `git clone --depth 1 --single-branch --no-tags` and disables interactive Git credential prompts and ambient credential helpers.

## Security boundaries

- Mount local source repositories read-only when using Docker.
- Do not place tokens or passwords inside repository URLs.
- Do not mount SSH keys, Git credentials, or the Docker socket into the scanner container.
- Use narrowly scoped, read-only GitHub credentials for private repositories.
- Treat generated reports, SBOMs, history databases, and baseline files as security-sensitive inventory.
- The scanner runs as non-root UID `10001` in the provided image.

## Current limitations

GitLab/Azure DevOps private authentication, provider OAuth/App integrations, explicit branch/tag selection, commit metadata capture, repository-size quotas, and tenant-specific encrypted credential storage are not included yet. Those should be implemented as dedicated integrations before a hosted multi-tenant service accepts broader private-repository credentials.
