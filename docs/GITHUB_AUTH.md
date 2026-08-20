# GitHub Repository Authentication

`secscan` can scan public GitHub repositories without credentials. Private `github.com` repositories can be scanned by configuring the server-side `SECSCAN_GITHUB_TOKEN` environment variable.

The token is never entered in the web GUI and must never be embedded in a repository URL. A scan target remains a normal HTTPS URL such as:

```text
https://github.com/example/private-project.git
```

## Recommended token

Use a GitHub fine-grained personal access token whenever possible.

Recommended scope:

- Repository access: **Only select repositories**
- Repository permissions: **Contents: Read-only**
- No write permissions
- No organization-administration permissions

Create a separate token for secscan rather than reusing a broad personal or automation token. Give it access only to repositories secscan must inspect and use an expiration date appropriate for your environment.

Classic personal access tokens may work when they have sufficient repository read access, but they are broader than necessary and are not recommended for new configurations.

## Docker Compose configuration

Copy the example environment file once:

```bash
cp .env.example .env
```

Edit `.env` and set the token:

```dotenv
SECSCAN_GITHUB_TOKEN=github_pat_your_token_here
```

Then start or recreate the service:

```bash
docker compose up --build --wait
```

Docker Compose reads `.env` automatically. The repository's `.gitignore` excludes `.env`; `.env.example` is intentionally committed with an empty token value.

Do **not** commit your populated `.env` file.

The token is passed to both the web service and the optional Compose CLI profile. You do not need to type it into the browser.

## Web GUI usage

After configuring `SECSCAN_GITHUB_TOKEN` and starting the service:

1. Open the secscan web GUI.
2. Choose **New scan**.
3. Select **Repository**.
4. Enter the ordinary credential-free GitHub URL, for example `https://github.com/example/private-project.git`.
5. Start the scan.

Public GitHub repositories work the same way whether the token is configured or not.

## CLI usage

For a local Python installation:

```bash
export SECSCAN_GITHUB_TOKEN='github_pat_your_token_here'
secscan scan repository https://github.com/example/private-project.git \
  --output-dir ./reports \
  --fail-on HIGH
unset SECSCAN_GITHUB_TOKEN
```

With the Compose CLI profile, the token from `.env` is already passed into the container:

```bash
docker compose --profile tools run --rm cli \
  scan repository https://github.com/example/private-project.git \
  --output-dir /reports/manual-private-repository \
  --fail-on HIGH
```

## Security behavior

`SECSCAN_GITHUB_TOKEN` is server-side configuration. Secscan does not add it to:

- repository URLs
- browser requests
- scan job targets
- Git command-line arguments
- scan history
- generated reports or SBOMs

For an authenticated `github.com` clone, secscan converts the token to an HTTP authorization header and supplies that header only through process-local Git environment configuration for the short-lived clone process. Interactive Git prompts, credential helpers, system Git configuration, and global Git configuration are disabled for remote clones. Clone errors are redacted before they can be persisted as job errors.

Anyone who can inspect the environment of the running secscan process/container or administer the Docker host should already be considered trusted. The current local/self-hosted token mechanism is not the final multi-tenant SaaS credential design.

## Troubleshooting

### `Repository not found`

GitHub commonly returns `Repository not found` for private repositories when authentication is missing or the token cannot access that repository. Check that:

- `SECSCAN_GITHUB_TOKEN` is populated in `.env` or the service environment.
- the token has access to the exact repository.
- the token has read-only **Contents** permission.
- the token has not expired or been revoked.
- Compose was recreated after changing `.env` (`docker compose up -d --force-recreate` is sufficient when a rebuild is not otherwise needed).

### Public repositories work but private repositories fail

This normally means the GitHub token is absent, invalid, expired, or not scoped to the private repository. The repository URL should still be a normal `https://github.com/OWNER/REPOSITORY.git` URL; do not add a username or token to it.

### Embedded credentials are rejected

URLs such as the following are intentionally rejected:

```text
https://username:token@github.com/example/project.git
```

Move the credential to `SECSCAN_GITHUB_TOKEN` and use the normal credential-free URL instead.

### Organization SSO or policy restrictions

An organization may require authorization or approval before a token can read its private repositories. Follow that organization's GitHub authentication policy and ensure the fine-grained token has actually been granted access to the selected repository.

## Other Git providers

Public HTTPS GitLab, Azure DevOps, and compatible Git repositories can be scanned today. `SECSCAN_GITHUB_TOKEN` is used only for `github.com`.

Private GitLab and Azure DevOps authentication are not yet supported. Those providers will use the repository-authentication provider boundary rather than storing credentials in scan targets.
