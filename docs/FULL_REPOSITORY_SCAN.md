# Full Repository Security Scan

The default `repository` scan is a comprehensive security pass over one local or remote source repository. It runs multiple complementary open-source engines and normalizes their findings into the same `secscan.json` report used by the rest of secscan.

## Engines

| Engine | Coverage | secscan severity behavior |
| --- | --- | --- |
| Trivy | dependency/SCA vulnerabilities and repository package findings | preserves Trivy severity |
| Semgrep | static application security testing (SAST) using the `p/security-audit` ruleset | ERROR→HIGH, WARNING→MEDIUM, INFO→LOW |
| Gitleaks | credentials, API keys, tokens, and other secrets in the working tree | CRITICAL |
| Checkov | Terraform, CloudFormation, Kubernetes, Dockerfile and other IaC/configuration policy checks | uses Checkov severity when present; otherwise MEDIUM |

The engines are complementary. A finding from one engine does not imply that another engine should find the same issue.

## Web GUI

Choose **Repository — Full security scan**, then enter either:

```text
/workspace
https://github.com/example/project.git
https://gitlab.com/example/project.git
https://dev.azure.com/example/project/_git/project
```

Private `github.com` repositories use the existing server-side `SECSCAN_GITHUB_TOKEN` configuration. The token must never be embedded in the repository URL.

## CLI

The normal repository command now means the full scan:

```bash
secscan scan repository /path/to/repository \
  --output-dir ./reports \
  --fail-on HIGH
```

Remote repositories work the same way:

```bash
secscan scan repository https://github.com/example/project.git \
  --output-dir ./reports \
  --fail-on HIGH
```

For troubleshooting or direct comparison with the previous behavior, a Trivy-only scanner remains available:

```bash
secscan scan repository-trivy /path/to/repository \
  --output-dir ./reports/trivy-only
```

`full-repository` is also available as an explicit CLI alias for the comprehensive scanner.

## Remote repository behavior

A remote repository is shallow-cloned once for the analysis phase. The same checkout is passed to Trivy, Semgrep, Gitleaks, and Checkov, then deleted. The generated CycloneDX SBOM uses the existing repository SBOM path and may resolve the repository again after analysis.

GitHub authentication remains process-local. Tokens are not added to repository URLs, scan targets, reports, or Git command arguments.

## Secret handling

Gitleaks is invoked with full redaction enabled. Secscan intentionally does not copy Gitleaks `Secret` or `Match` values into normalized findings. A secret finding contains the rule, description, file, and line needed for remediation without reproducing the credential in `secscan.json`.

Treat raw scanner artifacts and generated reports as security-sensitive data even with redaction enabled.

## Failure behavior

A full repository scan is considered incomplete if a required engine is missing, times out, returns an operational failure, or produces invalid JSON. Secscan fails the job instead of silently presenting a partial result as a full scan.

Normal findings do not cause an engine failure. Gitleaks and Checkov are invoked in modes that return successful process status when findings are present; secscan's own policy threshold determines whether the completed scan returns policy exit code `2`.

## Docker Compose

The secscan image bundles pinned versions of the additional engines. Build and run as usual:

```bash
docker compose up --build --wait
```

Then choose **Repository — Full security scan** in the GUI. For a private GitHub repository, configure `SECSCAN_GITHUB_TOKEN` in `.env` before starting Compose.

The image currently pins:

- Semgrep 1.172.0
- Gitleaks 8.30.1
- Checkov 3.3.8
- Trivy 0.74.0

Pinned versions make local/CI results reproducible. Engine upgrades should be made intentionally and validated through CI/container smoke tests.

## Scope and limitations

No scanner can guarantee discovery of every vulnerability. The full scan substantially broadens coverage across dependencies, source code, secrets, and infrastructure configuration, but it does not yet include dynamic application scanning, runtime behavior analysis, authenticated web/API testing, cloud posture discovery beyond existing secscan capabilities, or every language-specific analyzer.

Future integrations can be added behind the same scanner/orchestration model without changing the repository URL or job-history contracts.
