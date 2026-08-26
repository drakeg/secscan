# Docker and CI Build Performance

secscan intentionally bundles several substantial security engines. A completely clean image build can therefore take several minutes, especially while compiling Nuclei and Gitleaks and installing Semgrep and Checkov. Normal development should not repeat that work when the pinned scanner inputs have not changed.

## Normal local development

Keep using the supported Compose path:

```bash
cp .env.example .env
docker compose up --build --wait
curl --fail http://127.0.0.1:8000/healthz
```

Docker/BuildKit should reuse the pinned scanner stages and the Semgrep/Checkov tool layer on subsequent builds. Changes limited to secscan application source normally rebuild the wheel and final application layer rather than recompiling/reinstalling every scanner.

To stop the stack without discarding useful image/build cache:

```bash
docker compose down
```

## Deliberate clean build

Use a no-cache build only when you specifically need to validate a completely cold reconstruction or troubleshoot cache behavior:

```bash
docker compose build --no-cache
docker compose up --no-build --wait
curl --fail http://127.0.0.1:8000/healthz
```

A clean build is expected to be substantially slower and is not the recommended inner development loop.

## CI behavior

Pull requests run the complete Python 3.12/3.14 preflight, container build, CLI startup, Compose service health check, authenticated Linux-host fixture, fixable-critical image vulnerability gate, and CodeQL analysis.

The container build uses Docker Buildx with GitHub Actions cache import/export. Cache misses must remain correct: the cache is only a performance optimization and does not replace pinned source inputs or validation.

CI runs for pull requests and pushes to `main`. Feature-branch pushes do not independently run the same full CI suite when the pull request event already validates that commit.

The final image gate uses Trivy vulnerability scanning only because its purpose is specifically to reject fixable CRITICAL vulnerabilities in the built image. Repository secret scanning remains part of the repository scanner; scanning the entire built image for secrets is not part of this container-vulnerability gate.

## What invalidates expensive layers

The Nuclei build/template stage changes when the pinned Nuclei version, template release, or reviewed template commit changes. The Gitleaks stage changes when its pinned version changes. The Semgrep/Checkov stage changes when either pinned Python scanner version or its base Python image changes.

Application source changes should not invalidate those stages.

## Cost

Local Docker caching has no secscan service cost. GitHub-hosted BuildKit cache uses the repository's existing GitHub Actions cache allowance and introduces no new paid service. Cache retention and eviction are controlled by GitHub; secscan must always build correctly after a cache miss.
