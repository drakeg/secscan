# secscan

`secscan` is an open-source, container-first security scanner that uses scanner plugins and a Trivy adapter to normalize vulnerability findings into a stable secscan schema, write machine-readable and HTML reports, and return CI-friendly policy exit codes.

Development is delivered incrementally using Agile sprints. See [`docs/ROADMAP.md`](docs/ROADMAP.md), [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), and [`docs/AGILE.md`](docs/AGILE.md).

## Build

```bash
docker build -t secscan:dev .
```

A successful scan creates four artifacts:

- `trivy.json` — raw Trivy vulnerability output
- `secscan.json` — normalized secscan findings
- `secscan.cdx.json` — CycloneDX JSON SBOM
- `secscan.html` — self-contained browser report

## Image scanning

```bash
docker volume create secscan-reports
docker volume create secscan-cache

docker run --rm \
  -v secscan-reports:/reports \
  -v secscan-cache:/cache \
  secscan:dev scan image alpine:3.20 \
    --output-dir /reports \
    --fail-on CRITICAL
```

## Filesystem scanning

Mount the target read-only. The scanner writes only to `/reports` and `/cache`:

```bash
docker volume create secscan-reports
docker volume create secscan-cache

docker run --rm \
  -v "$PWD:/scan:ro" \
  -v secscan-reports:/reports \
  -v secscan-cache:/cache \
  secscan:dev scan filesystem /scan \
    --output-dir /reports \
    --fail-on CRITICAL
```

A specific directory can be mounted instead:

```bash
docker run --rm \
  -v "/path/to/rootfs:/scan:ro" \
  -v secscan-reports:/reports \
  -v secscan-cache:/cache \
  secscan:dev scan filesystem /scan
```

For a local Python installation:

```bash
secscan scan filesystem . --output-dir ./reports --fail-on HIGH
```

## Copy reports from a rootless Docker volume

```bash
mkdir -p reports

docker run --rm \
  -v secscan-reports:/source:ro \
  -v "$PWD/reports:/destination" \
  alpine:3.20 \
  sh -c 'cp /source/* /destination/'
```

Open `reports/secscan.html` in a browser to review the vulnerability report.

## Exit codes

- `0`: scan completed and policy passed
- `1`: scanner, target, input, registry, or output error
- `2`: scan completed but findings met or exceeded `--fail-on`

The vulnerability database cache is stored under `/cache` and should be persisted between scans.

## Local development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
ruff check .
mypy
pytest
secscan --help
```

## Current boundaries

The built-in scanners support public container images and local filesystem paths. Both use the same normalized findings, reports, policy threshold, and exit-code behavior. YAML policy files, suppressions, private registry authentication, scan history, service mode, AWS discovery, and contextual risk scoring remain later increments.

## Security notes

- Container image scanning does not require mounting the Docker socket.
- Filesystem targets should be mounted read-only with `:ro`.
- The secscan image defaults to non-root UID `10001`.
- Rootless Docker users should use Docker-managed named volumes for `/reports` and `/cache`.
- Do not use `--privileged`, disable SELinux, or make project directories permanently world-writable.

## Documentation

- [Agile delivery model](docs/AGILE.md)
- [Product roadmap and sprint plans](docs/ROADMAP.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Definition of done](docs/DEFINITION_OF_DONE.md)

## License

A project license has not yet been selected. Until one is added, normal copyright restrictions apply.
