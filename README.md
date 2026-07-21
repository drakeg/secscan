# secscan

`secscan` is an open-source, container-first security scanner that wraps Trivy, normalizes vulnerability findings into a stable secscan schema, writes machine-readable and HTML reports, and returns CI-friendly policy exit codes.

Development is delivered incrementally using Agile sprints. See [`docs/ROADMAP.md`](docs/ROADMAP.md), [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), and [`docs/AGILE.md`](docs/AGILE.md).

## Sprint 2 usage

Build the scanner:

```bash
docker build -t secscan:dev .
```

One scan creates four artifacts:

- `trivy.json` — raw Trivy vulnerability output
- `secscan.json` — normalized secscan findings
- `secscan.cdx.json` — CycloneDX JSON SBOM
- `secscan.html` — self-contained browser report

### Rootful Docker

```bash
mkdir -p reports cache
docker run --rm \
  --user "$(id -u):$(id -g)" \
  -v "$PWD/reports:/reports" \
  -v "$PWD/cache:/cache" \
  secscan:dev scan image alpine:3.20 \
    --output-dir /reports \
    --fail-on CRITICAL
```

### Rootless Docker

Rootless Docker remaps container UIDs into a subordinate host-ID range, so Docker-managed named volumes are the supported workflow:

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

Copy all generated artifacts to the current directory:

```bash
mkdir -p reports
docker run --rm \
  -v secscan-reports:/source:ro \
  -v "$PWD/reports:/destination" \
  alpine:3.20 \
  sh -c 'cp /source/* /destination/'
```

Open `reports/secscan.html` in a browser to review the vulnerability report.

Exit codes:

- `0`: scan completed and policy passed
- `1`: scanner, target, input, or output error
- `2`: scan completed but findings met or exceeded `--fail-on`

The vulnerability database cache is stored under `/cache` and should be persisted between scans.

## Local development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
pytest
secscan --help
```

## Sprint 2 boundaries

This increment scans public container images and emits raw JSON, normalized JSON, a CycloneDX SBOM, and a self-contained HTML report. Filesystem scanning, YAML policy loading, suppressions, private registry authentication, scan history, service mode, AWS discovery, and contextual risk scoring remain later sprints.

## Security note

Sprint 2 scans image references directly and does not require mounting the Docker socket. The image defaults to non-root UID `10001`.

- Rootful Docker: use `--user "$(id -u):$(id -g)"` for writable host bind mounts.
- Rootless Docker: use Docker-managed named volumes because container UIDs are remapped.
- Do not use `--privileged`, disable SELinux, or make project directories permanently world-writable.

## Documentation

- [Agile delivery model](docs/AGILE.md)
- [Product roadmap and sprint plans](docs/ROADMAP.md)
- [Initial architecture](docs/ARCHITECTURE.md)
- [Definition of done](docs/DEFINITION_OF_DONE.md)

## License

A project license has not yet been selected. Until one is added, normal copyright restrictions apply.
