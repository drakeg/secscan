# secscan

`secscan` is an open-source, container-first security scanner that wraps Trivy, normalizes vulnerability findings into a stable secscan schema, writes machine-readable reports, and returns CI-friendly policy exit codes.

Development is delivered incrementally using Agile sprints. See [`docs/ROADMAP.md`](docs/ROADMAP.md), [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), and [`docs/AGILE.md`](docs/AGILE.md).

## Sprint 1 usage

Build the scanner:

```bash
docker build -t secscan:dev .
```

Scan a public image and save the normalized report in `./reports`:

```bash
mkdir -p reports cache
docker run --rm \
  -v "$PWD/reports:/reports" \
  -v "$PWD/cache:/cache" \
  secscan:dev scan image alpine:3.20 --fail-on CRITICAL
```

Exit codes:

- `0`: scan completed and policy passed
- `1`: scanner or input error
- `2`: scan completed but findings met or exceeded `--fail-on`

The default report path is `/reports/secscan.json`. The vulnerability database cache is stored under `/cache` so it can be persisted with a volume mount.

## Local development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
pytest
secscan --help
```

## Sprint 1 boundaries

This increment scans public container images and emits normalized JSON. HTML reports, filesystem scanning, YAML policy loading, suppressions, private registry authentication, scan history, service mode, AWS discovery, and contextual risk scoring are planned for later sprints.

## Security note

Sprint 1 scans image references directly and does not require mounting the Docker socket. Persisted report and cache directories should be writable by container UID `10001`.

## Documentation

- [Agile delivery model](docs/AGILE.md)
- [Product roadmap and sprint plans](docs/ROADMAP.md)
- [Initial architecture](docs/ARCHITECTURE.md)
- [Definition of done](docs/DEFINITION_OF_DONE.md)

## License

A project license has not yet been selected. Until one is added, normal copyright restrictions apply.
