# secscan

`secscan` is an open-source, container-first security scanner that wraps Trivy, normalizes vulnerability findings into a stable secscan schema, writes machine-readable reports, and returns CI-friendly policy exit codes.

Development is delivered incrementally using Agile sprints. See [`docs/ROADMAP.md`](docs/ROADMAP.md), [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), and [`docs/AGILE.md`](docs/AGILE.md).

## Sprint 1 usage

Build the scanner:

```bash
docker build -t secscan:dev .
```

### Rootful Docker

For a normal rootful Docker daemon, bind-mount host directories and run with the current host UID and GID:

```bash
mkdir -p reports cache
docker run --rm \
  --user "$(id -u):$(id -g)" \
  -v "$PWD/reports:/reports" \
  -v "$PWD/cache:/cache" \
  secscan:dev scan image alpine:3.20 --fail-on CRITICAL
```

This keeps generated files owned by the current host user.

### Rootless Docker

Rootless Docker remaps container UIDs into a subordinate host-ID range. Passing the host UID with `--user` therefore does not make a bind mount writable inside the container.

The supported rootless workflow uses Docker-managed named volumes:

```bash
docker volume create secscan-reports
docker volume create secscan-cache

docker run --rm \
  -v secscan-reports:/reports \
  -v secscan-cache:/cache \
  secscan:dev scan image alpine:3.20 --fail-on CRITICAL
```

Copy the report to the current directory when needed:

```bash
mkdir -p reports
docker run --rm \
  -v secscan-reports:/source:ro \
  -v "$PWD/reports:/destination" \
  alpine:3.20 \
  cp /source/secscan.json /destination/secscan.json
```

For a one-off rootless scan, an explicitly writable host directory also works, but named volumes are preferred over setting project directories to mode `0777`.

Detect rootless mode with:

```bash
docker info | grep -i rootless
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

Sprint 1 scans image references directly and does not require mounting the Docker socket. The image defaults to non-root UID `10001`.

- Rootful Docker: use `--user "$(id -u):$(id -g)"` for writable host bind mounts.
- Rootless Docker: use Docker-managed named volumes because container UIDs are remapped.
- Do not use `--privileged` or disable SELinux to make secscan work.

## Documentation

- [Agile delivery model](docs/AGILE.md)
- [Product roadmap and sprint plans](docs/ROADMAP.md)
- [Initial architecture](docs/ARCHITECTURE.md)
- [Definition of done](docs/DEFINITION_OF_DONE.md)

## License

A project license has not yet been selected. Until one is added, normal copyright restrictions apply.
