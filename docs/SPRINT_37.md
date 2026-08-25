# Sprint 37 — Deterministic Linux Host Compose Validation

## Goal

Add a deterministic, opt-in Docker Compose SSH fixture that exercises the Sprint 36 `linux-host` scanner end to end without requiring an operator-owned external server, weakening SSH verification, committing private keys, or adding recurring infrastructure cost.

## User stories

1. As an operator, I can validate authenticated Linux-host scanning locally before pointing secscan at a real server.
2. As a maintainer, I can exercise the actual OpenSSH client, strict host-key verification, scanner command, normalization, and report pipeline across the container boundary.
3. As a security reviewer, I can verify that test credentials are generated ephemerally and are not committed or persisted in reports/history.

## Planned implementation

- add an opt-in Compose profile for a private SSH Linux fixture
- generate fixture host/user key material at runtime or through a documented local setup helper; do not commit private keys
- require strict host-key verification in the secscan client path even for the fixture
- mount client key/known-host material read-only into the CLI container
- provide copyable setup, scan, verification, and cleanup commands
- add Compose/configuration regression coverage for the fixture boundary
- keep the ordinary `docker compose up --build --wait` path unchanged

## Acceptance criteria

- the normal Compose stack remains unchanged unless the explicit Linux-host test profile is enabled
- a local operator can start the fixture and successfully run `secscan scan linux-host` against it
- the fixture is reachable only on the private Compose network and publishes no SSH port to the host
- no private key is committed to the repository or baked into the secscan image
- strict host-key verification remains enabled; `StrictHostKeyChecking=no` is not introduced
- generated test credentials can be removed with documented cleanup
- scanner output/report/history do not contain private-key contents
- focused tests, `git diff --check`, full `bash scripts/preflight.sh`, applicable Docker/Compose validation, GitHub CI, and CodeQL pass before merge
- current and projected recurring infrastructure/service cost remains $0

## Security and operational boundaries

- the fixture is test-only and opt-in
- no host SSH port is published
- no password authentication, sudo, SSH agent forwarding, bastion/proxy support, or arbitrary SSH flags are added
- no real operator credential is required for fixture validation
- no cloud resource, hosted service, package publication, or release tag is introduced

## Out of scope

- REST/web submission of `linux-host` jobs
- browser credential handling or persistent SSH credential storage
- full package-CVE correlation or OpenSCAP/Wazuh integration
- Windows assessment
- CIDR/bulk host execution, scheduling, persistent assets, or AWS EC2 correlation

## Cost outlook

Sprint 37 uses only local Docker Compose, OpenSSH, and the existing secscan image/scanner pipeline. Current and projected recurring secscan infrastructure/service cost remains **$0**.
