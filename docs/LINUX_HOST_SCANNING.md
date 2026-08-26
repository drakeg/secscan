# SSH-authenticated Linux host assessment

`secscan scan linux-host` performs a bounded read-only posture assessment of one Linux host over OpenSSH. It complements the agentless `network` scanner: the network scanner observes externally exposed services, while `linux-host` inspects selected internal configuration available to an authenticated unprivileged account.

Only assess systems you own or are explicitly authorized to test.

## Security model

The scanner supports only key-based OpenSSH authentication. It requires:

- one resolvable hostname or IP address as the scan target
- `SECSCAN_SSH_USER` — a simple Linux username
- `SECSCAN_SSH_KEY` — an absolute path to an existing private-key file
- `SECSCAN_SSH_KNOWN_HOSTS` — an absolute path to an existing OpenSSH `known_hosts` file
- optional `SECSCAN_SSH_PORT` — defaults to `22`

SSH uses fixed options including `BatchMode=yes`, `PasswordAuthentication=no`, `KbdInteractiveAuthentication=no`, `PreferredAuthentications=publickey`, `IdentitiesOnly=yes`, and `StrictHostKeyChecking=yes`. It disables agent/X11 forwarding and ignores ambient SSH configuration with `-F /dev/null`.

The key path and known-hosts path are operator configuration and are not added to the scan target, normalized findings, history records, or reports. The private-key and host-key **contents** are never read into secscan output. Treat the files themselves as sensitive and mount them read-only when using containers.

secscan does not provide `StrictHostKeyChecking=no`, password authentication, keyboard-interactive authentication, SSH agent forwarding, arbitrary SSH options, bastion/proxy commands, sudo prompts, or browser/API credential submission.

## What it checks

The remote side receives one constant shell script through standard input. It does not interpolate target/user input into that script and does not modify the host. The first posture set gathers:

- Linux kernel and `/etc/os-release` identity
- UID 0 account names from `/etc/passwd`
- effective OpenSSH `PasswordAuthentication` and `PermitRootLogin` when readable through `sshd -T`
- pending package-update count on hosts with `apt`
- basic UFW/firewalld state when readable
- up to 20 world-writable regular files beneath `/etc` within two directory levels

These checks currently produce normalized findings for:

- pending package updates — Medium
- SSH password authentication enabled — High
- direct SSH root login enabled — High
- additional UID 0 accounts — Critical
- inactive host firewall when positively detected — Medium
- world-writable files beneath `/etc` — High

A check that is unsupported or unreadable is retained as raw check metadata where possible; secscan does not invent a vulnerability from missing privileges.

### Important limitation

This is not yet a complete remote package-CVE assessment. `apt list --upgradable` indicates available package updates using the host's existing package metadata; it does not prove that every update is security-related and does not refresh package indexes. Future host-scanning Sprints can add distribution-specific vulnerability intelligence/OpenSCAP/Wazuh-style integrations without changing this initial SSH trust boundary.

## GUI and service workflow

The browser GUI exposes **Linux server — Authenticated assessment** as a normal **New scan** option. The browser submits only the hostname/IP, normal scan options, and an explicit authorization acknowledgement. It never receives or submits SSH private-key material, known-hosts contents, passwords, or arbitrary SSH options.

SSH credentials are configured on the secscan service. For Docker Compose, place the private key and `known_hosts` file in an operator-controlled directory and mount it read-only through `SECSCAN_SSH_DIR`. The default layout is:

```text
.secscan-ssh/
├── id_ed25519
└── known_hosts
```

The default `.secscan-ssh/` directory is ignored by Git. Do not commit private keys.

Configure `.env`:

```dotenv
SECSCAN_SSH_DIR=./.secscan-ssh
SECSCAN_SSH_USER=secscan-audit
SECSCAN_SSH_KEY=/run/secscan-ssh/id_ed25519
SECSCAN_SSH_KNOWN_HOSTS=/run/secscan-ssh/known_hosts
SECSCAN_SSH_PORT=22
```

Then use the normal startup path:

```bash
docker compose up --build --wait
```

Open the GUI, choose **Linux server — Authenticated assessment**, enter one hostname or IP address, acknowledge that you own or are authorized to assess the host, and start the scan. If the service-side SSH configuration is incomplete, the GUI reports that Linux host scanning is not configured and the service rejects the request before persisting a job.

Once queued, the Linux-host assessment follows the same background-job, auto-refresh, history, severity-summary, dashboard, policy, baseline, report, and artifact paths as other secscan scans.

This credential model is deliberately appropriate to the current local/single-operator service. A future multi-user hosted service will require explicit user/organization/asset/integration models and an encrypted tenant-aware secret-management boundary rather than reusing one shared service key.

## Local CLI example

Create or select a dedicated read-only assessment account and SSH key according to your normal host-management practices. Populate a known-hosts file out-of-band after independently verifying the host key.

```bash
export SECSCAN_SSH_USER=secscan-audit
export SECSCAN_SSH_KEY=/absolute/path/to/id_ed25519
export SECSCAN_SSH_KNOWN_HOSTS=/absolute/path/to/known_hosts
export SECSCAN_SSH_PORT=22

secscan scan linux-host server.example.com \
  --output-dir ./reports/linux-host \
  --fail-on HIGH
```

Remove the variables when finished:

```bash
unset SECSCAN_SSH_USER SECSCAN_SSH_KEY SECSCAN_SSH_KNOWN_HOSTS SECSCAN_SSH_PORT
```

The normal policy, baseline, HTML/JSON report, CycloneDX device artifact, history, and exit-code behavior remains available.

## Container example

The secscan image includes `openssh-client`. Mount the key and known-hosts files read-only and point the environment variables at the container paths:

```bash
docker run --rm \
  --env SECSCAN_SSH_USER=secscan-audit \
  --env SECSCAN_SSH_KEY=/run/secscan-ssh/id_ed25519 \
  --env SECSCAN_SSH_KNOWN_HOSTS=/run/secscan-ssh/known_hosts \
  --env SECSCAN_SSH_PORT=22 \
  -v /absolute/path/to/id_ed25519:/run/secscan-ssh/id_ed25519:ro \
  -v /absolute/path/to/known_hosts:/run/secscan-ssh/known_hosts:ro \
  -v secscan-reports:/reports \
  secscan:dev scan linux-host server.example.com \
    --output-dir /reports/linux-host \
    --fail-on HIGH
```

Do not bake private keys into an image or commit them into this repository.

## Deterministic Docker Compose fixture

Sprint 37 adds an opt-in private SSH fixture so the real containerized scanner path can be tested without an external server. The fixture publishes no SSH port to the host. It generates a fresh Ed25519 client key, host key, and matching `known_hosts` entry inside a dedicated named volume each time the fixture starts; no private key is committed to the repository or baked into the secscan image.

Start the normal service plus the fixture:

```bash
cp .env.example .env
docker compose --profile linux-host-test up --build --wait
```

Run the authenticated assessment through the CLI container using the generated read-only credentials:

```bash
SECSCAN_SSH_USER=secscan-audit \
SECSCAN_SSH_KEY=/run/secscan-ssh-fixture/client_key \
SECSCAN_SSH_KNOWN_HOSTS=/run/secscan-ssh-fixture/known_hosts \
SECSCAN_SSH_PORT=22 \
docker compose --profile tools --profile linux-host-test run --rm cli \
  scan linux-host linux-host-fixture \
  --output-dir /reports/linux-host-fixture \
  --fail-on HIGH
```

The fixture intentionally exercises the scanner's normal `StrictHostKeyChecking=yes` path. Do not replace the generated known-hosts file with an insecure host-key bypass.

Inspect the generated report from the reports volume through the usual secscan tooling, then clean up the fixture and its generated credentials:

```bash
docker compose --profile linux-host-test down
docker volume rm "${SECSCAN_COMPOSE_PROJECT:-secscan}_secscan-ssh-fixture" 2>/dev/null || true
```

`docker compose down -v` is also appropriate when you intentionally want to remove all local secscan Compose volumes, including reports and cache.

## Host account permissions

Use the least-privileged account that can read the posture data you intend to assess. The scanner does not use sudo or attempt privilege escalation. Some checks may therefore be unavailable on hardened systems, which is preferable to silently broadening privileges.

The remote script performs read-only commands only. It does not run package updates, install software, alter firewall/SSH configuration, change permissions, restart services, or deploy an agent.

## Failure behavior

The scan fails operationally (exit code `1` through the normal scanner boundary) when required SSH configuration is missing, target/user/port validation fails, the SSH executable is unavailable, strict host-key verification or public-key authentication fails, the command times out, the remote output is malformed/incomplete, or the remote kernel is not Linux.

## Cost

The feature uses local OpenSSH plus existing secscan reporting/history. The deterministic fixture uses only local Docker Compose resources. Current and projected recurring secscan infrastructure/service cost remains **$0**. Operators are responsible for their own hosts and network usage.
