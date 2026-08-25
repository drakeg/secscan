# SSH-authenticated Linux host assessment

`secscan scan linux-host` performs a bounded read-only posture assessment of one Linux host over OpenSSH. It complements the agentless `network` scanner: the network scanner observes externally exposed services, while `linux-host` inspects selected internal configuration available to an authenticated unprivileged account.

Only assess systems you own or are explicitly authorized to test.

## Security model

Sprint 36 intentionally supports only key-based OpenSSH authentication. The scanner requires:

- one resolvable hostname or IP address as the scan target
- `SECSCAN_SSH_USER` — a simple Linux username
- `SECSCAN_SSH_KEY` — an absolute path to an existing private-key file
- `SECSCAN_SSH_KNOWN_HOSTS` — an absolute path to an existing OpenSSH `known_hosts` file
- optional `SECSCAN_SSH_PORT` — defaults to `22`

SSH uses fixed options including `BatchMode=yes`, `PasswordAuthentication=no`, `KbdInteractiveAuthentication=no`, `PreferredAuthentications=publickey`, `IdentitiesOnly=yes`, and `StrictHostKeyChecking=yes`. It disables agent/X11 forwarding and ignores ambient SSH configuration with `-F /dev/null`.

The key path and known-hosts path are operator configuration and are not added to the scan target, normalized findings, history records, or reports. The private-key and host-key **contents** are never read into secscan output. Treat the files themselves as sensitive and mount them read-only when using containers.

secscan does not provide `StrictHostKeyChecking=no`, password authentication, keyboard-interactive authentication, SSH agent forwarding, arbitrary SSH options, bastion/proxy commands, sudo prompts, or browser/API credential submission in this Sprint.

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

## Host account permissions

Use the least-privileged account that can read the posture data you intend to assess. Sprint 36 does not use sudo or attempt privilege escalation. Some checks may therefore be unavailable on hardened systems, which is preferable to silently broadening privileges.

The remote script performs read-only commands only. It does not run package updates, install software, alter firewall/SSH configuration, change permissions, restart services, or deploy an agent.

## Failure behavior

The scan fails operationally (exit code `1` through the normal CLI boundary) when required SSH configuration is missing, target/user/port validation fails, the SSH executable is unavailable, strict host-key verification or public-key authentication fails, the command times out, the remote output is malformed/incomplete, or the remote kernel is not Linux.

## Service and web GUI boundary

`linux-host` is a scanner plugin and therefore appears in CLI scanner discovery, but Sprint 36 does **not** add SSH secrets to the REST submission model or web GUI. A future service increment must introduce a deliberate credential/integration boundary rather than accepting private-key material from browsers or persisting it in job records.

## Cost

The feature uses local OpenSSH plus existing secscan reporting/history. Current and projected recurring secscan infrastructure/service cost remains **$0**. Operators are responsible for their own hosts and network usage.
