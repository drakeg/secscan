# Authenticated Windows Host Scanning

Sprint 51 added a bounded read-only `windows-host` scanner for Windows systems that already expose Microsoft-supported OpenSSH Server. Sprint 64 exposes that same scanner through a dedicated authenticated service/API and browser workflow without changing its transport or remote command boundary.

## Security model

The scanner uses the existing secscan SSH controls:

- public-key authentication only
- `BatchMode=yes`
- password and keyboard-interactive authentication disabled
- `StrictHostKeyChecking=yes`
- an explicit known-hosts file is required
- SSH agent and X11 forwarding are disabled
- no TOFU or `accept-new`
- no target-side secscan agent
- no password, private key, or host-key material is written to reports

Windows OpenSSH Server is a target prerequisite. Secscan does not install or enable it.

## Configuration

The CLI and server-side fallback use the same file-based SSH settings as Linux host scanning:

```env
SECSCAN_SSH_USER=CONTOSO\secscan
SECSCAN_SSH_KEY=/run/secscan-ssh/id_ed25519
SECSCAN_SSH_KNOWN_HOSTS=/run/secscan-ssh/known_hosts
SECSCAN_SSH_PORT=22
```

`SECSCAN_SSH_USER` accepts a simple local username such as `secscan` or a domain-qualified `CONTOSO\secscan` value. Password authentication is not supported.

For browser/API use, encrypted SSH credential profiles are preferred. The stored profile provides the private key and trusted-host material. A Windows submission may optionally provide a validated per-scan SSH username override, such as `CONTOSO\secscan`; the override is not persisted into the credential profile.

## CLI

```bash
secscan scan windows-host windows.example --output-dir /reports/windows-example
```

The normal secscan policy, baseline, report, history, and exit-code pipeline applies.

## Web/API

Professional-entitled authenticated users can choose **Windows server — Authenticated assessment** in the workspace or submit:

```http
POST /api/v1/windows-host-jobs
Content-Type: application/json
```

Example body:

```json
{
  "target": "192.0.2.20",
  "windows_host_authorized": true,
  "credential_profile_id": "<profile-id>",
  "ssh_username": "CONTOSO\\secscan",
  "ssh_port": 22,
  "timeout": 600
}
```

`windows_host_authorized` must be `true` before a job is persisted. `credential_profile_id` and `ssh_username` are optional when the configured server-side fallback is used; a username override is supported only with an encrypted credential profile. Browser/API jobs reuse the normal tenant ownership, history, policy, baseline, dashboard, reporting, and artifact paths.

## Read-only evidence collected

The scanner invokes non-interactive Windows PowerShell over SSH and records:

- Windows edition/caption
- OS version and build number
- architecture
- most recently reported installed hotfix and date when available
- Domain, Private, and Public Windows Firewall profile state
- Microsoft Defender real-time protection state when Defender cmdlets are available
- SMB1 optional-feature state when available
- pending reboot registry evidence
- installed software name, version, and publisher from standard HKLM uninstall registry locations

## Findings

The scanner emits normalized posture findings for:

- disabled Windows Firewall profiles
- Microsoft Defender real-time protection disabled, when Defender is present and reports that state
- SMBv1 enabled
- pending reboot evidence

An `unavailable` state is retained as evidence rather than guessed into a pass/fail result.

## Explicit limitations

The Windows host path does **not**:

- use WinRM, Basic authentication, NTLM, CredSSP, or TrustedHosts
- accept passwords
- accept arbitrary SSH options or arbitrary PowerShell/remote commands
- configure Windows or firewall rules
- query Windows Update services to infer missing patches
- guess CVEs from Windows software display names
- perform installed-software CVE correlation
- accept target lists or ranges through the Windows authenticated-host endpoint
- automatically reassess assets
- automatically trust SSH host keys

Those capabilities require separate planning because they materially change trust, credential, network, or correlation boundaries.

## Cost

The scanner and Web/API workflow add no cloud resources, hosted scanner, or paid scanning service. Current and projected recurring secscan service cost remains **$0**.
