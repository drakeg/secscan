# Authenticated Windows Host Scanning

Sprint 51 adds a bounded read-only `windows-host` scanner for Windows systems that already expose Microsoft-supported OpenSSH Server.

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

The CLI uses the same file-based SSH settings as Linux host scanning:

```env
SECSCAN_SSH_USER=CONTOSO\secscan
SECSCAN_SSH_KEY=/run/secscan-ssh/id_ed25519
SECSCAN_SSH_KNOWN_HOSTS=/run/secscan-ssh/known_hosts
SECSCAN_SSH_PORT=22
```

`SECSCAN_SSH_USER` accepts a simple local username such as `secscan` or a domain-qualified `CONTOSO\secscan` value. Password authentication is not supported.

## Run

```bash
secscan scan windows-host windows.example --output-dir /reports/windows-example
```

The normal secscan policy, baseline, report, history, and exit-code pipeline applies.

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

The initial scanner emits normalized posture findings for:

- disabled Windows Firewall profiles
- Microsoft Defender real-time protection disabled, when Defender is present and reports that state
- SMBv1 enabled
- pending reboot evidence

An `unavailable` state is retained as evidence rather than guessed into a pass/fail result.

## Explicit limitations

Sprint 51 does **not**:

- use WinRM, Basic authentication, NTLM, CredSSP, or TrustedHosts
- accept passwords
- configure Windows or firewall rules
- query Windows Update services to infer missing patches
- guess CVEs from Windows software display names
- perform installed-software CVE correlation
- submit Windows scans through the web GUI
- automatically reassess assets

Those capabilities require separate planning because they materially change trust, credential, network, or correlation boundaries.

## Cost

The scanner adds no cloud resources, hosted scanner, or paid service. Current and projected recurring secscan service cost remains **$0**.
