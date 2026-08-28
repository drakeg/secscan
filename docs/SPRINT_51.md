# Sprint 51 — Authenticated Windows Host Assessment

## Goal

Add a bounded read-only authenticated Windows assessment path using Microsoft-supported OpenSSH Server, while reusing secscan's strict key-only SSH trust model and normalized policy/report/history pipeline.

## Stories and acceptance criteria

- `windows-host` is a registered scanner and CLI target type.
- the scanner accepts exactly one validated hostname or IP target.
- authentication is public-key only; password, keyboard-interactive, agent forwarding, X11 forwarding, TOFU, and `accept-new` are not supported.
- an existing absolute private-key file and known-hosts file are required.
- Windows local or `DOMAIN\user` account names are strictly validated and passed as a separate SSH argument.
- remote execution is non-interactive PowerShell with a fixed read-only collection script.
- target evidence includes OS/build/architecture, latest installed hotfix evidence, firewall profile states, Defender real-time state when available, SMB1 state, pending-reboot evidence, and installed software inventory.
- normalized findings are emitted for disabled firewall profiles, Defender real-time protection disabled, SMB1 enabled, and pending reboot evidence.
- unsupported/unavailable security signals remain explicit evidence and are not guessed into findings.
- credentials and host-key material never appear in findings or raw output.
- focused tests cover strict SSH arguments, parsing, inventory deduplication, malformed data, missing files, non-Windows targets, SSH failure, and timeout.
- wheel integrity verifies the Windows scanner module.

## Security and correctness boundaries

This sprint deliberately uses OpenSSH rather than WinRM so it can reuse the already reviewed key-only and explicit-host-trust model. Secscan does not install or configure OpenSSH Server on the target.

No WinRM, Basic authentication, NTLM, CredSSP, TrustedHosts, passwords, target mutation, Windows Update network query, heuristic missing-patch inference, software-name CVE guessing, or GUI Windows submission is introduced.

The PowerShell collector reads standard CIM, firewall, Defender, optional-feature, reboot-indicator, hotfix, and uninstall-registry data. Missing cmdlets or features use bounded `unavailable` evidence where defined rather than silently claiming a secure state.

## Cost

- current recurring secscan infrastructure/service cost: **$0**
- projected recurring cost introduced by this sprint: **$0**
- no AWS resources or paid SaaS integrations are activated

## Validation

Before merge:

- Ruff passes.
- mypy passes.
- pytest passes on Python 3.12 and 3.14.
- wheel integrity and clean installation pass.
- Docker/Compose service/login smoke and authenticated Linux fixture remain green.
- Trivy fixable-critical self-scan passes.
- CodeQL workflow and the separate GitHub code-scanning check pass on the exact PR head.
