# Sprint 64 — Authenticated Windows Host Web/API Submission

## Goal

Expose the existing strict key-only `windows-host` scanner through the authenticated service API and browser workspace without changing its SSH transport, read-only PowerShell posture checks, or target authorization boundary.

## Scope

This sprint adds a dedicated authenticated Windows host workflow that:

- accepts one literal hostname/IP target through a dedicated `POST /api/v1/windows-host-jobs` endpoint
- requires explicit operator authorization acknowledgement before any job is persisted
- reuses the existing encrypted SSH credential profiles for private-key and trusted-host material
- supports an optional Windows SSH username override for local or `DOMAIN\\user` account names without storing that override in the credential profile
- supports the existing strict server-side `SECSCAN_SSH_*` fallback when no encrypted profile is selected
- preserves strict host-key checking, public-key-only authentication, no agent forwarding, no passwords, and no TOFU/`accept-new`
- queues normal tenant-owned service jobs and reuses existing history, artifacts, policy, baseline, dashboard, and reporting behavior
- exposes **Windows server — Authenticated assessment** in the browser with a dedicated authorization control and SSH options
- keeps authenticated host workflows Professional-entitled in the existing plan middleware

## Security boundaries

- The browser never receives stored private keys or known-hosts contents.
- The server validates the target before persistence.
- The Windows username override is validated by the existing `windows-host` username validator and is used only for that submitted scan.
- Credentials are materialized only into owner-readable temporary files for the child process and removed with the temporary directory after execution.
- The child scan remains the existing fixed `secscan scan windows-host ...` path; clients cannot inject SSH options, PowerShell, arbitrary flags, or remote commands.
- Host-key trust remains explicit and fail-closed.
- Authorization acknowledgement is an operator safety control, not cryptographic proof of ownership.

## Out of scope

- WinRM
- passwords, keyboard-interactive authentication, SSH agent authentication, or stored passphrases
- arbitrary PowerShell or remote command execution
- target lists or ranges
- Windows agent installation
- automatic host-key trust
- tenant-shared credential ownership changes
- Windows-specific credential-profile schema migration
- service scheduling or recurring scans

## Cost

Current/projected recurring secscan infrastructure/service cost remains **$0**. The workflow uses the existing local/container service, OpenSSH client, encrypted credential store, and Windows scanner.

## Acceptance criteria

- Browser users can select **Windows server — Authenticated assessment** and submit one authorized target.
- `POST /api/v1/windows-host-jobs` rejects missing authorization, malformed targets, malformed username overrides, unknown credential profiles, and unconfigured fallback submission before persistence.
- Encrypted credential-profile submissions execute `windows-host` with ephemeral key/known-host files and an optional validated username override.
- Server-side fallback submissions enter the normal job pipeline as `windows-host`.
- Free-plan session users are denied the Windows authenticated-host endpoint just as they are denied Linux authenticated-host workflows.
- Browser/API tests cover success and failure paths without requiring a live Windows machine.
- Wheel verification includes the Windows browser module.
- Ruff, mypy, pytest, wheel/clean-install validation, Docker/Compose smoke, Trivy self-scan, CodeQL workflow, and the separate GitHub Advanced Security CodeQL check are green before merge.
