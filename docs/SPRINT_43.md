# Sprint 43 — Authenticated Linux Package Inventory

## Goal

Extend authenticated Linux host assessment with a deterministic, read-only installed-package inventory that can support later CVE correlation without widening SSH privilege or trust boundaries.

## Stories

1. As an operator, I can see the installed OS package inventory collected during an authenticated Linux scan.
2. As an operator, I receive a deterministic package artifact suitable for later vulnerability correlation and comparison.
3. As a security reviewer, I can verify package collection remains read-only, bounded, key-only, and strict-host-key checked.

## Acceptance criteria

- support Debian-family hosts through `dpkg-query` and RPM-family hosts through `rpm`
- package collection uses the existing fixed remote script; no user-supplied remote commands or package-manager flags are accepted
- normalized package records contain only package name, installed version, architecture when available, and package-manager source
- package records are deterministically sorted and deduplicated
- raw Linux-host scan output records package-manager availability and package count without embedding secrets
- write a versioned `secscan.linux-packages.json` artifact for Linux-host scans
- generated CycloneDX SBOM includes collected packages as library components with deterministic purl-like package identity only where safely derivable
- unsupported package managers produce an empty inventory with an explicit unavailable state rather than failing the posture scan
- existing SSH key-only authentication, explicit host-key trust, strict host-key checking, timeouts, policy/history/report behavior, and legacy SSH configuration remain unchanged
- tests cover Debian, RPM, unsupported-manager, malformed package output, deterministic ordering, artifact/SBOM output, and existing scanner behavior
- Python 3.12/3.14 preflight, container/Compose smoke, authenticated Linux fixture, Trivy image gate, CodeQL workflow, and GitHub code-scanning checks pass before merge

## Security boundaries

- no sudo or privilege escalation
- no package installation, update, removal, repository refresh, or mutation
- no arbitrary remote command execution
- no passwords, SSH agents, trust-on-first-use, `accept-new`, or relaxed host-key checking
- package inventory is security-sensitive host metadata and follows existing report/storage protections

## Cost

Current and projected recurring infrastructure/service cost remains **$0**. This sprint adds no AWS resources, hosted services, or paid dependencies.

## Out of scope

- CVE correlation or vulnerability findings from package inventory
- Windows/macOS inventory
- containers running on the host
- kernel module inventory
- package-file ownership
- repository configuration or update availability changes
- multi-host/range scanning
- SaaS tenancy, billing, or entitlements
