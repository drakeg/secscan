# Sprint 42 — SSH Host-Key Trust Management

## Goal

Make authenticated Linux-host onboarding practical from the browser without weakening OpenSSH host-key verification. secscan may discover a server's presented public host key, but only an authenticated administrator may explicitly approve that key for future scans.

## Stories

1. As an administrator, I can enter one hostname/IP and SSH port and ask secscan to discover the public SSH host key currently presented by that endpoint.
2. As an administrator, I can review the discovered key type and SHA-256 fingerprint before deciding whether to trust it.
3. As an administrator, I can approve one discovered host key and persist that exact key as the trusted key for the host/port.
4. As an operator, Linux-host scans use the approved host key with `StrictHostKeyChecking=yes` rather than silently accepting an unknown or changed key.
5. As an administrator, I can list and remove approved host keys.
6. If a host presents a different key later, discovery shows the new fingerprint but does not replace the approved key automatically; scans continue to fail closed until an administrator deliberately updates trust.

## Acceptance criteria

- discovery accepts only the existing validated single-host target boundary and ports 1-65535
- discovery performs a bounded in-process SSH handshake using Paramiko; request-derived values are not passed to a shell or external command-line utility
- only public host-key material, key type, host/port, SHA-256 fingerprint, and timestamps are persisted; no private credentials are involved
- trust APIs require an authenticated browser administrator; bearer-token automation does not implicitly gain administrator trust-management rights
- approval requires the exact discovered public key and fingerprint presented back by the GUI
- approved host keys are stored separately from SSH private-key credential profiles
- profile-backed Linux scans build temporary `known_hosts` data from the approved trust record when one exists, while preserving compatibility with manually supplied profile `known_hosts` data
- changed keys are never auto-approved or silently overwritten
- `StrictHostKeyChecking=yes`, public-key-only authentication, no agent forwarding, and existing scan authorization acknowledgement remain unchanged
- no network ranges, CIDRs, wildcard discovery, automatic trust-on-first-use, DNS SSHFP trust, certificate authorities, bastions, or arbitrary SSH options are added
- current and projected recurring infrastructure/service cost remains $0

## Security notes

The in-process SSH handshake proves only what key was presented by the endpoint reached at discovery time; it does not prove that key belongs to the intended machine. The GUI must therefore show the SHA-256 fingerprint prominently and instruct the administrator to compare it against an independently trusted source before approval.

A changed host key is treated as a security event. The existing approved record remains authoritative until an administrator explicitly replaces it.

## Validation

- unit tests for host/port validation, bounded in-process discovery, fingerprinting, approval, replacement, listing, and deletion
- API tests for administrator-only discovery and trust mutation
- failure tests for malformed keys, mismatched fingerprints, unknown hosts, non-admin users, and key changes
- regression coverage that Linux scan execution still uses strict host-key verification
- `bash scripts/preflight.sh`
- Compose/container smoke and real SSH fixture validation when relevant
- CodeQL, including the separate GitHub Advanced Security code-scanning check
- `git diff --check`

## Cost outlook

All storage remains in the existing local SQLite database and host-key discovery runs in-process using the packaged Paramiko dependency. Current and projected recurring infrastructure/service cost remains $0.
