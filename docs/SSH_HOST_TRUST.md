# SSH host-key trust management

Sprint 42 adds GUI-managed SSH host-key discovery and explicit administrator approval for authenticated Linux-host scanning.

## Why this exists

SSH private-key credentials answer **who secscan authenticates as**. SSH host trust answers **which server secscan believes it reached**. These are intentionally separate security controls.

secscan keeps OpenSSH `StrictHostKeyChecking=yes`. It never enables `StrictHostKeyChecking=no`, `accept-new`, or automatic trust-on-first-use.

## GUI workflow

1. Sign in with an administrator account.
2. Open **SSH credentials**.
3. In **Trusted host keys**, enter one hostname/IP and SSH port.
4. Choose **Discover host key**.
5. secscan runs bounded `ssh-keyscan` discovery and displays every presented key type and SHA-256 fingerprint.
6. Compare the fingerprint against an independent trusted source, such as the server console or an established configuration-management record.
7. Approve only the exact verified key.

Discovery alone does not create trust. Approval is a separate action tied to the authenticated administrator account.

## Changed host keys

If a server later presents a different SSH key, discovery shows the new fingerprint but does not replace the stored trust record. The existing approved key stays authoritative until an administrator explicitly approves a new discovery.

This is intentional. Unexpected host-key changes can indicate a rebuilt server, an addressing/DNS mistake, or a man-in-the-middle condition.

## How scans consume trust

Approved host keys are public data stored in the existing local SQLite database. When an encrypted SSH credential profile is used, secscan merges the approved host-key records into the temporary `known_hosts` file created for that scan. Manually supplied `known_hosts` entries in the credential profile remain available as a compatibility trust source.

For nonstandard SSH ports, secscan writes the OpenSSH bracketed form, for example:

```text
[server.example.com]:2222 ssh-ed25519 AAAA...
```

The temporary file still runs with strict host-key verification and is removed after the scan.

## Administrator boundary

Listing, discovery, approval, replacement, and deletion of GUI-managed host trust require an authenticated browser session whose user role is `admin`. A compatibility `SECSCAN_API_TOKEN` bearer token does not by itself grant host-trust administration rights.

## Security boundary

`ssh-keyscan` only reports the key presented by the endpoint that answered at discovery time. It does not prove identity. The administrator must verify the SHA-256 fingerprint through an independent trusted channel before approval.

Sprint 42 does not add CIDR/range discovery, DNS SSHFP trust, SSH certificate authorities, bastions/proxies, passwords, arbitrary SSH flags, or automatic key acceptance.

## Cost

The feature uses the existing OpenSSH client and SQLite database. Current and projected recurring infrastructure/service cost remains $0.
