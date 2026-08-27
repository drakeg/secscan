# Sprint 40 — GUI SSH Credential Profiles

## Goal

Make authenticated Linux scanning practical from the browser by allowing a local secscan operator to create encrypted reusable SSH credential profiles, choose one default profile, and optionally bind a different profile to a specific host without placing private-key material in scan jobs, history, reports, or logs.

## User stories

1. As an operator, I can create an SSH credential profile in the GUI with a friendly name, Linux username, private key, and trusted `known_hosts` content.
2. As an operator, I can mark one profile as the default for Linux-host scans.
3. As an operator, I can select a different profile for a host and remember that host-to-profile choice.
4. As a security reviewer, I can verify that private keys are encrypted at rest and never returned by list/read APIs or persisted in scan records and artifacts.

## Security design

- Credential storage is disabled unless `SECSCAN_CREDENTIAL_KEY` is configured on the service.
- The master key is supplied out-of-band through the service environment and is never written to SQLite.
- Private keys and `known_hosts` content are encrypted with authenticated Fernet encryption before SQLite persistence.
- Credential APIs return metadata only. Stored secret material is never readable back through the browser/API.
- Linux-host workers decrypt only the selected profile in memory and pass it to the scanner through an in-memory scan environment.
- The scanner materializes private key/known-hosts files only in a temporary directory for the duration of the SSH process and deletes them afterward.
- Strict host-key checking, public-key-only SSH authentication, fixed SSH arguments, and the existing read-only remote program remain unchanged.
- Passwords, arbitrary SSH flags, key passphrases, agents, bastions/proxies, automatic trust-on-first-use, and cloud secret managers remain out of scope.
- Credential creation/editing is intended for the loopback/local deployment. Do not submit credentials across the existing trusted-LAN HTTP mode because it does not provide TLS.

## Planned implementation

- add a small encrypted SSH credential store and schema migration
- add profile metadata, one-default enforcement, and host-to-profile binding
- add service-only credential master-key configuration
- extend the service worker boundary so a Linux-host job can receive per-job in-memory scanner environment without mutating global process environment
- add GUI/API create/list/delete/default profile operations
- add credential selection and optional per-host remember behavior to the Linux-host New Scan workflow
- keep the existing server-side `.secscan-ssh` profile as a compatibility fallback when encrypted profiles are not configured/selected
- document local setup, backup/recovery implications, credential rotation/deletion, and safe LAN limitations

## Acceptance criteria

- the GUI can create a profile containing name, username, private key, and known-hosts text when `SECSCAN_CREDENTIAL_KEY` is configured
- list/read responses never contain private-key or known-hosts contents/ciphertext
- exactly one profile may be default; selecting a new default clears the previous default transactionally
- a host may be bound to a non-default profile and that choice is offered automatically on later scans
- deleting a profile removes host bindings to it
- Linux-host jobs may select a stored profile without persisting decrypted material in `service_jobs`, reports, artifacts, history, or logs
- concurrent Linux-host jobs can use different profiles without changing `os.environ`
- strict host-key verification remains mandatory
- malformed master keys, malformed private keys/profile data, unknown profile IDs, and missing default/profile configuration fail closed
- automated tests cover encryption at rest, metadata-only APIs, default/host binding semantics, concurrent-safe per-job environment, GUI behavior, and secret non-disclosure
- full preflight, Docker/Compose validation, CI, and CodeQL pass before merge
- recurring secscan infrastructure/service cost remains $0

## Cost outlook

This Sprint uses the existing local SQLite/service/Compose architecture plus an open-source Python cryptography dependency. It introduces no hosted secret manager, cloud resource, paid API, or recurring service cost. Current/projected recurring secscan infrastructure cost remains **$0**.
