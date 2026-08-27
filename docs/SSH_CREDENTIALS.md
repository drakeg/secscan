# SSH credential profiles

secscan can store reusable SSH credential profiles for authenticated Linux-host scans. This is intended to make the browser GUI the normal operator workflow while keeping private-key material out of scan jobs, history, findings, reports, and artifact metadata.

## Local-only credential management boundary

Credential creation sends a private SSH key to the local secscan service. Use this feature only through the default loopback binding (`127.0.0.1`) unless a future deployment adds a properly configured TLS boundary. The existing trusted-LAN mode is plain HTTP and is **not** appropriate for submitting credentials, even when bearer authentication is enabled.

For local use, configuring `SECSCAN_API_TOKEN` is still recommended so another local browser/process cannot use the credential-management API without the token.

## Enable encrypted storage

Generate a 32-byte Fernet master key once:

```bash
python -c "import base64,secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"
```

Store the result in your ignored `.env` file:

```dotenv
SECSCAN_CREDENTIAL_KEY=<generated-value>
SECSCAN_API_TOKEN=<optional-strong-local-api-token>
```

Then restart the service:

```bash
docker compose up --build --wait
```

The master key is supplied to the service through its environment and is not written into the SQLite database. Keep it backed up separately from the secscan report volume. If the master key is lost, stored SSH profiles cannot be decrypted. Changing the key without re-creating the profiles has the same effect.

## Create profiles in the GUI

Open **SSH credentials** in the sidebar and provide:

- a friendly profile name, such as `Default Linux servers`
- the Linux SSH username
- an unencrypted OpenSSH or PEM private key
- trusted OpenSSH `known_hosts` entries for the hosts that profile may access
- optionally, **Make this the default profile**

The service validates the private key before encrypting it. Private-key and `known_hosts` content are encrypted with authenticated Fernet encryption before SQLite persistence. List/read responses expose only profile ID, profile name, username, default state, and timestamps; the API does not provide a way to read the stored key or `known_hosts` plaintext back.

Password-protected private keys are intentionally not supported in this Sprint because that would require a second secret and passphrase-lifecycle design.

## Default and per-host selection

In **New scan → Linux server — Authenticated assessment**, choose a credential profile or leave the selector on **Default / server fallback**.

When no profile is selected explicitly, secscan resolves credentials in this order:

1. a remembered profile binding for that exact host;
2. the profile marked as default;
3. the legacy server-side `SECSCAN_SSH_*` file-mounted configuration, when configured.

Selecting a profile applies it to that scan. Enable **Remember this profile for this host** only when you want future scans of that exact hostname/IP to use that profile automatically.

Deleting a profile also removes its remembered host bindings. A host with no remaining binding falls back to the current default profile when one exists.

## Host-key verification

Stored profiles contain normal OpenSSH `known_hosts` content and the existing Linux scanner continues to enforce `StrictHostKeyChecking=yes`. secscan does not provide an insecure host-key bypass or automatic trust-on-first-use.

Obtain and verify host fingerprints through your normal administrative process before adding the corresponding trusted entry. A future GUI increment can improve fingerprint enrollment/approval without weakening this trust model.

## How a profile-backed scan executes

For each profile-backed Linux job, the service:

1. decrypts only the selected profile in memory;
2. creates a unique temporary directory on the service's bounded `/tmp` tmpfs;
3. writes the private key and `known_hosts` data there with restrictive permissions;
4. starts a child `secscan scan linux-host ...` process with only that job's SSH environment;
5. removes the temporary directory when the process finishes;
6. persists only the normal target/job/report/artifact information.

The selected private key, `known_hosts` text, encryption ciphertext, and master key are not written to `service_jobs`, scan history, normalized findings, reports, or artifact manifests.

Separate child-process environments allow concurrent Linux scans to use different profiles without mutating the service's global `os.environ`.

## Legacy file-mounted fallback

The Sprint 39 file-based configuration remains supported for compatibility and CLI use:

```dotenv
SECSCAN_SSH_DIR=./.secscan-ssh
SECSCAN_SSH_USER=secscan-audit
SECSCAN_SSH_KEY=/run/secscan-ssh/id_ed25519
SECSCAN_SSH_KNOWN_HOSTS=/run/secscan-ssh/known_hosts
SECSCAN_SSH_PORT=22
```

GUI-managed encrypted profiles are preferred for normal interactive Linux-host scanning once `SECSCAN_CREDENTIAL_KEY` is configured.

## Security limitations

This local credential store is not a SaaS tenant secret vault. It does not provide organization isolation, user roles, KMS/HSM-backed keys, key rotation workflows, audit events, TLS termination, SSH certificates, password authentication, arbitrary SSH flags, SSH agents, or bastion/proxy configuration. Those capabilities require explicit future security architecture.

Current and projected recurring secscan infrastructure/service cost remains **$0**.
