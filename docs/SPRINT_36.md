# Sprint 36 — SSH-Authenticated Linux Host Assessment

## Goal

Add the first authenticated internal-host assessment path for Linux systems without introducing agents, passwords, browser-submitted credentials, persistent secret storage, cloud infrastructure, or paid services.

## User stories

1. As an operator, I can run an authenticated Linux assessment against one hostname/IP using an SSH private key and known-hosts file that I mount or otherwise provide locally.
2. As an operator, I can see normalized findings for important Linux posture signals such as patch/update status, SSH hardening, firewall state, and selected service/user configuration.
3. As a maintainer, I can test the scanner against a private Docker Compose SSH fixture without connecting to public infrastructure.
4. As a security reviewer, I can verify that SSH secrets never enter scan targets, command history, normalized findings, reports, or persisted secscan job metadata.

## Planned implementation

- add a built-in `linux-host` scanner plugin and registry entry
- accept one hostname or IP plus an SSH username through a scanner-specific target format; credentials remain separate from the target
- use key-based OpenSSH authentication only for this sprint
- require strict host-key checking with an operator-supplied `known_hosts` file
- accept private-key and known-hosts paths through local CLI options/environment that are not persisted into normalized findings/history
- invoke OpenSSH through fixed argument lists with password, keyboard-interactive, agent forwarding, X11 forwarding, and remote command interpolation disabled
- run a fixed, read-only Linux inspection script/command set that gathers OS identity and selected security posture signals
- normalize detected posture issues into secscan `Finding` records so policy, baseline, HTML/JSON reporting, and history continue to work
- add `openssh-client` to the container if not already present
- add an opt-in private Compose SSH fixture for deterministic local testing; normal `docker compose up --build --wait` remains unchanged
- document credentials, host-key verification, least-privilege expectations, supported checks, limitations, and cleanup

## Initial checks

The first authenticated host scanner should stay intentionally bounded. It may report findings for signals such as:

- pending Debian/Ubuntu security or package updates when the host exposes that information without changing package state
- SSH password authentication enabled
- SSH root login permitted
- empty or missing host firewall posture when readable via supported tools
- unexpected UID 0 accounts beyond root
- selected world-writable sensitive configuration paths when detectable without privilege escalation

Unsupported/permission-denied checks should be recorded as scanner metadata or clearly documented limitations rather than silently converted into security findings.

## Acceptance criteria

- one Linux hostname/IP can be assessed through key-based SSH without installing a secscan agent on the target
- private-key material and known-hosts contents are never embedded in the target, normalized findings, reports, history, or logs
- strict host-key checking is mandatory; insecure `StrictHostKeyChecking=no` behavior is not provided
- password and keyboard-interactive authentication are disabled
- remote commands are constant, read-only, non-interactive, and not constructed from user-controlled shell fragments
- target and SSH username validation reject URLs, CIDRs, whitespace/control characters, and shell fragments
- normalized host findings flow through the standard policy, baseline, reporting, and history pipeline
- an opt-in private Compose fixture demonstrates successful key authentication and at least one deterministic posture finding without publishing an SSH port to the host
- failure coverage includes bad target/user input, missing key/known-hosts material, host-key mismatch/authentication failure, malformed remote output, and command timeout
- existing scanners and normal Compose service startup remain compatible
- focused tests, `git diff --check`, full `bash scripts/preflight.sh`, applicable Docker/Compose validation, GitHub CI, and CodeQL pass before merge
- no release tag, package publication, AWS resource, hosted service, or recurring infrastructure cost is introduced

## Security and operational boundaries

- only systems the operator owns or is explicitly authorized to assess may be targeted
- key-based SSH only; passwords, keyboard-interactive authentication, SSH agent forwarding, bastion/proxy configuration, SSH certificates, and browser/API credential submission remain out of scope
- no sudo prompts, privilege escalation, package installation, remediation, file modification, service restart, or agent deployment is performed on the target
- service/web submission of SSH credentials remains out of scope; this sprint establishes the scanner/CLI/container boundary first
- one target per scan; CIDRs, inventories, discovery, scheduling, and bulk host execution remain out of scope
- Linux support is bounded to distributions/checks that can be detected safely; unsupported distributions fail clearly or return limited metadata rather than being guessed
- the private SSH key remains operator-managed and should be mounted read-only; it is never copied into reports or persistent secscan state

## Validation plan

Automated tests will mock subprocess execution and parser output for success/failure cases and verify exact SSH argument construction. Container/Compose validation will use an opt-in private SSH fixture on the internal Compose network with a dedicated test key and pinned host key material intended only for the fixture. The fixture will not publish port 22 to the host and will not start during the ordinary service quick-start path.

## Cost outlook

Sprint 36 uses local OpenSSH, Docker Compose, SQLite/history, and the existing secscan reporting pipeline. Current and projected recurring secscan infrastructure/service cost remains **$0**. Operators remain responsible for their own systems and network usage.
