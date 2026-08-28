# Sprint 45 — Debian Source-Package CVE Accuracy

## Goal

Improve authenticated Debian/Ubuntu package vulnerability correlation by carrying source-package identity from the installed dpkg database into the Trivy-compatible CycloneDX metadata, without guessing unsupported RPM source identity.

## Stories

1. As an operator, Debian/Ubuntu Linux scans can distinguish a binary package from the source package against which distribution CVEs may be tracked.
2. As a security reviewer, source-package name/version is derived only from dpkg metadata or Debian's defined same-name/same-version fallback.
3. As an operator, existing RPM-family correlation continues unchanged rather than parsing source RPM filenames heuristically.

## Acceptance criteria

- the fixed read-only SSH script requests binary package name, installed version, architecture, source package name, and source package version from `dpkg-query`
- when Debian omits the Source field because source and binary name/version are identical, secscan records the binary identity as the source identity
- partially populated source metadata is rejected as malformed rather than silently guessed
- package inventory preserves `source_name` and `source_version` for enriched dpkg packages
- generated Trivy package components include `aquasecurity:trivy:SrcName` and `aquasecurity:trivy:SrcVersion`
- legacy four-field package rows remain accepted for compatibility and RPM rows do not gain inferred source metadata
- Linux raw schema and scanner version are incremented for the enriched inventory
- focused tests cover explicit source identity, Debian fallback, malformed metadata, and RPM non-inference
- the real authenticated Linux Compose fixture remains green
- Python 3.12/3.14 preflight, Trivy self-scan, CodeQL workflow, and the separate GitHub code-scanning check are green before merge

## Security boundaries

No passwords, agents, sudo, root escalation, package mutation, arbitrary commands/flags, TOFU, `accept-new`, target-side Trivy installation, network ranges, or cloud services are added.

RPM `SOURCERPM` filenames are not parsed into source name/version in this sprint because that would introduce ambiguous filename heuristics. RPM-family package CVE correlation remains at the Sprint 44 behavior until a deterministic source-identity mechanism is selected.

## Correctness basis

Debian policy states that a binary package may omit its `Source` field when the source package has the same name and version as the binary package. Therefore the same-name/same-version fallback is defined package semantics rather than an inference.

Trivy-generated CycloneDX package components carry `aquasecurity:trivy:SrcName` and `aquasecurity:trivy:SrcVersion`; secscan now supplies those fields when they can be proven from dpkg metadata.

## Cost

- current recurring secscan infrastructure/service cost: **$0**
- projected recurring cost introduced by this sprint: **$0**
- no AWS resources or paid services are activated

## Out of scope

- RPM source-package identity parsing
- language ecosystem packages such as pip/npm/gem
- Windows package scanning
- KEV/EPSS enrichment
- remediation or package upgrade execution
- multi-host scheduling or CIDR scanning
