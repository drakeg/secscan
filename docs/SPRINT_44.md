# Sprint 44 — Authenticated Linux Package CVE Correlation

## Goal

Turn the authenticated Linux package inventory from Sprint 43 into actionable vulnerability findings by correlating supported operating-system packages with the existing local Trivy vulnerability engine.

## Stories

1. As an operator, I can run the existing authenticated Linux host scan and receive CVE findings for installed OS packages when secscan can prove the package ecosystem and distribution mapping.
2. As an operator, package CVEs use the same normalized finding, policy, baseline, history, report, dashboard, and severity paths as existing secscan findings.
3. As a security reviewer, I can verify that secscan does not guess a distribution mapping when the remote OS metadata is unsupported or inconsistent with its package manager.

## Acceptance criteria

- the existing fixed, read-only SSH collection remains the only remote execution path
- Debian/Ubuntu dpkg inventory can be translated to a bounded CycloneDX document containing Trivy package metadata and distro-qualified package URLs
- supported RPM-family inventory has an explicit allow-listed OS-to-Trivy mapping rather than a generic RPM assumption
- the generated temporary SBOM contains package name, installed version, architecture, distribution identifier, Trivy package ID, and Trivy package type
- the temporary SBOM is scanned locally with the existing `trivy sbom` adapter
- Trivy vulnerability output is normalized into secscan-owned findings and retargeted to the actual Linux hostname/IP rather than the temporary SBOM path
- posture findings and package vulnerability findings are returned together by the existing `linux-host` scanner
- unsupported or inconsistent distro/package-manager combinations remain inventory-only and are explicitly reported as `unsupported_distro`
- no temporary SBOM path or SSH secret becomes a persisted credential field
- tests cover Debian/Ubuntu CVE correlation, RPM-family metadata, unknown distro fail-closed behavior, existing SSH hardening, package parsing, and operational failures
- Python 3.12 and 3.14 preflight, container/Compose authenticated fixture, Trivy image self-scan, CodeQL workflow, and the separate GitHub code-scanning check are green before merge

## Security boundaries

This sprint does not add passwords, SSH agent use, sudo, root login, arbitrary remote commands, arbitrary scanner flags, shell fragments, host-key TOFU, `accept-new`, CIDR/range scanning, package installation/remediation, remote Trivy installation, or target-side vulnerability-database downloads.

The OS-to-Trivy mapping is allow-listed. Unknown distro IDs, missing OS versions, and package-manager mismatches are not coerced into another distribution family. In those cases the authenticated package inventory remains available but CVE correlation is skipped.

Trivy documents that SBOM scans can identify vulnerabilities but that accurate detection may rely on Trivy-specific package metadata. Secscan therefore supplies only metadata derived deterministically from `/etc/os-release` and the installed package database and does not infer unsupported distribution ancestry.

## Operational behavior

The first supported Linux CVE correlation in a container may require Trivy to obtain its vulnerability database using its normal cache behavior. The existing container cache is reused for subsequent Trivy work in that runtime. This sprint does not introduce an additional vulnerability service, daemon, database server, or cloud dependency.

## Cost

- current recurring secscan infrastructure/service cost: **$0**
- projected recurring cost introduced by this sprint: **$0**
- no AWS resources or paid SaaS integrations are activated

## Out of scope

- source-package metadata enrichment beyond what can be proven from the current package inventory
- language-package discovery on remote hosts
- Windows package/CVE scanning
- remote filesystem/rootfs copying
- remediation or package upgrade execution
- KEV/EPSS enrichment
- multi-host scheduling or network ranges
- SaaS tenant isolation or billing

## Demonstration

Run the existing authenticated Linux host Compose fixture and confirm that:

1. SSH remains key-only with strict host-key verification.
2. Installed packages are collected as before.
3. A supported distro produces a local Trivy SBOM vulnerability scan.
4. Any returned CVEs appear as normal secscan findings against the Linux host target.
5. An unknown distro fixture retains inventory but records `package_vulnerability_scan.status = unsupported_distro` without invoking Trivy SBOM scanning.
