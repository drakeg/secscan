# Remaining Sprint Sequence

This document turns the directional backlog into an ordered candidate sprint sequence. Only the current sprint is committed. Later sprint numbers remain candidates until sprint planning confirms exact stories, acceptance criteria, dependencies, security boundaries, and cost.

## Completed through Sprint 50

Sprints 0–50 are complete, including repository/image/SBOM scanning, policy and baselines, service/history/reporting, AWS ECR discovery/scanning, web UI, Nmap/Nuclei network assessment, authenticated Linux posture/package/CVE scanning, local accounts and encrypted SSH credentials, CISA KEV enrichment, FIRST EPSS enrichment, explainable KEV/EPSS-aware web prioritization, and persistent first-class asset inventory with scan-history association.

## Current sprint

### Sprint 51 — Authenticated Windows Host Assessment

Add a bounded, read-only authenticated Windows assessment path using key-only OpenSSH, explicit host trust, installed-software inventory, patch/posture evidence, and normalized findings without a target-side secscan agent.

## Candidate remaining sprints

### Sprint 52 — Bounded Network-Range Assessment

Expand single-host Nmap/Nuclei assessment to explicitly authorized, tightly bounded IP/CIDR target sets with hard maximums, deterministic target expansion, rate/concurrency controls, and clear audit evidence.

### Sprint 53 — Web/API DAST Expansion

Add bounded HTTP/HTTPS application assessment beyond the current generic single-host network path, with explicit URLs, safe defaults, authorization acknowledgement, and controls that prevent unbounded crawling or third-party targeting.

### Sprint 54 — Additional Scanner Adapters

Add complementary open-source engines such as Grype and Syft where they provide independent coverage or inventory value, while normalizing results into secscan-owned models and avoiding duplicate-noise inflation.

### Sprint 55 — AWS Compute Asset Association

Add read-only EC2 inventory/association so discovered compute assets can be linked to secscan assessments without enabling paid scanning services or mutating AWS resources.

### Sprint 56 — ECS/EKS Workload Association

Associate container images and assessment results with ECS tasks/services and EKS workloads using read-only AWS/Kubernetes metadata and bounded allow-lists.

### Sprint 57 — Tenant and Authorization Isolation

Evolve the existing local multi-user account foundation into explicit tenant/project ownership, role-scoped assets and scans, and storage/API isolation suitable for a future SaaS deployment.

### Sprint 58 — External Workflow Integrations

Add narrowly scoped outbound integrations such as GitHub issues, Jira, Slack, ServiceNow, or SIEM export. Each integration should be split further if required to preserve least privilege and a focused sprint boundary.

### Sprint 59 — Signed Policy and Governance Bundles

Add integrity/authenticity controls for shared policy bundles, controlled distribution, version/provenance evidence, and enterprise governance workflows.

## Backlog after the numbered candidate sequence

These remain valid ideas but are intentionally not assigned fixed sprint numbers yet:

- Windows web/API submission and reusable credential-profile workflow after the CLI scanner boundary is accepted
- richer remediation analytics and censored-aware timing metrics
- additional SBOM formats
- deeper license/dependency governance
- private registry authentication beyond current GitHub/ECR paths
- expanded release signing/provenance controls
- cross-source vulnerability/inventory correlation
- automated but bounded reassessment scheduling after persistent assets exist
- additional cloud providers
- agent-based assessment only if a later threat/cost review justifies it

## Planning rule

A candidate sprint becomes committed only after the preceding sprint is accepted and planning verifies that the scope remains the highest-priority small demonstrable increment. Security/correctness issues discovered in production or CI supersede this ordering and are fixed immediately.
