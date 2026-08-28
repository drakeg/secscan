# Sprint 49 — Explainable Web Risk Prioritization

## Goal

Make the existing CISA KEV and FIRST EPSS enrichment visible and useful in the secscan web dashboard without inventing an opaque aggregate risk score or changing scanner severity/policy semantics.

## Stories and acceptance criteria

- the web dashboard reads the enriched `secscan.json` artifact for completed scans and caches the result per job
- current posture continues to use only the newest completed scan for each scanner/target pair
- the **Most urgent targets** view ranks targets deterministically by:
  1. known-exploited (CISA KEV) finding count
  2. critical finding count
  3. high finding count
  4. maximum EPSS probability
  5. medium finding count
  6. total finding count
- KEV count is shown when a target has one or more known-exploited findings
- maximum EPSS probability is shown when EPSS enrichment is present
- the normal scan list surfaces the same KEV/EPSS signals alongside severity chips
- scans without KEV or EPSS enrichment remain fully supported and retain severity-only prioritization
- no synthetic secscan risk score is created
- no policy threshold, exit code, scanner severity, finding fingerprint, suppression, or baseline behavior changes

## Security and correctness boundaries

- the browser reads only existing authenticated secscan artifact endpoints; no new external HTTP service is contacted
- KEV and EPSS remain operator-supplied local enrichment datasets
- ranking is explainable from displayed inputs and does not claim mathematical risk quantification
- no automatic remediation or asset mutation is introduced
- no new credentials, network exposure, paid service, or cloud resource is introduced

## Operations and cost

- current recurring secscan infrastructure/service cost: **$0**
- projected recurring cost introduced by this sprint: **$0**

## Validation

Before merge:

- Python 3.12 and 3.14 preflight pass
- web asset regression coverage confirms KEV/EPSS prioritization code is shipped
- Docker/Compose service and login smoke pass
- authenticated Linux-host fixture passes
- Trivy fixable-critical self-scan passes
- CodeQL workflow and the separate GitHub code-scanning check pass on the exact PR head
