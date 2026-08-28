# Sprint 53 — Bounded Network-Range Assessment

## Goal

Add a tightly bounded network-range assessment capability without weakening the existing single-host network scanner or allowing arbitrary target sets.

## Included

- New `network-range` scanner capability exposed through the normal CLI registry.
- Literal IPv4/IPv6 addresses and CIDR input only.
- Deterministic ascending address expansion.
- Hard maximum of 16 expanded host addresses.
- Sequential execution only (`concurrency = 1`).
- Reuse of the existing fixed-flag Nmap/Nuclei single-host scanner for every expanded address.
- Standard normalized findings, policy, reporting, baseline, history, and artifact behavior through the existing CLI pipeline.
- Raw audit evidence recording the requested target, exact expanded targets, target count, maximum target limit, concurrency, and ordering.
- Unit coverage for deterministic expansion, single-IP input, invalid/hostname/list/URL rejection, oversized CIDR rejection, sequential scanning, and registry exposure.

## Security and correctness boundaries

- No hostnames are accepted by `network-range`; ranges must use literal IP addressing so expansion is deterministic and cannot change through DNS.
- No URLs, comma-separated lists, target files, arbitrary Nmap/Nuclei flags, public-host discovery, or automatic network enumeration are accepted.
- A CIDR expanding beyond 16 scannable addresses fails before any network tool is invoked.
- Nmap and Nuclei retain their existing fixed safe command construction, pinned template path, disabled update checks, and disabled Interactsh behavior.
- Range execution is sequential to prevent the range feature from multiplying scanner concurrency or creating an uncontrolled burst.
- The existing `network` scanner remains single-host only.
- The existing web/API single-host network submission contract is unchanged in this sprint. A later increment may expose `network-range` through the authenticated web/API boundary with the same explicit authorization acknowledgement.

## Acceptance criteria

1. `secscan scan network-range 10.0.0.0/30` expands deterministically to `10.0.0.1` and `10.0.0.2` and scans them in that order.
2. A single literal IPv4 or IPv6 address is accepted as a one-target range assessment.
3. Hostnames, URLs, comma-separated targets, and malformed input fail closed.
4. A range expanding to more than 16 hosts fails before Nmap or Nuclei runs.
5. Expanded targets are assessed sequentially using the existing `NetworkScanner` implementation.
6. Aggregated findings retain their per-host target identity and are deduplicated only by finding ID, target, and package type.
7. Raw evidence records the exact expansion and enforced controls.
8. Existing single-host `network` behavior and validation remain unchanged.
9. Python 3.12/3.14 preflight, packaging, Docker/Compose, Trivy self-scan, CodeQL Actions, and the separate GitHub code-scanning check are green.

## Cost

No paid service, hosted scanner, cloud resource, or recurring infrastructure cost is introduced. Current/projected recurring secscan service cost remains **$0**.
