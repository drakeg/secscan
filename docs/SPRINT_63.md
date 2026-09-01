# Sprint 63 — Authenticated Network-Range Web/API Submission

## Goal

Expose the existing bounded `network-range` scanner through the authenticated local service and browser without weakening its authorization, target-count, sequential-execution, or scanner-argument boundaries.

## Scope

This sprint adds a dedicated `POST /api/v1/network-range-jobs` endpoint and a browser scanner option for literal IPv4/IPv6 addresses or CIDRs that expand to at most 16 scannable hosts.

The endpoint:

- requires `network_authorized: true` before any job is persisted
- validates and bounds the complete target range before handing work to the shared job pipeline
- reuses the existing `network-range` scanner identity and sequential Nmap/Nuclei execution
- retains normal tenant ownership, job status/history, filtering, policy, baseline, reporting, and artifact behavior through the existing service job machinery
- does not accept hostnames, URLs, target lists, files, arbitrary Nmap/Nuclei flags, scanner concurrency controls, or automatic discovery

The browser exposes a distinct **Network range — Bounded assessment** option with its own authorization acknowledgement and exact target guidance.

## Security/correctness repair

The pre-existing CIDR helper materialized all hosts before enforcing the 16-host limit. That was safe for the intended small ranges but could consume excessive CPU/memory if a very large IPv6 CIDR was supplied directly.

Sprint 63 changes expansion to consume at most `maximum + 1` hosts using `itertools.islice`, so oversized ranges fail at the bound rather than after full materialization. Regression coverage includes `2001:db8::/64`.

## API example

```bash
curl -X POST http://127.0.0.1:8000/api/v1/network-range-jobs \
  -H 'content-type: application/json' \
  -d '{
    "target": "192.0.2.0/30",
    "network_authorized": true,
    "fail_on": "NONE",
    "timeout": 600
  }'
```

When service authentication is configured, the existing session/bearer authentication boundary applies to this endpoint in the same way as the other protected service APIs.

## Out of scope

- ranges larger than 16 scannable hosts
- concurrent host assessment
- implicit subnet discovery
- hostname lists or DNS expansion
- scheduled/repeated network-range scans
- public/hosted unauthenticated scanning
- proof of target ownership beyond the explicit operator acknowledgement

## Cost

Current/projected recurring secscan infrastructure cost remains **$0**. This increment reuses the existing local service, Nmap, Nuclei, SQLite job store, and bundled template corpus.

## Acceptance criteria

- a request without explicit authorization is rejected before persistence
- malformed or oversized ranges are rejected before persistence
- huge IPv6 CIDRs fail without unbounded host materialization
- an authorized bounded range creates a normal `network-range` job and runs through the existing scanner pipeline
- normal job detail/history/filter/artifact paths remain available
- the browser provides a distinct range scanner option, range-specific authorization checkbox, bounded target help, and dedicated API submission path
- wheel verification requires the new Python and JavaScript modules
- Ruff, mypy, pytest, wheel/clean-install checks, container/Compose smoke, Trivy self-scan, CodeQL workflow, and the separate GitHub Advanced Security CodeQL check are green before merge
