# Sprint 54 — Bounded HTTP/HTTPS DAST Core

## Goal

Add a scanner-isolated, bounded HTTP/HTTPS application assessment core that can later be exposed through the authenticated service/UI without weakening existing authorization controls.

## Included

- new `web-dast` scanner registered through the standard scanner registry
- exactly one explicit `http://` or `https://` URL per scan
- URL normalization with a 2048-character ceiling
- rejection of non-HTTP schemes, missing hosts, embedded credentials, fragments, and invalid ports
- fixed Nuclei invocation using the existing pinned template corpus
- template updates disabled
- Interactsh/external callbacks disabled
- no arbitrary scanner flags
- no target lists
- no crawler/discovery feature enabled by secscan
- normalized project-owned findings
- raw audit evidence describing the bounded controls
- focused validation/command-hardening/registry tests
- wheel integrity coverage

## Security boundaries

The scanner does not accept arbitrary command-line options and passes the validated URL as one argument to a fixed Nuclei command. It does not enable target discovery, target lists, template updates, or Interactsh. Embedded URL credentials are rejected so secrets are not persisted into scan history or artifacts through the target field.

Nuclei templates can make application-layer requests required by the selected template corpus; therefore operators must scan only systems they own or are explicitly authorized to assess. Service/browser submission is intentionally deferred until the service's typed request model can add a dedicated authorization acknowledgement for this scanner. The existing generic `network` API is not broadened to accept URLs.

## Out of scope

- authenticated application sessions or browser automation
- credential/header/cookie injection
- crawler-driven endpoint discovery
- OpenAPI/Swagger import
- GraphQL schema discovery
- target lists or multiple domains
- web/API service submission
- public anonymous scanning
- arbitrary Nuclei flags or templates
- hosted callback services

## Cost

Current and projected recurring secscan infrastructure/service cost remains **$0**. This increment reuses the existing Nuclei binary and pinned local template corpus.

## Validation

Required before merge:

- Ruff
- mypy
- pytest on supported Python versions
- wheel and clean-install verification
- Docker/Compose smoke validation
- authenticated Linux fixture regression validation
- fixable-critical container self-scan
- CodeQL workflow
- separate GitHub Advanced Security CodeQL check on the exact PR head
