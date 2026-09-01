# Sprint 62 — Signed Policy and Governance Bundles

## Goal

Make secscan YAML security policies portable across teams and environments without requiring operators to trust an unsigned file solely because of where it was downloaded or copied from.

## Scope

Sprint 62 adds an offline `secscan-policy` workflow built around Ed25519 signatures:

- `secscan-policy keygen` creates an explicit local signing keypair.
- `secscan-policy sign` validates one existing secscan YAML policy before signing it into a schema-versioned JSON bundle.
- `secscan-policy verify` verifies bundle structure, signer fingerprint, policy digest, Ed25519 signature, and policy semantics without contacting any network service.
- `secscan-policy verify --extract-policy ...` writes the exact signed YAML only after all verification gates succeed.

Each bundle carries:

- schema version
- bundle identifier
- governance version
- Ed25519 algorithm identifier
- SHA-256 signer fingerprint
- SHA-256 policy digest
- exact UTF-8 YAML policy bytes encoded as base64
- bounded source/provenance text
- signature over deterministic canonical JSON metadata and policy content

## Security boundaries

- Ed25519 is the only accepted signature algorithm in schema version 1.
- Private keys are never embedded in bundles, logs, reports, databases, environment variables, or service state.
- Generated private keys use owner-only `0600` permissions and existing key files are never overwritten.
- Bundle, key, extracted-policy, and output files are never overwritten implicitly.
- Signing requires the source YAML to pass the existing secscan policy parser first.
- Verification fails closed on unknown/missing top-level fields, wrong field types, unsupported schema/algorithm, malformed base64, digest mismatch, wrong signer fingerprint, invalid signature, invalid UTF-8, or invalid policy semantics.
- Policy content is limited to 1 MiB and the complete bundle to 2 MiB.
- Verification and extraction are entirely offline. This sprint adds no download URL, registry, package repository, background updater, trust-on-first-use behavior, or automatic key retrieval.
- The signer public key must be distributed through an independently trusted channel; secscan does not claim that possession of an arbitrary public key proves organizational trust.

## Governance model

The initial governance model is deliberately simple. A security team can keep the signing private key under its own operational controls, publish the public key through its existing trusted configuration-management channel, and distribute signed policy bundle files through any transport. Consumers verify the bundle against the independently obtained public key before extracting or applying the policy.

The bundle `bundle_id`, `version`, `source`, policy digest, and signer fingerprint provide stable provenance evidence that can be archived with scan/release records. This sprint does not introduce a central governance server or certificate authority.

## Out of scope

- hosted policy registry or automatic policy download
- private-key escrow, HSM/KMS integration, or secret-manager integration
- key rotation/revocation lists or multi-signature quorum policy
- certificate-chain/PKI trust
- automatic scan invocation directly from a bundle
- tenant-scoped policy distribution through the web service
- remote signing services
- paid infrastructure or recurring service cost

These can be evaluated as later increments if operational need justifies them.

## Cost

Current and projected recurring secscan infrastructure/service cost remains **$0**. Signing and verification are local operations using the cryptography dependency already required by secscan.

## Acceptance criteria

- a local Ed25519 keypair can be created without overwriting existing key material
- a valid YAML policy can be signed into a deterministic schema-versioned bundle
- a matching public key verifies the signed bundle offline
- a verified policy can be extracted byte-for-byte from the signed bundle
- tampered policy content, tampered signed metadata, and the wrong public key are rejected
- invalid source YAML cannot be signed
- generated private-key permissions are owner-only on POSIX systems
- package and container integrity checks require the signed-policy module
- Python quality/test/package checks, Docker/Compose smoke, Trivy self-scan, CodeQL workflow, and the separate GitHub Advanced Security CodeQL result are green before the PR is considered complete
