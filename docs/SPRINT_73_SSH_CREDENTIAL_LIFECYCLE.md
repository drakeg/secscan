# Sprint 73 — SSH credential enabled lifecycle

This increment adds an owner-controlled enabled/disabled state for tenant-owned shared SSH credentials.

## Boundary

- Existing credentials are enabled by default for compatibility.
- Only the active tenant owner may change lifecycle state.
- Disabled credentials remain present as metadata for administration and historical evidence.
- A disabled credential cannot be explicitly selected for a new Linux-host scan.
- Disabling a credential clears its default flag and tenant host bindings so it cannot be selected implicitly for future scans.
- Re-enabling does not silently restore prior default or host bindings; the owner must make those choices explicitly.
- Lifecycle state is keyed by both tenant and credential ID, preserving the existing non-disclosing tenant boundary.
- Secret ciphertext is unchanged and is never returned by lifecycle operations.

No paid service or recurring infrastructure is introduced.
