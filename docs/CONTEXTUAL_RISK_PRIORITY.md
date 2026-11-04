# Contextual Risk Priority — Foundation (Issue #209)

This increment introduces `secscan.risk_priority.assess_finding_priority`, a pure
function over a normalized finding document. It can consume existing scanner
severity and optional local CISA KEV and EPSS enrichment fields. It does not
modify scan reports, the API, persistence, or any tenant-owned resources yet.
Integration will be a separately reviewed increment.

## Advisory priority tiers (v0 proposal)

- **urgent**: an explicitly true `known_exploited` flag from trusted KEV enrichment
- **high**: scanner severity CRITICAL, or a validated EPSS probability >= 0.5
- **medium**: scanner severity HIGH or MEDIUM, without the above evidence
- **low**: scanner severity LOW, without the above evidence
- **unassessed**: no recognized scanner severity or positive prioritization evidence

This intentionally does **not** redefine scanner severity or claim that a
vulnerability is exploitable. EPSS is a probability estimate, not a proof of
asset exposure. The 0.5 threshold is a conservative initial triage rule for
later stakeholder review, not a formal risk standard.

## Evidence semantics

The output includes an ordered list of human-readable reasons and an evidence
object. Missing or malformed EPSS is ignored. A false or absent
`known_exploited` value is reported as **unknown**, not as proof that a
vulnerability is not exploited. Internet exposure, identity privilege, and
asset criticality are always **unknown** in this initial increment because no
verified asset context has been attached.

Example:

```python
from secscan.risk_priority import assess_finding_priority

result = assess_finding_priority({
    "severity": "HIGH",
    "known_exploited": True,
    "epss": {"score": 0.12},
})
assert result["tier"] == "urgent"
assert result["evidence"]["internet_exposure"] is None
```

## Security and operations

- No cloud API requests, host probing, outbound requests, new services, or
  paid dependencies.
- No tenant lookup or cross-tenant joins. Future integration must receive only
  already-authorized tenant-scoped inventory and validate source provenance.
- No persistent score and no automatic action. Decisions can be recomputed
  from input evidence, allowing threshold changes without migrations.
- Tests cover missing evidence, malformed scores, escalation precedence,
  and unknown network/identity/criticality context.

## Deferred work

Connect findings to verified tenant-scoped asset identities, provenance,
scan timestamps, and explicitly verified exposure evidence. Add a separate
review of score thresholds, stale data, UI presentation and report schema
versioning before enabling priority output in production reports.

See #209 for the subsequent steps and acceptance boundaries.
