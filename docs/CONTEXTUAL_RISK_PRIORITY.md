# Contextual Risk Priority — Foundation (Issue #209)

This increment introduces `secscan.risk_priority.assess_finding_priority`, a pure
function over a normalized finding document. It can consume existing scanner
severity and optional local CISA KEV and EPSS enrichment fields. Its foundation does not query tenants or assets. An optional report-builder
integration is now available without changing existing default report output.
The API, persistence, and tenant-owned resource queries remain unchanged.

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

## Opt-in report-builder integration

Python callers may pass `include_priority=True` to `build_report(...)` after
supplying already-authorized scan findings. This adds a `priority` object to
each normalized finding and a `summary.priority` breakdown of urgent, high,
medium, low, and unassessed counts. Priority assessment happens **after**
optional KEV and EPSS enrichment and uses only that existing local evidence.
The opted-in JSON document uses schema version `1.3`; without the argument,
the report stays exactly on its existing `1.0`/`1.1`/`1.2` schema behavior.

```python
from secscan.report import build_report

report = build_report("example", findings, {"name": "Trivy"}, include_priority=True)
assert report["schema_version"] == "1.3"
```

The opt-in does not yet alter CLI flags, HTML report layout, public API routes,
or persisted jobs. Consumers must explicitly opt in, and no prioritization
reorders existing findings or triggers remediation.

## Deferred work

Connect findings to verified tenant-scoped asset identities, provenance,
scan timestamps, and explicitly verified exposure evidence. Add a separate
review of score thresholds, stale data, UI presentation and report schema
versioning before enabling priority output in production reports.

See #209 for the subsequent steps and acceptance boundaries.
