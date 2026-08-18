# Reachability and Parity

## Contents

- Coverage dimensions
- Reviewed ledger
- Classification rules
- Reporting
- Staleness

## Coverage dimensions

Classify these questions independently for every goal-relevant behavior:

1. **Shipped-data reachability:** Can the selected retail data and gameplay
   route invoke the behavior?
2. **Reusable interpreter completeness:** Does the target implement the broader
   opcode, action, packet, or format contract beyond shipped-reachable cases?
3. **Implementation:** Is the behavior implemented, partially implemented,
   deliberately replaced, missing, inapplicable, or still unknown?
4. **Semantic parity:** Has observable behavior been compared at the required
   level, including state, timing, ownership, presentation, and failure paths?

Non-reachability is a scope boundary, not proof that code is irrelevant or safe
to delete. A portable service substitution can be implementation-equivalent
without matching retail internals.

## Reviewed ledger

Append one reviewed classification to `coverage.jsonl`:

```json
{
  "id": "coverage-shell-main-menu",
  "behavior_id": "behavior-shell-main-menu",
  "scope": {
    "retail_data": "retail-v1.0",
    "binary_digest": "sha256:...",
    "target_revision": "source revision or absent"
  },
  "shipped_data_reachability": {
    "status": "reachable",
    "evidence_ids": ["ev-shell-data-001"]
  },
  "reusable_interpreter": {
    "status": "not_applicable",
    "evidence_ids": []
  },
  "implementation": {
    "status": "missing",
    "evidence_ids": []
  },
  "semantic_parity": {
    "status": "unknown",
    "evidence_ids": []
  },
  "review_state": "reviewed",
  "confidence": "high",
  "reviewed_by": "coordinator",
  "timestamp": "2026-01-01T00:00:00Z"
}
```

Generated scans and candidate matches are evidence inputs. They must not
overwrite a reviewed classification. Append a superseding record when evidence,
retail data, the binary, or the target revision changes.

## Classification rules

Use `reachable`, `not_reachable`, or `unknown` for shipped-data reachability.

Use these statuses for the other three dimensions:

- `complete`: the bounded contract is implemented for the stated scope;
- `partial`: material behavior remains missing or differs;
- `equivalent`: a deliberate replacement satisfies the required contract;
- `missing`: no qualifying implementation exists;
- `not_applicable`: the dimension does not apply to this behavior;
- `unknown`: evidence is insufficient or stale.

Use `proposed`, `reviewed`, or `superseded` for `review_state`. Only reviewed,
non-superseded records contribute to current reporting.

## Reporting

Report each dimension with its own explicit denominator and scope. Include:

- reviewed versus unknown records;
- reachable complete/equivalent, partial, and missing behaviors;
- non-reachable interpreter gaps separately;
- parity verification level and important untested routes;
- confidence and stale-evidence counts.

Do not label function mappings, named symbols, commits, or static xrefs as
percent implemented. Prefer a prioritized gap list over a single percentage.

## Staleness

Treat a record as stale when its binary digest, retail-data identity, behavior
contract, target revision, or supporting evidence changes. Preserve the old
record and append a replacement with an explicit supersession link.
