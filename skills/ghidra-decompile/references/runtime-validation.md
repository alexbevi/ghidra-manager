# Runtime Validation

## Contents

- Validation objective
- Reproduction route
- Retail observation
- Target observation
- Differential review
- Evidence limits

## Validation objective

Observe one bounded behavior under reproducible conditions, then compare the
retail and target implementations at the level required by the behavior
contract. Prefer targeted replay over broad, unauditable playthrough claims.

## Reproduction route

Record enough detail for another investigator to reach the same state:

- executable and data-set identities;
- save, scene, mission, script, resource, action, or command identifiers;
- starting state and configuration;
- ordered user inputs or automated events;
- timing-sensitive waits or synchronization points;
- randomness controls and known nondeterminism;
- debugger, emulator, instrumentation, or logging configuration.

Keep the route narrowly tied to one behavior slice. Preserve reusable fixtures
or captures under `<state-dir>/traces/`.

## Retail observation

Observe the retail executable first. Capture applicable:

- function/dispatcher entry and exit;
- input values and state read before execution;
- state writes and externally visible side effects;
- resource, archive, file, script, or media accesses;
- clocks, delays, frame boundaries, audio position, and event ordering;
- input, cursor, palette, screen, audio, and modal ownership;
- return values, transitions, cleanup, and failure behavior.

Record observations, not interpretations. Link each interpretation back to raw
captures or independently evidenced static analysis.

## Target observation

Exercise the same route against the target revision and equivalent data. Record
the same observation categories, including portable service substitutions. Do
not normalize away a difference until its acceptability is reviewed.

## Differential review

Append one object to `runtime.jsonl`:

```json
{
  "id": "runtime-shell-menu-001",
  "behavior_id": "behavior-shell-main-menu",
  "route": {
    "steps": ["Start retail executable", "Enter main menu"],
    "inputs": ["No command-line switches"],
    "preconditions": ["Retail data set is installed"]
  },
  "retail": {
    "environment": "DOS emulator configuration",
    "revision": "sha256:...",
    "observations": ["Menu owns keyboard input until selection"],
    "artifacts": ["traces/shell-menu-retail.log"]
  },
  "target": null,
  "comparison": {
    "status": "retail-observed",
    "matched": [],
    "differences": [],
    "not_observed": ["Target implementation"]
  },
  "evidence_ids": ["ev-runtime-shell-001"],
  "review_state": "reviewed",
  "timestamp": "2026-01-01T00:00:00Z"
}
```

Use `retail-observed`, `matched`, `mismatched`, or `inconclusive` for comparison
status. Require a target observation for `matched` or `mismatched`.

## Evidence limits

- A build or unit test does not establish an interactive runtime claim.
- One successful route does not establish malformed-data or alternate-resource
  behavior.
- Static reachability does not establish event ordering, audio/video clocks,
  palette restoration, nested ownership, or suspended-state save/restore.
- A portable equivalent can pass parity when the reviewed external contract is
  preserved; identical low-level calls are not required.
