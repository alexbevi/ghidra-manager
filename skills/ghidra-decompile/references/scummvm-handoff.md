# ScummVM Implementation Handoff

## Contents

- Inspect the target
- Choose the implementation boundary
- Distinguish substitutions
- Record the mapping
- Define validation
- Implement in reviewable slices

## Inspect the target

Before proposing a mapping, inspect the exact ScummVM checkout and record its
revision. Read repository instructions and the target engine's architecture,
source, tests, TODOs, and relevant history. Treat documentation and commit
messages as evidence seeds; verify behavior against current code and retail
evidence.

Search for existing parsers, dispatch registries, platform services, resource
identifiers, state objects, and neighboring engines with applicable patterns.
Do not invent a new abstraction before understanding the existing engine
boundary.

## Choose the implementation boundary

Map a behavior slice to the smallest coherent target component. Record exact
paths and symbols. Prefer a reviewable vertical slice containing the parser or
runtime change, target documentation, tests, and fixtures needed to make the
behavior usable.

Preserve traceability to retail roots and canonical resource IDs. Avoid porting
low-level retail helpers when one established ScummVM service satisfies their
external contract.

## Distinguish substitutions

Classify the strategy as:

- `faithful`: reproduce the retail engine behavior in the target engine;
- `portable-equivalent`: use ScummVM services while preserving the reviewed
  external contract;
- `intentional-deviation`: retain a documented, reviewed semantic difference;
- `unimplemented`: no qualifying target behavior exists.

Typical portable boundaries include filesystem streams, platform events,
graphics presentation, audio mixers and clocks, codecs, save infrastructure,
and host UI. Keep game-specific ordering, state transitions, resource
selection, ownership, cleanup, and failure behavior in the engine when the
retail contract requires them.

## Record the mapping

Append one object to `mappings.jsonl`:

```json
{
  "id": "mapping-shell-main-menu",
  "behavior_id": "behavior-shell-main-menu",
  "target": {
    "kind": "scummvm",
    "repository": "/path/to/scummvm",
    "revision": "git revision",
    "paths": ["engines/example/menu.cpp"],
    "symbols": ["ExampleEngine::runMainMenu"]
  },
  "retail_contract": ["Menu owns input until a selection returns"],
  "strategy": "faithful",
  "service_substitutions": [],
  "retained_engine_semantics": ["Persist selected chain state before launch"],
  "validation": {
    "unit_tests": ["menu state transition test"],
    "fixtures": ["retail menu resource"],
    "interactive_replay": ["Start new game and choose the first mission"]
  },
  "evidence_ids": ["ev-shell-001"],
  "confidence": "high",
  "status": "ready",
  "source_task": "map-scummvm-implementation",
  "timestamp": "2026-01-01T00:00:00Z"
}
```

Use `draft`, `ready`, `implemented`, `verified`, or `superseded` for status.

## Define validation

Calibrate validation to the claim:

- parser and data-layout claims: fixtures and unit tests;
- dispatch and state-transition claims: focused engine tests or debug routes;
- timing, palette, audio, modal ownership, and cleanup claims: targeted
  interactive replay against retail observations;
- broad parity claims: multiple explicit routes and data-set coverage.

A successful build establishes compilation only. A unit test establishes its
asserted contract only. Record replay separately.

## Implement in reviewable slices

When implementation is authorized, keep each commit to one usable behavior or
tightly coupled contract. Stage only the target files belonging to that slice,
preserve unrelated worktree changes, run the repository-required validation,
and do not claim parity beyond the recorded evidence.
