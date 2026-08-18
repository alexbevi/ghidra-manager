# Behavior Slices

## Contents

- Slice boundary
- Required record
- Lifecycle
- Evidence expectations
- Review rules

## Slice boundary

Model one observable behavior or external contract that an implementer can
reason about and validate independently. Good slices include a scene action, a
script opcode, a resource decoder operation, a state transition, a UI command,
or a save/load operation.

Avoid both extremes: do not create one record per low-level helper, and do not
collapse an entire engine subsystem into one record. Split when triggers,
ownership, resource contracts, or validation routes differ materially.

## Required record

Append one object to `behaviors.jsonl`:

```json
{
  "id": "behavior-shell-main-menu",
  "title": "Run the shell main menu",
  "program": "/GAME.EXE",
  "retail_roots": ["4245:02d4"],
  "trigger": {
    "route": "Startup after shell initialization",
    "inputs": ["argc", "argv"],
    "preconditions": ["Shell resources are loaded"]
  },
  "state_reads": ["chain-state word"],
  "state_writes": ["selected executable chain state"],
  "control_flow": ["Dispatch menu until launch or exit"],
  "resources": ["shell menu resources"],
  "timing_and_ownership": ["Menu owns input until it returns"],
  "side_effects": ["Persist shell state"],
  "error_and_fallback_paths": ["Fatal shell exit on resource failure"],
  "evidence_ids": ["ev-shell-001", "ev-shell-004"],
  "confidence": "high",
  "verification": "static",
  "status": "evidenced",
  "unresolved": [],
  "source_task": "recover-shell-main-menu",
  "timestamp": "2026-01-01T00:00:00Z"
}
```

Use qualified addresses when the program has multiple address spaces. Keep
instructions and decompiler syntax in evidence artifacts; express the behavior
record in domain terms without adding unsupported intent.

## Lifecycle

Use:

```text
draft -> evidenced -> ready-for-implementation -> implemented -> verified
```

- `draft`: the boundary or root set remains provisional.
- `evidenced`: the retail contract is supported but has unresolved items.
- `ready-for-implementation`: the bounded contract and validation route are
  sufficient to implement without reopening broad reconnaissance.
- `implemented`: a target implementation exists but parity is not proven.
- `verified`: the stated validation route passed at a recorded revision.

Never infer `implemented` or `verified` from Ghidra decoration.

## Evidence expectations

Require direct control-flow or data-flow evidence plus an independent category
for high confidence. Link every material branch, state mutation, resource
contract, timing/ownership rule, and error path to evidence. Record an omitted
or unreachable branch explicitly rather than silently simplifying it.

## Review rules

- Review the slice boundary separately from its semantic claims.
- Keep retail observations separate from target implementation decisions.
- Preserve uncertainty in `unresolved`; do not hide it in broad wording.
- Reopen the slice when a loader, type, prototype, resource schema, or runtime
  trace invalidates one of its dependencies.
