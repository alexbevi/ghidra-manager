# Campaign Profiles

## Contents

- Select a profile
- Symbol recovery
- Reimplementation
- Shared boundaries
- Changing profile

## Select a profile

Choose exactly one profile when initializing the campaign. Derive it from the
user's objective rather than from the binary format or the apparent amount of
unnamed code.

Use `symbol-recovery` for objectives such as:

- rename all defensible placeholder functions;
- recover structures, enums, variables, or prototypes;
- produce a clean and navigable Ghidra database;
- synchronize verified documentation between binary variants.

Use `reimplementation` for objectives such as:

- reproduce a feature or subsystem in a source port;
- understand a game engine's runtime contracts;
- compare retail behavior with an existing implementation;
- identify implementation gaps or parity risks.

## Symbol recovery

Use symbols and type classes as explicit coverage units. Inventory the requested
classes, recover high-confidence items, record low-confidence exceptions, and
perform the full mutation/readback/save audit.

A symbol-recovery campaign can legitimately require zero placeholder names, but
that count does not prove code discovery, behavioral understanding, or runtime
parity.

## Reimplementation

Use bounded observable behaviors and external contracts as coverage units.
Prioritize reachable dispatchers, state transitions, resource formats,
ownership, timing, failure behavior, and portable service boundaries.

Name and type only enough surrounding code to make each behavior defensible and
usable. Treat compiler runtime helpers, unreachable branches, and unrelated
subsystems as contextual unless the objective expands to include them.

Do not report function, address, commit, or symbol counts as percent
reimplemented. Several retail functions can map to one portable service, and a
single dispatcher or interpreter can cover many shipped behaviors.

## Shared boundaries

Both profiles require:

- exact program and binary identity;
- analysis-fidelity readiness;
- evidence-backed claims and explicit uncertainty;
- serialized Ghidra mutations with independent readback;
- saved-state and campaign-state validation;
- an objective-specific completion audit.

## Changing profile

Do not silently change the campaign denominator. When the user changes the
objective, either create a new campaign or record an explicit profile migration
with the old profile, new profile, reason, timestamp, and resulting task audit.
