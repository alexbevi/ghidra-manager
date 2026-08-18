# Evidence and Naming Standard

## Contents

- Evidence categories
- Confidence policy
- Rename order
- Function and class recovery
- Structures and globals
- Parameters and locals
- Comments and cross-references
- Audit traps

## Evidence categories

Record addresses and concrete observations from these independent categories:

1. **Control flow:** branches, loop behavior, return values, error paths,
   callers, callees, and dispatch position.
2. **Data flow:** reads, writes, field offsets, array strides, allocation sizes,
   ownership, and lifetime.
3. **Strings and resources:** format strings, errors, paths, commands, labels,
   resource IDs, extensions, and string-table membership.
4. **External contracts:** imports, APIs, file formats, protocols, calling
   conventions, and runtime callbacks.
5. **Cross-binary evidence:** unique hashes, instruction equivalence, matching
   constants, sibling versions, debug symbols, or source ports.
6. **Runtime evidence:** observed calls, values, logs, files, or state changes.
7. **Similarity and proximity:** nearby functions, shared callees, analogous
   shape, and address neighborhood.

Similarity or proximity is supporting evidence, not an identity proof.

## Confidence policy

### High

Require a direct behavioral or data-layout observation plus at least one
independent corroborating category. High-confidence items may receive semantic
names and concrete types.

### Medium

Require one strong anchor with consistent surrounding behavior but incomplete
identity. Use a conservative capability name, record it as provisional, and
avoid false domain specificity.

### Low

Use when evidence is analogy, proximity, or weak similarity only. Do not rename
or type. Record a bookmark, tag, task, or unresolved evidence item instead.

Raise confidence only when new evidence is independent. Ten callers repeating
the same unsupported assumption are not ten pieces of evidence.

## Rename order

Within a subsystem, usually recover in this order:

1. roots, dispatchers, and distinctive leaf functions;
2. globals and tables that define subsystem vocabulary;
3. prototypes and calling conventions;
4. minimal structures, enums, arrays, and pointer types;
5. parameters and stored locals;
6. remaining helper functions;
7. comments, tags, bookmarks, and architecture notes.

Iterate when a recovered type reveals better function or variable semantics.

## Function and class recovery

Name functions by observed responsibility. Prefer verbs and domain nouns:
`LoadArchiveIndex`, `DispatchSceneAction`, `DecodeFlicFrame`.

Avoid claims such as `ValidateLicense` when evidence proves only a comparison
and branch. Use `CheckStartupToken` until the external meaning is established.

Infer a class only with object evidence such as:

- a stable `this` parameter;
- repeated field offsets across methods;
- constructor, destructor, allocation, or initialization behavior;
- a vtable or coherent method table;
- shared lifetime and ownership.

Otherwise use a subsystem namespace or free-function vocabulary. Do not turn
every pointer-bearing helper cluster into a class.

## Structures and globals

Recover the smallest proven layout first. Require repeated offset access,
allocation size, serialization layout, array stride, or cross-version agreement
before naming fields.

Use opaque bytes for unknown regions. Preserve offsets and size. Add fields as
evidence accumulates; do not force a complete structure.

Differentiate:

- a scalar global from a pointer to state;
- an inline array from a pointer;
- a table base from its elements;
- a resource identifier from an address or handle;
- a union-like overlap from contradictory guessed fields.

Validate every type after applying it and inspect all affected decompilations.

## Parameters and locals

Derive parameters from calling convention, call sites, use-def chains, and
field access. A parameter name must describe its role across callers, not one
caller's incidental value.

Before renaming locals:

1. Compare Ghidra's stored variable inventory with decompiler output.
2. Identify overlapping stack fragments and aggregate candidates.
3. Distinguish live storage from decompiler-synthetic `local_*` names.
4. Re-decompile after type changes.
5. Leave phantom defaults alone and record them in the meaningful-local audit.

Do not chase a zero default-local count by creating meaningless names or
persisting decompiler phantoms.

## Comments and cross-references

Use comments to record:

- observable behavior and side effects;
- accepted input and output meaning;
- dispatch/table membership;
- non-obvious field offsets or invariants;
- direct cross-version matches;
- uncertainty and excluded interpretations.

Avoid comments that merely restate the function name or describe the agent's
process.

For cross-binary matches, record source and target program identities,
addresses, match method, instruction count, hash/similarity, and material
differences. Do not transfer a name, type, or comment when the match is
non-unique or only shape-similar.

## Audit traps

- `FUN_* == 0` does not prove all functions were discovered.
- A clean function list does not prove jump-table or function-pointer targets
  are defined.
- Decompiled `local_*` names may be phantoms absent from stored variables.
- Reanalysis can add functions and reopen a clean audit.
- A wrong data-type category/path can look like a missing type.
- Aggregate stack types can overlap fragment locals and fail atomically.
- A readable decompilation can still contain a damaged function boundary or
  fall-through graph.
- One string can be diagnostic, incidental, or shared; inspect its use.
- A successful write response is not verification; read back and re-decompile.
