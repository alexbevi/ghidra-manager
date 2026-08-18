---
name: ghidra-decompile
description: Coordinate long-running, evidence-driven reverse engineering and decompilation of binaries in Ghidra. Use when Codex needs to scan and index an active Ghidra program, locate entry points, walk direct and indirect function graphs, use strings and cross-references to recover names, classes, data structures, parameters, variables, and types, operate inside a persistent /goal, or orchestrate a coordinator and specialized subagents for exploration, renaming, consolidation, verification, cross-referencing, and comments or decoration.
---

<!--
Human invocation reference: create a goal whose objective explicitly names the
gated skill, for example:
`/goal Use $ghidra-decompile to analyze <program> and recover its program model.`
Implicit invocation is disabled, so `$ghidra-decompile` must appear in the goal.
-->

# Ghidra Decompilation

Recover a program incrementally while keeping Ghidra as the semantic source of
truth and a small external project directory as the coordination checkpoint.
Prefer verified, conservative names over complete-looking speculation.

## Load the supporting guidance

- Read [references/orchestration.md](references/orchestration.md) before
  delegating or resuming a multi-agent campaign.
- Read [references/evidence-and-naming.md](references/evidence-and-naming.md)
  before proposing or applying names, types, classes, or comments.
- Read [references/project-state.md](references/project-state.md) before
  initializing, validating, or repairing campaign state.
- Read [references/analysis-fidelity.md](references/analysis-fidelity.md)
  before accepting an imported program as the semantic analysis target.

The coordinator must read the required references itself. Do not delegate
interpretation of this skill.

## Preserve the goal

1. Call `get_goal` at the start of every goal turn and after any context
   compaction.
2. If a goal is active, copy its exact objective into `project.json`. Treat it
   as the completion invariant; do not narrow it to the current batch.
3. If no goal is active, continue normally. Do not create one unless the user
   explicitly requests it. Mention that a `/goal` is useful for a campaign
   expected to span turns.
4. Keep the goal active while evidence-backed work remains. A turn boundary,
   checkpoint, empty worker wave, or clean-looking decompiler is not
   completion.
5. Call `update_goal(status="complete")` only after the completion audit below
   proves the full objective. Follow the platform's strict blocked-goal rules;
   do not invent a weaker skill-specific threshold.

## Establish campaign state

Choose a state directory outside generated Ghidra installation state. Prefer an
existing user-designated reverse-engineering workspace; otherwise use a
dedicated directory such as:

```text
~/.codex/ghidra-decompile/projects/<program-slug>/
```

Inside this repository, use the ignored `.ghidra-decompile/<program-slug>/`
directory. Never place campaign state, transformed binaries, traces, or other
program-specific artifacts under `skills/ghidra-decompile/`.

Initialize it once:

```bash
python3 scripts/init_project.py \
  --output <state-dir> \
  --project <ghidra-project> \
  --program <program-name> \
  --program-path <ghidra-program-path> \
  --goal "<exact goal objective>"
```

Run `scripts/validate_project.py <state-dir>` before resuming a campaign and
after material state edits. Never overwrite an existing campaign with the
initializer.

## Connect to the exact program

Before analysis or mutation:

1. List Ghidra instances and connect to the exact project.
2. List open programs, switch to the target, and read current program,
   language, image-base, address-space, format, analysis, and save state.
3. Record stable identity fields in `project.json`. If identity differs on
   resume, stop rather than applying saved addresses to another binary.
4. Inspect available Ghidra MCP tool groups. Load `analysis`, `xref`,
   `datatype`, `documentation`, `symbol`, and `comment` when the bridge is
   lazy. Use the live schema instead of assuming tool argument shapes.
5. Confirm analysis is idle before taking a baseline or applying a batch.

Do not treat a successful launcher command as proof of connectivity. Verify the
responding instance and open program.

Do not weaken bridge policy merely to enable inline scripts. When script
execution is disabled, use native MCP inventory, analysis, xref, and batch
tools; record any audit coverage that remains unavailable.

## Phase 0: Prove analysis fidelity

Before naming or modeling behavior, prove that Ghidra exposes the executable
content the retail loader can reach. Follow `references/analysis-fidelity.md`.

Inspect the file container, relocation model, overlays, appended payloads,
compression, embedded executables, segment aliases, and loader-created memory
map. Identify compiler runtime code and establish the applicable near/far,
register-return, stack-cleanup, and hidden-parameter conventions.

If the original import omits reachable code, preserve it unchanged and create a
reproducible derived analysis image under the campaign `artifacts/` directory.
Record source and result digests, the immutable transformation tool identity and
arguments, the Ghidra program path, address mapping, and validation counts in
`project.json`. Compare the original and derived imports before choosing the
semantic source program.

Do not start broad semantic recovery while fidelity is `pending` or `blocked`.
Record limitations explicitly when a complete import is impossible.

## Phase 1: Baseline and index

Capture counts and inventories before renaming:

- entry points, memory segments, imports, exports, namespaces, and classes;
- functions by source and naming class;
- strings, string tables, resources, globals, and data items by references;
- data types, structures, enums, and function signatures;
- code gaps, undefined functions, orphan code targets, and address-taken code;
- default parameters, stored locals, decompiler-visible defaults, and
  decompile failures.

Paginate every inventory to exhaustion or record the exact limit and remaining
cursor. Prefer bulk tools for complete scans and retain their query parameters
with the evidence.

Store aggregate counts in `progress.json`; store detailed findings as JSONL
evidence rather than turning progress into a symbol ledger.

Inspect analyzer configuration before rerunning analysis. Prefer selective
analyzers supported by the binary format and observed failure mode. Rebaseline
after reanalysis because it can create functions or invalidate earlier counts.

## Phase 2: Find roots and build the graph

Start from all defensible roots, not only the nominal executable entry:

- loader and runtime entry points;
- exported functions and callbacks registered with APIs;
- initialization, main loop, shutdown, and error paths;
- switch and jump tables;
- function-pointer tables, vtables, callback arrays, and address-taken code;
- script, event, resource, scene, command, or message dispatchers.

Walk callers and callees breadth-first, but prioritize frontier nodes with
strong anchors: distinctive strings, imports, named globals, structured data,
or multiple already-understood neighbors. Record graph edges and unresolved
indirect targets as evidence.

Use strings as anchors:

1. Index strings by address, encoding, segment, and all xrefs.
2. Cluster related strings such as resource paths, format strings, errors,
   commands, UI labels, file extensions, and subsystem prefixes.
3. Trace each cluster through referencing functions, callers, callees, and
   nearby tables.
4. Name behavior from control flow and data use, not from a string alone.

## Phase 3: Fan out by bounded subsystem

Keep the coordinator active and spawn only concrete tasks with an address
range, root set, string cluster, table, or subsystem boundary. Use waves sized
to available concurrency.

Good first-wave tasks are:

- entry-path and direct-call indexing;
- string/xref clustering;
- indirect-call, jump-table, and structured-data discovery.

Later waves can cover independent subsystems. Use the role and handoff
contracts in `references/orchestration.md`. Never let two write-capable agents
mutate the same Ghidra program concurrently.

## Phase 4: Recover one subsystem at a time

For each cluster:

1. Inspect decompilation, disassembly, variables, callers, callees, xrefs,
   strings, globals, and data layout.
2. Produce an evidence-backed rename/type plan.
3. Resolve conflicts and choose conservative names.
4. Grant one agent an exclusive mutation lease for the bounded batch.
5. Apply types before dependent variable names when type information makes the
   meaning clearer.
6. Apply the smallest coherent transaction.
7. Read back every changed function, symbol, type, prototype, and comment.
8. Have a different agent verify the batch against evidence.
9. Save the Ghidra program only after verification.
10. Rerun structural and meaningful-local audits, update state atomically, and
    enqueue newly exposed frontier work.

If a structure overlaps existing stack fragments, inspect storage and remove
only contained fragments proven to be decompiler artifacts before applying the
aggregate. If a saved type lookup fails, inspect its actual category/path rather
than recreating a duplicate.

## Phase 5: Consolidate and decorate

After several mutation batches:

- merge duplicate names and data types;
- reconcile subsystem vocabulary and calling conventions;
- validate class boundaries, ownership, and shared structures;
- propagate verified prototypes and field types through callers;
- cross-reference matching functions in other versions or binaries;
- add concise plate/decompiler/disassembly comments for entry paths,
  dispatchers, non-obvious invariants, data layouts, and uncertainty;
- update the campaign architecture document with confirmed subsystem and data
  relationships.

Comments must explain evidence and behavior, not narrate the reverse-engineering
session. Preserve uncertainty explicitly.

## Completion audit

Treat completion as unproven until all applicable checks pass:

- the connected project, program, and binary identity match campaign state;
- analysis is idle and the program is saved;
- every requested symbol class has a baseline and final audit;
- unresolved functions, placeholder symbols, code gaps, orphan targets, and
  indirect dispatch entries are either resolved or explicitly evidenced as
  non-code, unreachable, external, or low-confidence;
- remaining default parameters and locals are separated into live stored
  variables versus decompiler phantoms;
- no high-confidence rename/type task remains queued;
- all applied batches have independent readback verification;
- important roots, dispatchers, types, and subsystem boundaries are decorated;
- architecture and cross-reference notes match current Ghidra state;
- `scripts/validate_project.py <state-dir>` passes.

Report baseline-to-final counts, unresolved exceptions, saved-state status, and
the exact evidence supporting completion. A zero `FUN_*` count alone is not a
completion signal.
