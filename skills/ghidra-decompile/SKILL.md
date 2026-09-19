---
name: ghidra-decompile
description: Coordinate long-running, evidence-driven reverse engineering and decompilation of binaries in Ghidra for either symbol recovery or software reimplementation. Use when Codex needs to scan and index an active Ghidra program, locate entry points, walk direct and indirect function graphs, recover names and types, extract behavior for a source port or game-engine reimplementation, operate inside a persistent /goal, or orchestrate bounded exploration, mutation, consolidation, verification, and documentation.
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

## Load only the current mode

Read the [manager tool guide](../../tools/README.md) for command schemas and
budget accounting. Use its bounded artifacts instead of regenerating scripts or
loading full historical checkpoints.

- At first import, read [analysis fidelity](references/analysis-fidelity.md).
- For names and types, read [evidence and naming](references/evidence-and-naming.md).
  Before runtime/library naming, also read
  [function identification](references/function-identification.md).
- At initialization or when repairing state, read
  [project state](references/project-state.md) and
  [campaign profiles](references/campaign-profiles.md).
- For independent review, use [ghidra-verify](../ghidra-verify/SKILL.md).
- For ownership, shared-tail, or dispatcher damage, use
  [ghidra-analysis-repair](../ghidra-analysis-repair/SKILL.md).
- For delegated work, read [orchestration](references/orchestration.md).
- For reimplementation, read [behavior slices](references/behavior-slices.md)
  and [reachability and parity](references/reachability-and-parity.md).
  Load [resource entry graphs](references/resource-entry-graphs.md) when game
  data drives execution, [runtime validation](references/runtime-validation.md)
  for runtime claims, and [ScummVM handoff](references/scummvm-handoff.md) for
  that target.

Read a reference when entering its mode, not at every batch. The coordinator
retains responsibility for interpreting applicable requirements.

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

## Budget every work session

Use `ghidra-manager campaign --state DIRECTORY session start` with the default
100,000-token allowance, or an explicit `--tokens` value from the user. Record
available goal/session cumulative usage through `usage record` before starting
work and after every batch. The first observation establishes the session baseline.
State which agents the measurement covers; do not add overlapping counters or
claim missing worker usage is measured. Unknown usage blocks new autonomous work.

Run `admit` before each batch. Report consumed, remaining, and measurement scope
at the start, after each batch, at 80%, and in the final response. At exhaustion,
finish only verification, recovery, and saving already-active work; report any
overshoot. Budget exhaustion pauses admission, not the original objective.
`budget set --tokens N` changes the allowance without erasing usage. Do not raise
it autonomously or silently start another session to bypass the limit. The CLI
cannot interrupt an in-flight response or measure weekly account allowance.

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

Prefer the packaged `ghidra-manager campaign --state DIRECTORY init` command.
Use its `status`, `validate`, and `report` commands for offline campaign state.
Initialize once with the full Ghidra program path, then resume the same directory:

```bash
ghidra-manager campaign --state <state-dir> init --project <project> \
  --program <program-name> --program-path /<program-name> \
  --profile symbol-recovery --goal "<exact goal objective>"
ghidra-manager campaign --state <state-dir> validate
ghidra-manager campaign --state <state-dir> report
```

Treat JSON and JSONL as canonical; regenerate summaries instead of editing them.
The old scripts are compatibility wrappers. New workflows use the manager CLI.

## Choose the campaign profile

Follow `references/campaign-profiles.md` and record one profile in
`project.json`:

- Use `symbol-recovery` when the objective explicitly asks for a clean,
  documented Ghidra database or named/type-recovered symbol classes.
- Use `reimplementation` when the objective is to understand, reproduce, port,
  or validate program behavior in another codebase.

Do not turn a reimplementation campaign into an unnamed-symbol sweep. Recover
additional symbols only when they support a reachable behavior, external
contract, shared data model, or stated acceptance criterion.

For a reimplementation campaign, record the target repository identity and
revision before classifying implementation or parity. When the target is
ScummVM, inspect its repository instructions, engine architecture, existing
services, implementation, tests, and relevant history before creating mappings.

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

Before broad manual runtime naming, inventory compatible Function ID databases,
signature sets, debug symbols, map files, source archives, and matching reference
binaries. Follow `references/function-identification.md`; record why each source
was selected or rejected, and do not treat a third-party match as self-proving.

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

For data-driven programs, inventory shipped resources and dispatch values before
assuming the static call graph defines reachability. Record archive members,
scripts, opcodes, action IDs, packet commands, save records, parsers,
dispatchers, and runtime consumers in `resources.jsonl`. Use their references as
graph roots alongside functions and strings.

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

## Phase 3: Select bounded work

Use `task add` and `next` to select a coherent subsystem or evidence-backed
frontier. Keep naming tasks to ten targets or fewer. Separate naming, types, and
repair queues; dependencies must be complete before a task starts. After two
failures, retain the evidence and defer the task. An explicit retry needs a reason.

Default to one analyst and one independent reviewer. Delegate additional work
only when authorized, independently useful, and covered by the remaining budget.
Give workers an address set, bounded packet, acceptance criteria, and output
artifact path. Never allow concurrent mutation of one program.

## Manager-backed batches

Use `scan`, `packet`, and `diff` to collect and compare evidence locally. Read the
bounded packet, not entire snapshot collections. Consult `metrics` to check
cache reuse and accepted changes per reported token. Do not convert local
operation counts into claimed model-token savings. Keep naming separate from types
and analysis repair. Submit a declarative `plan`, then `apply`, `verify`, and
`finalize` with a passing independent review. Use the `ghidra-verify` companion
skill for that review. A tool success is not evidence that a name is correct.
A timed-out write requires `reconcile`, never an automatic retry.

For layout and ABI changes, review the full changed native-output set. Register
arguments and returns require explicit storage; do not guess Watcom preservation
rules from a compiler label. A custom calling convention stays program-local.
For control flow, run `trial`, obtain independent review bound to the trial hash,
then use `apply --trial-review`. The final review must bind to the actual applied
snapshot. Neither a passing trial nor a clean C listing is a saved checkpoint.

Default to one analyst and one reviewer with fresh task-local context. Additional
workers need a bounded task and available budget. Do not reload every historical
checkpoint or every reference when only one subsystem is active.

## Phase 4: Recover one subsystem at a time

For each cluster:

1. Inspect decompilation, disassembly, variables, callers, callees, xrefs,
   strings, globals, and data layout.
2. Produce the profile-specific deliverable: a rename/type plan for
   `symbol-recovery`, or a bounded behavior contract in `behaviors.jsonl` for
   `reimplementation`.
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

For a reimplementation slice, require the exact trigger route, retail roots,
inputs and preconditions, state reads and writes, control-flow decisions,
resources, timing and ownership, side effects, error/fallback paths, evidence,
and unresolved questions defined in `references/behavior-slices.md`. Do not use
a prose summary as a substitute for the machine-readable record.

After reviewing a behavior slice, append its independent reachability and parity
dimensions to `coverage.jsonl`. Keep shipped-data reachability, reusable
interpreter completeness, implementation status, and semantic parity separate.
Never turn raw function, address, symbol, or commit counts into percent
reimplemented.

For runtime claims, record the reproducible route and paired retail/target
observations in `runtime.jsonl`. Preserve logs, traces, screenshots, state dumps,
or other raw captures under `traces/`. Static decompilation can establish a
contract hypothesis; it cannot establish timing, ownership, presentation, or
interactive parity by itself.

Map implementation-ready behaviors to the target in `mappings.jsonl`. Identify
exact target paths and symbols, whether the strategy is faithful or a portable
equivalent, service substitutions, engine-local semantics that must remain,
and unit/fixture/replay validation. Follow `references/scummvm-handoff.md` for
ScummVM targets.

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
- `ghidra-manager campaign --state <state-dir> validate` passes.
- `ghidra-manager campaign --state <state-dir> report` renders from canonical state without
  stale or dangling references.

Apply symbol-count and placeholder requirements only to `symbol-recovery` or an
explicit symbol-cleanup acceptance criterion. For `reimplementation`, audit the
requested behaviors and their evidence, dependencies, unresolved branches, and
validation routes instead; zero default names is neither required nor implied.
Report each coverage denominator from `coverage.jsonl` and list reachable or
important gaps. Do not collapse the dimensions into one completion percentage.

Report baseline-to-final counts, unresolved exceptions, saved-state status, and
the exact evidence supporting completion. A zero `FUN_*` count alone is not a
completion signal.
