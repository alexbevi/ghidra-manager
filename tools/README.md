# Campaign tools

Use the installed `ghidra-manager` entrypoint. Commands work without a checkout;
campaign artifacts belong outside the managed Ghidra installation.

```sh
ghidra-manager campaign --state ./campaign init --project fixture \
  --program fixture.exe --program-path /fixture.exe --goal 'Recover symbol names'
ghidra-manager campaign --state ./campaign --json status
ghidra-manager campaign --state ./campaign validate
ghidra-manager campaign --state ./campaign report
```

Lifecycle commands are offline: they neither connect to nor save Ghidra.
Initialization refuses a nonempty directory. Existing version 1 and 2 campaigns
remain readable, and the legacy skill scripts remain compatibility wrappers.
Reports render from canonical evidence without rewriting it.

## Session budgets

```sh
ghidra-manager campaign --state ./campaign session start --tokens 100000
ghidra-manager campaign --state ./campaign usage record --source goal \
  --stream root --measurement baseline --counter 2000000 --scope root
ghidra-manager campaign --state ./campaign usage record --source goal \
  --stream root --measurement batch-1 --counter 2025000 --scope root
ghidra-manager campaign --state ./campaign budget show
ghidra-manager campaign --state ./campaign budget set --tokens 150000
ghidra-manager campaign --state ./campaign session finish
```

The first counter establishes a baseline, not a charge for earlier work. Every
measurement ID is immutable and retry-safe. Sources covering the same agents
cannot be added together. Supply each covered agent with `--scope`; do not claim
worker coverage unless the source includes it. Counter resets require
reconciliation, never an automatic reset. Missing telemetry is reported as unknown.

The default allowance is 100,000 reported tokens. Adjusting it preserves consumed
usage and records the adjustment. A new session requires finishing the old one;
its baseline is fresh while campaign totals remain. Reports warn at 80%, identify
exhaustion at 100%, and expose overshoot. These numbers are counter deltas, not
weekly allowance, provider charges, or a mechanism to interrupt a model response.

Before each new autonomous batch, record current telemetry and run
`ghidra-manager campaign --state ./campaign admit`. Exit 3 means new work is
blocked by an unknown or exhausted budget. `admit --purpose verify`, `recover`,
and `save` permit closing an existing batch even after exhaustion; these are not
permission to expand its scope. Admission checks are read-only. They cannot stop
in-flight model responses, so record overshoot honestly.

## Complete inventories

`ghidra-manager campaign --state ./campaign scan --port 8089` captures the exact
program recorded by `init`. A bundled collector walks complete Ghidra iterators,
including qualified addresses, symbols, variables, types, strings, call edges,
flow overrides and program options. It reports counts and a content-addressed
artifact path, not the inventory itself. It refuses busy analysis, script errors,
partial results, and identity drift. Identical captures reuse the existing file.
Scripts must already be enabled by your GhidraMCP policy; the manager does not
enable them. Scanning never edits program semantics or saves Ghidra.

## Evidence packets

`ghidra-manager campaign --state ./campaign packet 00401000 --port 8089`
refreshes inventory, checks admission, and captures only uncached functions.
Cache keys include exact function metadata, callers/callees, referenced symbols,
all type definitions, program options, identity and collector version. Type and
option changes conservatively invalidate packets. A second capture detects edits
during collection. Raw evidence stays in the cache; the default packet is at most
32 KiB. Use `--max-bytes` to adjust it. Oversized functions are explicitly omitted
and `complete` is false: narrow the request or deliberately increase the limit.
Do not treat an incomplete packet as sufficient evidence for a mutation.
Both inventories use canonical ordering for freshness checks; changes in iterator
order alone do not invalidate evidence, while changed type definitions still do.

## Incremental verification

`ghidra-manager campaign --state ./campaign diff BEFORE.json AFTER.json` compares
retained snapshots. Pure decoration or stored-variable naming does not request
native decompilation. Other function changes include direct callers. Shared-type
or configuration changes, and uncertain indirect-consumer coverage, request a
full audit. The tool reports exactly why. Raw snapshots remain authoritative;
this classifier never treats cosmetic similarity as proof of semantic parity.

Collectors use the bounded script endpoint and a local temporary result file.
Only a completion marker enters Ghidra's console: printing a whole inventory can
stall an open Ghidra log viewer. A timeout is not proof that the server stopped;
reconcile live state before retrying any write. No automatic write retries occur.

## Rename proposals

Run `campaign --state DIRECTORY plan PROPOSAL.json` after `scan` and budget
admission. Example proposal:

```json
{"author":"analyst","changes":[{"kind":"function","address":"00401000",
"old_name":"FUN_00401000","new_name":"parse_header","evidence_ids":["ev-header"]}]}
```

Evidence IDs must already exist in the campaign evidence ledger. Global label
renames use `kind: global` and the exact numeric `symbol_id` from the snapshot.
Proposals require existing prior names, unique targets, and collision-free simple
identifiers. No type or flow fields are accepted. A retained plan binds the
snapshot, target fingerprints, and author; editing it invalidates its identifier.
Planning does not connect to or mutate Ghidra. Semantic confidence still requires
independent evidence review.

Stored variables use `kind: parameter` or `kind: local`, the owning function's
`address`, and the exact `storage` string in the snapshot. The target must resolve
uniquely. Decompiler-only temporaries have no persistent storage and are rejected.
This operation only names existing variables; it never creates or merges stack
storage or changes a datatype, ABI, or parameter list.

## Applying and reconciling naming batches

`campaign --state DIRECTORY apply PLAN.json --port 8089` rechecks identity,
snapshot and target fingerprints, then applies the entire batch in one Ghidra
transaction. Names are read back inside that transaction. A program-local receipt
and a campaign batch record identify the operation. The program remains unsaved
and the batch requires independent review. Existing mutation leases block apply.

After any uncertain response, use `campaign --state DIRECTORY reconcile --port
8089`. This only reads live state and the transaction receipt. A missing receipt
is unresolved, because a timed-out request may still be queued; it does not
trigger another write. Keep the project open and reconcile before further changes.

`campaign --state DIRECTORY self-test` runs the packaged inventory, decompiler,
and rename scripts against a temporary two-function raw binary in a separate
headless Ghidra process. It tests mid-batch rollback, successful readback, and
receipt-based replay, then deletes its temporary project. The existing GUI and
retail programs are not touched. A retained log records compilation and runtime
failures. This requires the managed Ghidra installation and JDK 21.

## Independent review and save

`campaign --state DIRECTORY verify --port 8089` repeats mechanical readback and
returns the exact `after_snapshot` to review. A different reviewer supplies:

```json
{"plan":"PLAN_ID","after_snapshot":"SNAPSHOT_ID","reviewer":"reviewer-id",
"verdict":"pass","evidence_ids":["ev-header"],"notes":"Findings and limitations."}
```

Run `campaign --state DIRECTORY finalize REVIEW.json --port 8089` to save. It
rejects self-review, missing evidence, failed verdicts, and changed live state.
It confirms the program is no longer modified before marking the batch saved.
Save errors remain distinct from application failures. Review identities record
workflow responsibility; they are not authentication or proof of independence.
Use the `ghidra-verify` companion skill for semantic review.

## Bounded queues

Use `task add ID --queue naming --address ADDRESS` with optional `--depends-on ID`
and `--priority N`; `next --queue naming` deterministically selects eligible work.
Queues are `naming`, `types`, and `repair`. Naming tasks have at most ten targets.
`task start ID` checks budget, dependencies and the single active-task rule.
`task fail ID --reason TEXT` records an attempt; two failures defer the task.
`task defer` explicitly parks difficult work. `task retry ID --reason TEXT` records
new evidence or an explicit decision before reopening it. Completion requires
`task complete ID --batch PLAN_ID` and a saved batch covering its targets.
Deferred tasks remain part of the goal; an empty naming queue is not completion.

## Reusable identification evidence

`campaign --state DIRECTORY match --reference SNAPSHOT.json --provenance TEXT`
retains candidates from an explicitly selected reference snapshot. Language and
compiler must match. Each candidate includes its source identity, byte-match
status, and reference ABI, never an automatically applied signature. Shape hashes
ignore operands and are deliberately weak; duplicates stay ambiguous. Review
strings, callers, constants and register behavior before reusing a name or Watcom
contract. `scan` also inventories installed Function ID files and language
compatibility. No third-party downloads or automatic FID application occur.

## Layout changes

Set `queue` to `types` in a proposal. A `structure` change declares a new absolute
`path`, exact `length`, and `fields` containing `offset`, `length`, `type`, and
`name`. Existing structures are not replaced implicitly. A `data_type` change
identifies `address`, exact `length`, and the existing or earlier-declared `type`.
Every change requires evidence IDs. Field sizes must match resolved Ghidra types;
overlapping fields, code/function overlap, and partially covered existing data
are rejected. No stack-variable merging occurs.

Apply captures native output before and after layout changes and retains a compact
`native-delta.json` for independent review. Exact layout readback and unchanged
machine code/function ownership are required before the same finalization gate.
The headless self-test covers type creation and rollback after a code-overlap error.

For type/ABI reviews, include `reviewed_native_functions` with every changed
function address from the native delta. Missing coverage prevents finalization.

## Explicit ABI contracts

Types-queue proposals also accept `abi` changes: `address`, `convention`, explicit
`return`, `parameters`, `varargs`, and `noreturn`. Each value specifies `type` and
`storage`, either `{"register":"EAX"}` or `{"stack":4}`; parameters also name the
variable. A void return uses `/void` and null storage. Width mismatches and
intersecting parameter storage fail the transaction.

A `compiler_model` operation supplies `name` and one reviewed `<prototype>` XML
string, with evidence IDs. It creates only a new program-local compiler extension;
existing models are not silently replaced. XML declarations/entities are rejected.
No installation files change. Register storage alone does not prove preservation:
the model and affected native caller outputs require independent review.

## Repair trials

Repair proposals use `queue: "repair"` with an author and evidence-backed changes.
Supported operations are metadata only:

| Kind | Additional fields |
| --- | --- |
| `body` | `address`, `old_body`, `ranges` of inclusive address pairs |
| `remove_function` | `address`, `old_body`, `old_name` |
| `flow_override` | `address`, exact lowercase hex `bytes`, `old_override`, `override` as `NONE` or `BRANCH` |
| `jump_table` | instruction `address`, exact `bytes`, owning `function`, ordered `targets` |
| `analyzer_option` | `address` containing the option name, boolean `old_value`, boolean `value` |

Every operation also has `kind` and existing `evidence_ids`. The only supported
analyzer option is `Shared Return Calls.Assume Contiguous Functions Only` in the
program's Analyzers options. Plans allow at most 100 operations and 256 targets
per jump table. Ghidra validates instruction extents, ownership, old values, and
existing flow conflicts inside the transaction. Order removal before expanding
an owner, and set a synthetic return's BRANCH override before adding its table.
No executable bytes are patched.

Run `plan PROPOSAL.json`, then `trial PLAN.json --port 8089`. A trial captures
native output and a candidate snapshot, rolls back, and independently compares
the restored inventory with the original snapshot. Inspect the retained trial,
native delta, raw/overridden p-code, and native jump tables before approval.
`trial-reconcile --port 8089` resolves a timed-out trial only when its completion
receipt exists and a fresh snapshot proves rollback. Otherwise it blocks further
mutations. Reconciliation does not approve the trial; run a new trial to obtain a
reviewable result. The isolated `self-test` checks RET stack semantics, computed
jump targets, public-return preservation, and rollback after the script boundary.

The [analysis repair skill](../skills/ghidra-analysis-repair/SKILL.md) guides this
workflow. Stable application and independent finalization are separate steps.

## Durable repairs

A repair needs two independent reviews, one of the rolled-back trial before
application and one of the actual program state before saving. The same reviewer
may do both, but must differ from the plan's author.

The trial review JSON contains `plan`, `trial` from the trial report, `reviewer`,
`verdict: "pass"`, nonempty `notes`, all `evidence_ids`, and every changed address
in `reviewed_native_functions`. Run:

```bash
ghidra-manager campaign --state ./campaign apply PLAN.json --trial-review REVIEW.json --port 8089
ghidra-manager campaign --state ./campaign verify --port 8089
```

The runner processes pending analysis inside the trial and application. Before
committing, it compares the result with the reviewed trial and rolls back a
mismatch. It then rechecks ownership, byte hashes, listing edges, native jump
cases, and the complete snapshot after native capture while analysis is idle.
An analyzer-created function or another edit prevents finalization. Use `finalize`
with a separate review bound to the actual `after_snapshot` to save.

Errors during the Ghidra transaction roll it back. A transport timeout or a
post-commit mismatch leaves an unresolved, unsaved batch. `reconcile` reads its
program-local receipt and rechecks the state. It never silently overwrites later
UI edits or invokes Undo against an unknown transaction. Investigate conflicting
edits before attempting recovery; a trial result is not proof of saved state.

## Efficiency measurements

`campaign --state DIRECTORY metrics` reports budget observations, cache hits and
misses, packet bytes, native captures, saved changes, failed attempts, and deferred
tasks. Counts cover completed instrumented work; a transport failure can perform
work that is not counted. The accepted-change ratio uses recorded campaign token
deltas. Missing usage produces a null ratio, never a claimed saving.

`campaign --state DIRECTORY benchmark` runs an isolated offline fixture through
the actual inventory, cache, packet, and diff code. The fixture contains 1,000
functions. Five name changes require no native audit; asking for the same five
functions twice captures them once. It records operation counts and packet sizes,
not estimated model tokens or a percentage reduction in weekly usage. Benchmark
artifacts are retained under `artifacts/benchmarks/`.

Cache keys conservatively include program memory, defined data, compiler settings,
function dependencies, types, symbols, and strings. Packets accept at most 64
functions, capture in groups of eight, and default to a 32 KiB output ceiling.
Omitted functions are explicit. Native verification reuses an audit only when
both the complete snapshot and retained native artifact hashes are unchanged.
Ghidra's analysis timing statistics are excluded from semantic snapshots; actual
analyzer settings remain part of every fingerprint.

Session budget commands are separate from weekly account limits:

```bash
ghidra-manager campaign --state ./campaign budget show
ghidra-manager campaign --state ./campaign budget set --tokens 150000
ghidra-manager campaign --state ./campaign metrics
```

The second command explicitly raises the allowance while retaining usage. Do not
run it automatically when exhausted. A fresh session requires a new measured
baseline, and all declared agent scopes must be disjoint. The manager makes no
paid model calls and cannot interrupt an in-flight response. See the budget
examples above for recording actual cumulative counters.

Finalization also checks retained native evidence hashes and rereads the complete
snapshot after saving. A concurrent edit during save leaves `save-uncertain` and
publishes no verified receipt. Keep UI edits outside manager mutation/finalization
windows. A save response alone cannot prove the reviewed snapshot was saved.
New-layout plans reject changes to existing types or unrelated function ABIs;
existing structure replacement remains outside this tool's supported operations.

Whole-program repair trials and applications allow 30 minutes for the script and
31 minutes for the HTTP response. Ordinary collectors retain a 60-second script
hint and 120-second HTTP wait. These are observation limits: some MCP releases
ignore the script hint, and a timeout does not cancel or roll back the operation.
Keep the command running in a monitored terminal session and reconcile any timeout
before retrying. The manager never retries a timed-out write automatically.

GUI repair scripts queue a worker off Swing's event thread because Ghidra refuses
analysis there. The manager polls the unique `script-result-*.json` in the batch
directory for up to 30 minutes after submission. The result and worker error log
remain available after a client timeout. A scheduled response is not completion;
rollback and applied-state checks still run before a trial or batch is accepted.
The isolated self-test exercises this Swing-launch path as well as direct execution.
The delayed worker loads its script from the installed package. It does not reuse
MCP's launch copy, which some plugin releases delete when the request returns.
