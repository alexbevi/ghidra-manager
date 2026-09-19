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
