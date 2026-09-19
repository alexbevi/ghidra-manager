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
