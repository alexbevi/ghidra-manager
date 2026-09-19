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
