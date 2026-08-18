# Campaign State

## Files

Keep the state directory small and machine-readable:

```text
<state-dir>/
├── artifacts/
├── traces/
├── project.json
├── progress.json
├── tasks.json
├── evidence.jsonl
├── renames.jsonl
├── behaviors.jsonl
├── coverage.jsonl
├── runtime.jsonl
└── ARCHITECTURE.md
```

`project.json` contains stable campaign and binary identity.
Keep reproducible transformed binaries and their sidecar manifests in
`artifacts/`; describe every derivative and its provenance in
`project.json.derived_programs`.

`progress.json` contains phase, status, aggregate baseline/current counts,
blockers, last verification, and active mutation lease. Do not store every
symbol here.

`tasks.json` contains bounded work, dependencies, authority, leases, and
handoffs.

`evidence.jsonl` is append-only. Store one evidence claim per line with a stable
ID, category, addresses, claim, source task, and timestamp.

`renames.jsonl` is append-only. Store proposals and applied/verified state:

```json
{
  "id": "rn-runtime-0042",
  "batch_id": "batch-runtime-006",
  "kind": "function",
  "address": "00024510",
  "old_name": "FUN_00024510",
  "new_name": "ParseRuntimeCommand",
  "confidence": "high",
  "evidence_ids": ["ev-runtime-011", "ev-runtime-019"],
  "state": "verified",
  "agent": "renamer-runtime",
  "verified_by": "verifier-runtime",
  "timestamp": "2026-01-01T00:00:00Z"
}
```

`behaviors.jsonl` is append-only. Store one bounded retail behavior contract per
line using `references/behavior-slices.md`. Symbol-recovery campaigns may leave
it empty; reimplementation campaigns use it as the primary semantic ledger.

`coverage.jsonl` is append-only. Keep independently reviewed shipped-data
reachability, reusable-interpreter, implementation, and semantic-parity
classifications using `references/reachability-and-parity.md`.

`runtime.jsonl` is append-only. Store reproducible retail observations and
paired target comparisons using `references/runtime-validation.md`. Put raw
logs, traces, screenshots, and state captures in `traces/` and reference them
with relative paths.

`ARCHITECTURE.md` is the human-readable confirmed model. Keep program identity,
entry path, subsystem boundaries, dispatch tables, data model, cross-version
matches, open questions, and verification summary. Label provisional claims.

## State rules

- Initialize once with `scripts/init_project.py`.
- Let the coordinator own JSON state writes.
- Append evidence and rename records; do not rewrite history to hide failed
  hypotheses.
- Append behavior revisions with new stable IDs or explicit supersession links;
  do not rewrite verified contracts silently.
- Update JSON files through staged temporary files and atomic replacement.
- Use stable IDs in handoffs and cross-links.
- Keep addresses qualified with address spaces when the program has more than
  one.
- Never overwrite a derived program in place; its digest and transformation
  provenance are part of campaign identity.
- Record UTC timestamps.
- Validate with `scripts/validate_project.py <state-dir>`.
- Keep Ghidra as the source of truth for program semantics. State files
  coordinate and explain; they do not override readback.

## Task lifecycle

Use:

```text
pending -> leased -> complete
                  -> blocked
                  -> needs-verification
```

Use `cancelled` only when the coordinator proves a task is obsolete or a
duplicate. A stale lease returns to `pending` after the coordinator confirms
the worker is inactive and reconciles any partial Ghidra changes.

Every mutation task must name its verification task. Every completed task must
provide evidence IDs, a handoff, or an explicit no-finding result.

## Identity mismatch

On resume, compare at least project, program path/name, format, language,
address spaces, image base, and an available binary/program digest. If a stable
identity field differs:

1. stop mutation;
2. record the mismatch as a blocker;
3. determine whether the binary was intentionally reimported or rebased;
4. create a migration or new campaign instead of blindly reusing addresses.
