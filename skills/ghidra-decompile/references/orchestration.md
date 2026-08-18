# Multi-Agent Orchestration

## Contents

- Coordinator contract
- Worker roles
- Fan-out strategy
- Mutation leases
- Task prompt contract
- Handoff contract
- Resuming a goal

## Coordinator contract

Keep one main coordinator responsible for:

- preserving the exact goal objective;
- verifying project and program identity;
- owning `project.json`, `progress.json`, and `tasks.json`;
- partitioning the graph into bounded tasks;
- resolving naming and type conflicts;
- granting the only active mutation lease;
- saving the program after independent verification;
- running audits and deciding whether the goal is complete.

The coordinator should inspect evidence directly before accepting a mutation
plan. Subagents can gather and analyze evidence, but they do not redefine the
goal or completion criteria.

## Worker roles

### Indexer or graph explorer

Operate read-only. Inventory roots, functions, strings, tables, xrefs, and graph
frontiers. Return bounded clusters and unresolved edges.

### Subsystem explorer

Operate read-only. Decompile a cluster, infer its responsibility, and identify
candidate functions, globals, types, and follow-up roots.

### Cross-referencer

Operate read-only. Compare versions, sibling binaries, imports, manuals, debug
symbols, source ports, normalized hashes, instructions, and string anchors.
Distinguish direct equivalence from analogy.

### Renamer and type recoverer

Build a proposal first. Apply it only with an explicit exclusive mutation lease.
Limit writes to the leased addresses and data-type categories. Read back all
changes and return exact old/new values.

### Consolidator

Review overlapping subsystem results. Resolve synonyms, namespace boundaries,
duplicate types, calling conventions, field layouts, and conflicting semantic
claims. Normally operate read-only and submit one reconciliation plan.

### Verifier

Remain independent from the batch author. Re-decompile, inspect disassembly and
xrefs, validate types and prototypes, and compare the batch with its evidence.
Return pass, fail, or needs-more-evidence for every change.

### Comment and decoration agent

Document only verified behavior. Add function comments, field comments,
bookmarks, tags, and architecture notes after the relevant names and types pass
verification. Avoid speculative narrative.

## Fan-out strategy

Use parallelism for independent reads:

1. Wave 1: entry/direct graph, string/xref clusters, indirect tables/data.
2. Wave 2: separate high-evidence subsystems.
3. Wave 3: cross-reference and consolidation of ambiguous clusters.
4. Mutation wave: one writer only.
5. Verification wave: a different agent.
6. Decoration wave: verified clusters only.

Keep one concurrency slot for the coordinator. Respect the actual slot limit;
do not assume a fixed number of workers.

Do not assign multiple agents the whole binary. Partition by root set, address
range, table, string cluster, or subsystem. Prefer tasks that can finish and
handoff in one turn.

## Mutation leases

Only one mutation lease may be active per Ghidra program.

The coordinator must record:

- `lease_owner`;
- bounded addresses and data-type categories;
- allowed mutation kinds;
- `started_at` and `heartbeat_at`;
- prerequisite evidence IDs;
- verification task ID.

A worker without the lease must not rename, retype, comment, run mutating
analysis, or save. Read-only Ghidra queries may run concurrently when the bridge
supports them.

Release the lease after readback, even when verification fails. Apply fixes in a
new lease rather than silently extending scope.

## Task prompt contract

Every subagent prompt must include:

```text
Goal invariant: <exact objective>
Project/program identity: <project, path, format, language, image base>
Role: <role>
Scope: <addresses, roots, table, strings, or subsystem>
Authority: read-only | propose-only | exclusive bounded mutation
Required evidence: <categories and minimum confidence>
Known context: <small set of verified names, types, and evidence IDs>
Deliverable: <handoff path or structured response>
Forbidden: <out-of-scope writes, save, analyzer reruns, unsupported claims>
```

Pass only verified task-local context. Do not leak the intended answer to
exploration or verification agents.

## Handoff contract

Return a structured handoff:

```json
{
  "task_id": "subsystem-audio-003",
  "program_identity": "recorded identity or digest",
  "scope": ["00012340-000129ff"],
  "status": "complete",
  "summary": "One sentence",
  "evidence": [
    {
      "id": "ev-audio-017",
      "category": "string-xref",
      "addresses": ["00012510", "0009a240"],
      "claim": "Function opens and parses the HMI driver configuration"
    }
  ],
  "proposals": [
    {
      "kind": "function",
      "address": "00012510",
      "old_name": "FUN_00012510",
      "new_name": "LoadHmiDriverConfiguration",
      "confidence": "high",
      "evidence_ids": ["ev-audio-017", "ev-audio-021"]
    }
  ],
  "new_frontier": ["00012a40"],
  "conflicts": [],
  "unresolved": [],
  "mutations_applied": []
}
```

For mutation tasks, populate `mutations_applied` with exact old/new values and
readback results. Never represent a proposal as an applied change.

## Resuming a goal

At every continuation:

1. Call `get_goal`.
2. Validate campaign files.
3. Reconnect and verify program identity.
4. Confirm analysis and save state.
5. Recycle stale leases to pending only after proving no worker is active.
6. Reconcile queued handoffs with current Ghidra state.
7. Resume the highest-confidence bounded frontier.

Do not restart reconnaissance when its saved evidence still matches the current
binary. Do not trust saved addresses when identity checks fail.
