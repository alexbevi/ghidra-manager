# Resource Entry Graphs

## Contents

- Why resources are roots
- Inventory
- Trace producers and consumers
- Record format
- Reachability rules

## Why resources are roots

Game behavior is frequently selected by archive contents, scripts, action
tables, packet streams, save records, or resource identifiers rather than a
complete static call graph. Treat installed retail data as an independent root
set when the objective concerns shipped behavior or interpreter completeness.

## Inventory

Enumerate applicable:

- archives, volumes, directories, and members;
- scripts, bytecode versions, opcodes, operands, callbacks, and action IDs;
- media containers, packet commands, codecs, palettes, and timing metadata;
- scene, mission, dialog, UI, inventory, and puzzle descriptors;
- save formats, persistent-state records, and version selectors;
- configuration, localization, font, bitmap, model, and audio resources.

Preserve the data-set identity and file/member digest when available. Use stable
canonical resource IDs that can also appear in behavior records and the target
implementation.

## Trace producers and consumers

For each resource or dispatch value, trace:

1. discovery or lookup;
2. open/read/decompression ownership;
3. parser or decoder entry;
4. dispatcher and indirect target selection;
5. runtime consumers and state mutations;
6. cleanup, caching, replacement, and failure behavior.

Distinguish an identifier from a pointer, handle, file offset, or address. Do
not infer reachability solely from a declared opcode or a named registry entry;
inspect installed data and the actual execution switch.

## Record format

Append one object to `resources.jsonl`:

```json
{
  "id": "resource-script-prologue",
  "data_set": "retail-v1.0",
  "canonical_id": "PROLOGUE.RUN",
  "kind": "compiled-scene-script",
  "container": "SCRIPT.PL",
  "member": "PROLOGUE.RUN",
  "digest": "sha256:...",
  "dispatch_values": ["callback-opcode:0x24"],
  "parser_roots": ["0001:2345"],
  "dispatcher_roots": ["0002:3456"],
  "consumer_roots": ["0003:4567"],
  "reachability": {
    "status": "reachable",
    "route": "Loaded by the shipped prologue scene"
  },
  "evidence_ids": ["ev-resource-001"],
  "status": "traced",
  "source_task": "index-resource-graph",
  "timestamp": "2026-01-01T00:00:00Z"
}
```

Use `discovered`, `catalogued`, `traced`, `unresolved`, or `superseded` for
record status. A traced record must identify at least one parser, dispatcher, or
consumer root.

## Reachability rules

- `reachable`: selected by the stated shipped data and route;
- `not_reachable`: present in code or format vocabulary but unused by the stated
  shipped data;
- `unknown`: inventory, indirect dispatch, or runtime evidence is incomplete.

Report declared-but-unused interpreter behavior separately from shipped-data
gaps. Recompute reachability when the retail data set changes.
