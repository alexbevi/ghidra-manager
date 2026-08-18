# Analysis Fidelity

## Contents

- Fidelity objective
- Container and loader audit
- Compiler and ABI audit
- Derived analysis programs
- Readiness decision

## Fidelity objective

Prove that the selected Ghidra program represents the executable content and
addressing model that retail execution can reach. Treat a readable entry point
or successful auto-analysis as necessary but insufficient.

Perform this gate before broad naming, type recovery, or completion counting.

## Container and loader audit

Record and verify:

- file size, format, headers, checksums, and entry metadata;
- mapped file ranges versus unmapped or appended bytes;
- relocations, fixups, segment tables, overlays, resources, and embedded images;
- compression, encryption, packing, or runtime copying into executable memory;
- loader-created blocks, permissions, address spaces, and segment aliases;
- executable targets referenced by thunks, tables, interrupts, or custom loaders;
- analyzer errors, overlapping instructions, fallthrough damage, and code gaps.

Trace custom load and dispatch mechanisms far enough to decide whether Ghidra's
initial memory map can expose their targets. Do not infer completeness from a
function count alone.

## Compiler and ABI audit

Identify compiler and runtime families when evidence permits. Separate runtime
and library code from game-specific logic without assuming it is irrelevant.

For every applicable ABI, establish:

- near versus far code and data pointers;
- segmented aliases and a canonical address representation;
- caller versus callee stack cleanup;
- register-pair scalar and pointer returns;
- hidden structure-result or environment parameters;
- variadic functions and stack layout;
- interrupt, callback, thunk, and overlay gateway conventions;
- `noreturn` behavior and unreachable cleanup tails.

When decompiled C conflicts with callers or instructions, treat disassembly,
p-code/data flow, stack deltas, and repeated call-site behavior as authoritative.
Record known decompiler limitations instead of forcing a misleading prototype.

## Derived analysis programs

Preserve the original executable and Ghidra import. Create a derivative only
when required to expose retail-reachable content or repair a loader limitation.

Store derived files under `<state-dir>/artifacts/` and record one
`derived_programs` entry in `project.json` with:

- a stable ID and purpose;
- source and result SHA-256 digests;
- relative artifact path and Ghidra program path;
- size, format, language, and image base;
- transformation tool, immutable version or source commit, and exact arguments;
- address-mapping rules between the original and derivative;
- validation counts and material differences between independent imports.

Do not overwrite a derived artifact in place. Produce a new identity when the
tool, arguments, source bytes, or address mapping changes.

## Readiness decision

Record `progress.json.analysis_fidelity.status` as:

- `pending`: the audit is incomplete;
- `ready`: the selected semantic source is adequate and limitations are bounded;
- `blocked`: reachable content or address semantics remain unavailable.

A `ready` decision must name the semantic Ghidra program, record the verification
time, and summarize container coverage, relocation/overlay handling, compiler
ABI, address aliasing, and remaining limitations. Reopen this gate after a
reimport, rebase, loader change, transformation change, or analyzer change.
