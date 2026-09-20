---
name: ghidra-analysis-repair
description: Diagnose and trial Ghidra function ownership, shared tails, synthetic returns, and computed-jump repairs when native decompilation disagrees with instruction evidence.
---

# Ghidra analysis repair

Use the manager's `campaign` commands and [repair tool guide](../../tools/README.md#repair-trials).
Keep the exact program path on every request. Inspect `instances` before live work.
Read the campaign's budget and unfinished batch first. Repair is a separate queue
from naming and ABI work. Do not resume a paused retail campaign just to test tools.

Start with saved raw bytes, raw and overridden p-code, ownership, incoming edges,
and native decompilation. A nicer-looking C listing is not proof of a repair.
Every proposed body range must contain whole instructions, retain its entrypoint,
and exclude other live owners. Prove all dispatcher targets and distinguish a
synthetic return from a public return. Preserve the stack load and adjustment
when overriding a synthetic RET as BRANCH. Keep public returns unchanged.

Use `plan` then `trial` for declarative repair proposals. The runner performs no
byte patches. Inspect both listing references and native jump-table output.
For reachable decoded code missing from the function inventory, use a separate
`create_function` batch with explicit unowned ranges and instruction hashes. Prove
entry roots and complete extents, including shared-tail consumers, before proposing
ownership. Existing-function capture coverage excludes these gaps. Keep default
names during discovery; review inferred metadata before later naming or ABI work.
Compare native output for every function whose output changed, including callers
outside the immediate region. Reconcile timeouts; never blindly retry a mutation.
A trial is usable only after the manager proves rollback with a fresh inventory.

If analysis recreates a false shared-tail function, inspect the responsible
analyzer and its program-local settings. The supported shared-return boolean
requires explicit old/new values and evidence. Do not disable unrelated analyzers
or edit a Ghidra installation to make a repair stick.

Give an independent reviewer the immutable plan, trial hash, raw evidence, changed
native artifacts, and failed hypotheses. Use [ghidra-verify](../ghidra-verify/SKILL.md)
for semantic review. Trial success does not authorize a save. Durable application
must pass the manager's stability and independent finalization checks.

Report measured session tokens, cap, remaining budget, measurement source and
coverage at each batch boundary. Unknown usage stays unknown. See the tool guide
for recording counters and explicit budget adjustments. After two failed attempts
at the same repair, defer it with the artifacts and the unresolved question.
