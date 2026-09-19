---
name: ghidra-verify
description: Independently review a bounded Ghidra campaign proposal against raw evidence and manager verification results before it can be saved. Use for an assigned semantic review, not routine CLI operation.
---

# Ghidra semantic verification

Use a fresh task-local context: exact program identity, retained plan, its evidence
packet, and deterministic verification report. Do not inherit the author's
intended conclusion or an entire campaign transcript.

For an applied batch, run `ghidra-manager campaign --state DIRECTORY verify
--port PORT` for mechanical readback. For a rolled-back repair trial, read its
retained `trial.json`, candidate snapshot, and native artifacts instead; there
is no applied batch to verify. Check each proposed meaning against relevant instructions, callers,
strings, and data use. Mechanical equality does not establish a correct name.
Names must not imply unproved ownership, success, safety, or runtime reachability.

Return a review JSON object containing `plan`, `after_snapshot`, `reviewer`,
`verdict`, `evidence_ids`, and concise `notes` describing findings and limits.
For layout, ABI, or repair changes, also return `reviewed_native_functions`
covering every address in the native delta. Inspect changed C and warnings
against raw instructions, caller contracts, storage widths, and layout extents.
A compiler label alone does not prove register arguments or preserved registers.
For repairs, verify target closure, ownership, raw/overridden p-code, and native
jump tables. Check that public returns and stack adjustments survive.

A trial review uses `trial` in place of `after_snapshot`; bind it to the retained
trial hash and verify that rollback was proven. The coordinator must obtain a
separate applied-state review before saving.

Use `pass` only when every change is supported. Otherwise return `fail` or
`needs-evidence`; identify the specific changes. Be independent of the author.

Do not mutate or save Ghidra. The coordinator runs the explicit `finalize`
command after a passing review. Report your usage measurement and coverage to the
coordinator so it can account for this review without double-counting.
