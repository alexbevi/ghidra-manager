---
name: ghidra-verify
description: Independently review a bounded Ghidra campaign proposal against raw evidence and manager verification results before it can be saved. Use for an assigned semantic review, not routine CLI operation.
---

# Ghidra semantic verification

Use a fresh task-local context: exact program identity, retained plan, its evidence
packet, and deterministic verification report. Do not inherit the author's
intended conclusion or an entire campaign transcript.

Run `ghidra-manager campaign --state DIRECTORY verify --port PORT` for mechanical
readback. Check each proposed meaning against relevant instructions, callers,
strings, and data use. Mechanical equality does not establish a correct name.
Names must not imply unproved ownership, success, safety, or runtime reachability.

Return a review JSON object containing `plan`, `after_snapshot`, `reviewer`,
`verdict`, `evidence_ids`, and concise `notes` describing findings and limits.
Use `pass` only when every change is supported. Otherwise return `fail` or
`needs-evidence`; identify the specific changes. Be independent of the author.

Do not mutate or save Ghidra. The coordinator runs the explicit `finalize`
command after a passing review. Report your usage measurement and coverage to the
coordinator so it can account for this review without double-counting.
