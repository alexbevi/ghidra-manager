---
name: ghidra-manager
description: Operate and maintain the repository's cross-platform ghidra-manager CLI for Ghidra installation, curated plugin discovery, updates, rollback, project and MCP discovery, launches, bridge registration, and compare/apply workflows. Use when Codex needs to inspect or change managed Ghidra state or plugins, launch or verify projects, connect GhidraMCP, compare live projects, troubleshoot manager behavior, or modify the Ghidra Manager repository.
---

# Ghidra Manager

Use `ghidra-manager` as the only user-facing entrypoint. Treat the repository
`README.md`, package source, and command output as the current source of truth;
do not hardcode release versions or platform paths.

## Choose the workflow

- Inspect installed and upstream versions with `ghidra-manager status`.
- Inspect the curated plugin catalog with
  `ghidra-manager plugins discover [--json]`.
- Inspect the active plugin set with `ghidra-manager plugins list [--json]`.
- Check local RE readiness with `ghidra-manager doctor [PROJECT]` and add
  `--program PROGRAM` when one exact open program is required.
- Preview an update with `ghidra-manager sync --dry-run`; use `sync` only when
  the user intends to install or update Ghidra and rebuild selected plugins.
- List recorded project paths with `ghidra-manager projects`.
- Open and verify one recorded project with `ghidra-manager open PROJECT`.
- List responding GhidraMCP processes with `ghidra-manager instances`.
- Restore the retained compatible pair with `ghidra-manager rollback`.
- Register the stdio bridge with
  `codex mcp add ghidra -- ghidra-manager bridge`.

`projects` reports Ghidra's settings registry, not live processes. Use
`instances` as the runtime truth surface. Prefer `doctor --json` when Codex
needs structured readiness details without upstream release resolution.

## Manage plugins

1. Run `ghidra-manager sync` before installing a plugin on a fresh manager.
2. Run `ghidra-manager plugins discover` and use only the bundled plugin IDs.
3. Close manager-owned Ghidra processes before running
   `ghidra-manager plugins install PLUGIN`.
4. Install `mcp` before MCP-dependent launch, bridge, instance, doctor, or
   compare workflows.
5. Install `ghidra-lx-loader` before importing an LE/LX executable, then
   relaunch Ghidra so the loader is available.
6. Verify the selected tag and commit with `ghidra-manager plugins list`.
7. Remove an optional plugin with `ghidra-manager plugins remove PLUGIN`; use
   `rollback` if the prior complete set must be restored.

Plugin install also updates an already-selected plugin. It builds the newest
stable release tag against the active Ghidra and leaves the prior pair usable
if source resolution, compilation, validation, or activation fails.

## Launch and verify projects

1. Prefer `ghidra-manager open PROJECT --program PROGRAM` for a single recorded
   project. It resolves the name, retains a startup log, and waits for the
   expected MCP project and optional program.
2. Use `ghidra-manager launch /absolute/path/project.gpr` only when raw Ghidra
   argument forwarding is required. Do not substitute a recorded project name.
3. If `open` times out, confirm CodeBrowser is open, GhidraMCP is enabled, and
   its server is started from the Ghidra Tools menu, then inspect the reported
   log.

Use `launch-multi` with two or more distinct `.gpr` paths when separate live
projects are needed. Inspect its retained `launch-logs/` entry if startup
fails. Never use `ghidra-manager launch --help` to inspect CLI syntax because
`launch` forwards `--help` to Ghidra; use `ghidra-manager help`, the README, or
the package source instead.

## Compare live projects

1. Run `ghidra-manager instances` and use its project names, not `.gpr` paths.
2. Run `ghidra-manager compare SOURCE_PROJECT TARGET_PROJECT`, treating the
   first project as authoritative.
3. Review the generated private plan before any write.
4. Run `ghidra-manager compare --apply PLAN_PATH` only with explicit user
   authorization. Applying revalidates the target and leaves changes unsaved
   in Ghidra for review or undo.

## Protect managed state

- Never edit `.managed/` or platform user-data homes directly.
- Never modify a Ghidra installation outside manager state.
- Close manager-owned Ghidra processes before `sync` or `rollback`.
- Preserve stable-release selection, GitHub SHA-256 verification, exact
  extension compatibility, immutable plugin source commits, staged builds,
  atomic full-set activation, and a usable current/previous pair when changing
  manager code.

## Modify the repository

Read `AGENTS.md` and `README.md` before editing. Keep platform behavior behind
the platform adapter, and update code, tests, and user documentation in one
self-contained slice. Run the relevant checks from `AGENTS.md`, inspect
`status` and `git status --short`, and use a Conventional Commit without
amending existing history.
