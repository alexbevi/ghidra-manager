@RTK.md

--- project-doc ---

# Ghidra Manager Repository Instructions

This repository manages local Ghidra tooling through one cross-platform Python
entrypoint: `ghidra-manager`. Keep the package and `README.md` aligned as the
source of truth for installation, updates, runtime commands, and rollback.

## Command Output

- Prefix verbose shell commands with `rtk` when RTK supports the command.
- Use `rg` or `rtk rg` for repository searches.
- Keep validation output focused on actionable failures.

## Repository Boundaries

- Treat `.managed/` and platform user-data homes as generated runtime state.
  Never edit or commit them.
- Do not modify Ghidra installations outside manager state.
- Keep `ghidra-manager` as the only supported user-facing entrypoint.
- Put OS behavior behind the narrow platform adapter rather than branching
  throughout command orchestration.
- Do not add a build system beyond the existing Python package and uv workflow.

## Release And Compatibility Invariants

- Track stable GitHub releases, not moving branches.
- Require a GitHub-provided SHA-256 digest for every downloaded release asset.
- Stage and verify downloads before changing active state.
- Read Ghidra compatibility from each extension's `extension.properties`.
- Install only the exact Ghidra version declared by the plugin.
- Build curated plugins from immutable stable-release commits with the target
  managed Ghidra distribution's Gradle wrapper.
- Install extensions under `Ghidra/Extensions/<plugin>` in the managed release.
- Refuse replacement while a manager-owned Ghidra process is running.
- Keep current and previous pairs usable. Shared-Ghidra rollback must reinstall
  the retained matching extension before changing active state.
- Update versioned JSON state through staged files and atomic replacement.
  Failure paths must leave the prior pair usable.

## Adding A Plugin

Add a future plugin as another reviewed registry entry:

1. Add one explicit entry to the bundled plugin registry; do not accept user
   supplied repositories or build commands.
2. Resolve only the newest stable GitHub release tag, dereference it to one
   immutable commit, and record the source archive digest.
3. Use the controlled Ghidra Gradle build adapter and require exactly one
   configured output artifact.
4. Validate extension identity, archive root, and the exact declared Ghidra
   version before staging.
5. Store the artifact and runtime files under the manager home with versioned
   JSON metadata.
6. Activate the complete plugin set with transaction backup and restoration.
7. Extend pair metadata and retention for every referenced artifact.
8. Add runtime commands only for a separate process or client entrypoint.
9. Update README prerequisites, commands, update/rollback behavior, and
   troubleshooting in the same commit.

## Validation

Run checks relevant to every vertical slice:

```bash
uv sync --locked --group dev
uv run pytest
uv run ruff check .
uv run mypy
uv build
uv run ghidra-manager sync --dry-run
git diff --check
```

- Run markdownlint when installed.
- Run a real `sync` and idempotent resync after changing downloads, archive
  validation, installation, activation, retention, or rollback.
- Run `bridge --help` after changing bridge or managed Python behavior.
- Run `instances` after changing MCP discovery or port parsing.
- Run `projects` after changing settings discovery or preference parsing.
- Test `launch-multi` with two distinct projects after changing launch,
  baseline exclusion, timeout, or port-range behavior.
- Verify failure cases do not change state or the installed extension.
- Inspect `status` and `git status --short` before finishing.

## Commits

- Use Conventional Commits.
- Commit the smallest self-contained vertical slice in each turn.
- Include code, documentation, and tests needed to make each slice usable.
- Validate before committing and stage only files belonging to the slice.
- Do not amend or rewrite existing commits unless explicitly requested.
