# Ghidra Manager Repository Instructions

This repository manages local Ghidra tooling through one entrypoint:
`ghidra-manager.sh`. Keep the script and `README.md` aligned as the source of
truth for installation, updates, runtime commands, and rollback behavior.

## Command Output

- Prefix verbose shell commands with `rtk` when RTK supports the command.
- Use `rg` or `rtk rg` for repository searches.
- Keep validation output focused on actionable failures.

## Repository Boundaries

- Treat `.managed/` as generated runtime state. Never edit or commit it.
- Do not modify Ghidra installations outside this repository.
- Keep the manager macOS-focused unless a task explicitly expands platform
  support and includes the corresponding validation.
- Keep `ghidra-manager.sh` as the only supported user-facing entrypoint. Put
  substantial, self-contained implementation in a narrowly named helper under
  `tools/` when shell would obscure it, and invoke that helper from the manager.
  Do not add a second installer or updater entrypoint.
- Do not add a build system when shell functions and the existing release
  assets are sufficient.

## Release And Compatibility Invariants

- Track stable GitHub releases, not moving branches.
- Require a GitHub-provided SHA-256 digest for every downloaded release asset.
- Stage and verify downloads before changing the active pair.
- Read Ghidra compatibility from each extension's `extension.properties`.
- Install only the exact Ghidra version declared by the plugin. Report a newer
  unmatched Ghidra release instead of forcing an unverified combination.
- Install extensions into the managed distribution's
  `Ghidra/Extensions/<plugin>` directory.
- Refuse extension replacement while a manager-owned Ghidra process is running.
- Keep current and previous pairs usable. When they share one Ghidra release,
  rollback must reinstall the matching retained extension before changing the
  active bridge.
- Update active state through staged files and atomic symlink replacement.
  Failure paths must leave the prior pair usable.

## Adding A Plugin

Add future plugins as another managed component in the existing script:

1. Add repository and asset-selection constants beside the existing upstream
   constants.
2. Implement a narrowly named release resolver that selects one stable asset
   and records its URL, tag, version, and SHA-256 digest.
3. Validate the extension name, plugin version, archive layout, and declared
   Ghidra version before staging it.
4. Store versioned payloads under `.managed/<plugin>/<version>/` with a small
   metadata file. Add the plugin version to pair metadata when it participates
   in compatibility or rollback.
5. Install with a transaction backup and restore it from `cleanup` on failure.
6. Extend retention so current and previous pairs keep every component they
   reference and prune only unreferenced versions.
7. Add stable runtime commands only when the plugin exposes a separate process
   or client entrypoint.
8. Update `README.md` in the same commit with prerequisites, commands, first-run
   steps, update behavior, rollback behavior, and troubleshooting.

Do not generalize the script into a plugin framework before a second plugin
demonstrates the shared behavior. Prefer explicit resolver, staging, and install
functions that preserve the current transaction model.

## Validation

Run the checks relevant to each vertical slice:

```bash
bash -n ghidra-manager.sh
./ghidra-manager.sh sync --dry-run
git diff --check
```

- Run ShellCheck and markdownlint when installed.
- Run the managed-Python syntax check after changing the compare engine:

```bash
uv run --python 3.13 --managed-python --no-project \
  python -m py_compile tools/ghidra_compare.py
```

- Run a real `sync` after changing downloads, archive validation, installation,
  activation, retention, or rollback.
- Re-run `sync` to verify idempotence.
- Run `bridge --help` after changing bridge selection or Python runtime setup.
- Run `instances` after changing MCP discovery, port parsing, or output.
- Run `projects` after changing Ghidra settings discovery, preference parsing,
  project storage validation, or active-instance matching.
- Test `launch-multi` with two distinct disposable or existing projects after
  changing process launch, baseline exclusion, timeout, or port-range behavior.
- Verify failure cases do not change `current`, `previous`, or the installed
  extension.
- Inspect `status` and `git status --short` before finishing.

## Commits

- Use Conventional Commits.
- Commit the smallest self-contained vertical slice in each turn.
- Include the code, documentation, and validation changes needed to make that
  slice usable; do not create separate cleanup-only commits for required docs or
  tests.
- Validate before committing and stage only files belonging to the slice.
- Keep commit subjects specific and reviewer-readable, for example:
  `feat: add managed plugin update workflow`.
- Do not amend or rewrite existing commits unless explicitly requested.
