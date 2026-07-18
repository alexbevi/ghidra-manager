# Ghidra Manager

Ghidra Manager is a cross-platform CLI for installing Ghidra and compiling a
curated set of extensions for that exact release. It tracks stable GitHub
releases, requires GitHub-published SHA-256 digests for release assets, builds
plugins from immutable release commits, and retains the active installation
plus one complete rollback pair.

The `ghidra-manager` Python command is the only supported user-facing
entrypoint on Windows, Linux, and macOS.

For Codex workflows, this repository also includes the
[`ghidra-manager` skill](skills/ghidra-manager/SKILL.md). Invoke
`$ghidra-manager` to inspect managed state, launch and verify projects, connect
the bridge, discover managed plugins, compare live projects, or work on the
manager itself.

## Install

Install [`uv`](https://docs.astral.sh/uv/) and a 64-bit JDK 21. The CLI uses uv
to provision Python 3.13, so a system Python installation is not required.

From a checkout:

```bash
uv tool install .
ghidra-manager help
```

For development:

```bash
uv sync --locked --group dev
uv run ghidra-manager help
```

JDK discovery checks `JAVA_HOME` and `PATH` on every platform. macOS also uses
`/usr/libexec/java_home` and Homebrew when available.

## Install, Update, And Roll Back

Resolve and install the newest stable Ghidra release. A fresh installation has
no plugins; later syncs rebuild the active pair's selected plugins for the new
Ghidra release:

```bash
ghidra-manager sync
```

Preview release selection without changing managed state:

```bash
ghidra-manager sync --dry-run
```

Show active, retained, and newest upstream versions:

```bash
ghidra-manager status
```

Check local reverse-engineering readiness without resolving upstream releases:

```bash
ghidra-manager doctor
ghidra-manager doctor ripper --program RIPPER.LE
ghidra-manager doctor ripper --program RIPPER.LE --json
```

`doctor` verifies the active pair, managed installation and MCP plugin, JDK 21,
recorded project, responding MCP identity and versions, expected open program,
endpoint catalog, and analysis status. Errors produce a nonzero exit code;
warnings remain successful so partial environments can be inspected.

Return to the retained previous pair:

```bash
ghidra-manager rollback
```

Close managed Ghidra processes before syncing or rolling back. Rollback
reinstalls the retained pair's complete plugin set before changing active
state, including when both pairs share one Ghidra release.

`GH_TOKEN` or `GITHUB_TOKEN` may authenticate GitHub API requests.

## Manage Plugins

List the reviewed plugins available from the manager's bundled registry:

```bash
ghidra-manager plugins discover
ghidra-manager plugins discover --json
ghidra-manager plugins list
ghidra-manager plugins list --json
```

The initial catalog contains `mcp` and `ghidra-lx-loader`. Discovery is
read-only and works before Ghidra is installed. Plugin versions are resolved
from stable GitHub releases when a plugin is installed or updated rather than
being pinned in the registry.

Install or update one plugin for the active Ghidra release:

```bash
ghidra-manager sync
ghidra-manager plugins install mcp
ghidra-manager plugins install ghidra-lx-loader
ghidra-manager plugins remove ghidra-lx-loader
```

Plugin installation requires an active Ghidra installation and refuses to
replace extensions while a manager-owned Ghidra process is running. The
manager resolves the latest stable plugin release tag to its immutable commit,
uses the target Ghidra distribution's Gradle wrapper, validates the generated
extension ZIP, then activates the complete selected set transactionally.
Removal is idempotent and creates a rollback pair that retains the removed
artifact until it is no longer referenced.

Install `mcp` before using `bridge`, `instances`, `open`, `launch-multi`, or
`compare`. Install `ghidra-lx-loader` before importing LE/LX binaries such as
DOS/4GW or OS/2 Linear Executables.

## Managed State

Fresh installations use the native user-data directory:

- Windows: `%LOCALAPPDATA%\ghidra-manager`
- Linux: `${XDG_DATA_HOME:-~/.local/share}/ghidra-manager`
- macOS: `~/Library/Application Support/ghidra-manager`

Set `GHIDRA_MANAGER_HOME` to override this location.

```text
<manager-home>/
├── ghidra/<version>/
├── plugins/<plugin>/<ghidra-version>/<source-commit>/
├── pairs/<ghidra-and-plugin-manifest>/metadata.json
├── state.json
├── gradle-cache/
├── launch-logs/
├── compare-plans/
├── python/
└── uv-cache/
```

`state.json` records the current and previous pair IDs without requiring
symlinks. Each pair records its exact Ghidra release and sorted plugin manifest.
Downloads, builds, and extension installation are validated before an atomic
state replacement. Failed extension replacement restores every affected
plugin directory.

When first run from a checkout containing the former `.managed/` layout, the
CLI adopts that directory in place and converts valid `current` and `previous`
pair metadata into versioned JSON. Legacy symlinks are not required afterward.
Existing GhidraMCP pairs migrate with `mcp` selected and retain their legacy
artifact paths until neither current nor previous references them.

## Run Ghidra And GhidraMCP

Install the MCP plugin first if it is not already selected:

```bash
ghidra-manager plugins install mcp
```

List recorded projects to resolve the exact project path:

```bash
ghidra-manager projects
```

Open a recorded project by name or `.gpr` path and wait for its GhidraMCP
endpoint:

```bash
ghidra-manager open ripper
ghidra-manager open /path/to/ripper.gpr --program RIPPER.LE
```

`open` retains a startup log, rejects an already-active project, and reports
success only after a new endpoint identifies the expected project and optional
program. Use `--timeout` or `--base-port` to override discovery defaults.

Launch the active distribution, optionally opening a project by its `.gpr`
path:

```bash
ghidra-manager launch
ghidra-manager launch /path/to/project.gpr
```

`launch` passes all remaining arguments directly to Ghidra. It does not resolve
a recorded name such as `ripper` to its project path, and `launch --help` is
therefore forwarded to Ghidra rather than handled as CLI help. Use
`ghidra-manager help` for the manager command summary.

On the first launch for a new Ghidra settings version:

1. Open or create a project and launch CodeBrowser.
2. Select **File > Configure > Configure All Plugins** and enable
   **GhidraMCP**.
3. Select **Tools > GhidraMCP > Start MCP Server**.

The plugin listens on `127.0.0.1:8089` by default and may fall back through
port 8104. Verify the launch by listing responding instances; the launcher
banner or exit code alone does not prove that Ghidra stayed running:

```bash
ghidra-manager instances
```

`projects` reads Ghidra's settings registry, while `instances` reports live
GhidraMCP endpoints. A running Project Window does not appear in `instances`
until CodeBrowser is open and the plugin server is active.

Launch one process per project and wait for new MCP endpoints:

```bash
ghidra-manager launch-multi \
  /path/to/first-project.gpr \
  /path/to/second-project.gpr
```

Without paths, `launch-multi` opens two instances by default. Use `--count`,
`--timeout`, or `--base-port` to override launch behavior. Projects and project
names must be distinct, and already-active projects are rejected. Detached
startup logs are retained under `launch-logs/`.

Register the managed stdio bridge with Codex:

```bash
codex mcp add ghidra -- ghidra-manager bridge
```

The bridge uses uv-managed Python 3.13 and the upstream retained script:

```bash
ghidra-manager bridge --help
```

`GHIDRA_MCP_BASE_PORT` changes the discovery base port.
`GHIDRA_MCP_LAUNCH_TIMEOUT` changes the multi-launch timeout.

## Compare Binaries Across Instances

Treat the first responding project as the documentation source and the second
as the target:

```bash
ghidra-manager compare source-project target-project
```

Comparison is read-only. It summarizes inventories first, then matches
functions only when normalized opcode hash and instruction count uniquely
identify one function in each program. It reports missing function metadata,
structures, and enumerations without overwriting conflicting target state.

Each comparison writes a private versioned plan under `compare-plans/` and
retains the newest ten. Apply a reviewed plan explicitly:

```bash
ghidra-manager compare --apply \
  /path/to/compare-plans/<timestamp>-source-to-target.json
```

Apply rechecks target project, PID, function hashes, documentation, and type
state. It stops on the first rejected operation and deliberately leaves changes
unsaved in Ghidra for review or undo.

## Validation

```bash
uv sync --locked --group dev
uv run pytest
uv run ruff check .
uv run mypy
uv build
uv run ghidra-manager sync --dry-run
git diff --check
```

Pull-request CI runs on Ubuntu x64, Windows x64, macOS ARM64, and macOS x64.
The manually triggered real-integration workflow performs a real sync,
idempotent resync, status check, and bridge smoke test on the same matrix.

## Troubleshooting

- **JDK 21 not found:** set `JAVA_HOME` or put Java 21 on `PATH`.
- **GitHub rate limit:** set `GH_TOKEN` or `GITHUB_TOKEN`.
- **MCP connection refused:** open CodeBrowser, enable GhidraMCP, and start its
  server from **Tools > GhidraMCP**.
- **MCP plugin is not installed:** close managed Ghidra processes, run
  `ghidra-manager plugins install mcp`, then relaunch Ghidra.
- **Plugin build failed:** inspect the reported Gradle output and keep using the
  unchanged active pair; the failed build is never activated.
- **Invalid project:** pass the `.gpr` path reported by the `projects` command,
  not only its display name.
- **Open timeout:** finish opening CodeBrowser, enable GhidraMCP, and inspect the
  retained log path reported by `open`.
- **Doctor not ready:** address each `ERROR` check, then rerun the same project
  and program selection before starting a write workflow.
- **Multi-launch timeout:** finish opening CodeBrowser in each project, then run
  `ghidra-manager instances`.
- **Update refused:** close all processes running from the managed Ghidra
  component directory.
- **Compare target changed:** generate a fresh plan instead of applying stale
  operations.
- **No project registry:** launch Ghidra once so it creates platform settings
  and records a project.
