<p align="center">
  <img src="https://raw.githubusercontent.com/alexbevi/ghidra-manager/main/docs/logo.png" alt="Ghidra Manager logo" width="240">
</p>

# Ghidra Manager

Ghidra Manager is a cross-platform CLI for installing Ghidra and compiling a
curated set of extensions for that exact release. It tracks stable GitHub
releases, requires GitHub-published SHA-256 digests for release assets, builds
plugins from immutable release commits, and retains the active installation
plus one complete rollback pair.

The `ghidra-manager` Python command is the only supported user-facing
entrypoint on Windows, Linux, and macOS.

For Codex workflows, this repository also includes the
[`ghidra-manager` skill](https://github.com/alexbevi/ghidra-manager/blob/main/skills/ghidra-manager/SKILL.md).
Invoke
`$ghidra-manager` to inspect managed state, choose reviewed plugins, launch and
verify projects, connect the bridge, target exact programs inside a project,
compare binaries, or work on the manager itself. The skill follows the same
safety rules as the CLI: use `instances` as runtime truth, identify programs
explicitly when more than one is open, and review comparison results before a
write. The skill is maintained in the source repository and is not installed
into Codex by the PyPI package.

## Command Summary

The examples below abbreviate paths, process IDs, and versions with angle
brackets. Running `ghidra-manager` without a subcommand is equivalent to
`ghidra-manager sync`.

| Command | Options | Sample output |
| --- | --- | --- |
| `ghidra-manager help` | Global: `-h`, `--help` | `usage: ghidra-manager ... {help,sync,status,...}` |
| `ghidra-manager --version` | None | `ghidra-manager 0.1.0` |
| `ghidra-manager sync` | `--dry-run` resolves without changing state | `Active pair: Ghidra <version>; plugins ghidra-lx-loader, mcp.` |
| `ghidra-manager status` | None | `Active Ghidra: <version>` |
| `ghidra-manager doctor [PROJECT]` | `--program PROGRAM`, `--json`, `--base-port PORT` | `Doctor result: ready` |
| `ghidra-manager rollback` | None | `Rolled back to Ghidra <version>; plugins mcp.` |
| `ghidra-manager projects` | None | `Projects known to Ghidra <version>:` |
| `ghidra-manager plugins discover` | `--json` | `mcp` is reported as `selected` or `available` |
| `ghidra-manager plugins list` | `--json` | `Plugins for Ghidra <version>:` |
| `ghidra-manager plugins install PLUGIN` | `mcp` or `ghidra-lx-loader` | `Installed plugin mcp <version> for Ghidra <version>.` |
| `ghidra-manager plugins remove PLUGIN` | `mcp` or `ghidra-lx-loader` | `Removed plugin mcp from Ghidra <version>.` |
| `ghidra-manager open PROJECT` | `--program PROGRAM`, `--timeout SECONDS`, `--base-port PORT` | `GhidraMCP instance ready:` |
| `ghidra-manager launch [GHIDRA_ARGS...]` | Remaining arguments pass through to Ghidra | `Launching Ghidra <version> with JDK 21...` |
| `ghidra-manager launch-multi [PROJECT.gpr ...]` | `--count N`, `--timeout SECONDS`, `--base-port PORT` | `GhidraMCP instances ready:` |
| `ghidra-manager bridge [BRIDGE_ARGS...]` | Remaining arguments pass through to the bridge | `<stdio bridge starts and waits for MCP traffic>` |
| `ghidra-manager compare SOURCE_PROJECT TARGET_PROJECT` | `--base-port PORT` | `Plan saved: <manager-home>/compare-plans/<plan>.json` |
| `ghidra-manager compare --apply PLAN` | No source or target arguments | `Applied <count> operations to <target>.` |
| `ghidra-manager coverage COMMAND` | `init`, `scan`, `seed`, `validate`, `report`, `diff`, `plans`, `apply` | `Coverage plan saved: <repository>/reports/coverage/plans/<plan>.json` |
| `ghidra-manager instances` | `--base-port PORT` | `MCP port 8089` |

`launch` and `bridge` deliberately pass remaining arguments through rather than
interpreting them. Environment variables can also set the manager home, MCP
base port, launch timeout, and GitHub authentication; those are described in
the detailed sections below.

## Install

Install [`uv`](https://docs.astral.sh/uv/) and a 64-bit JDK 21. The CLI uses uv
to provision Python 3.13, so a system Python installation is not required.

Install the published CLI in an isolated tool environment:

```bash
uv tool install ghidra-manager
ghidra-manager help
```

Upgrade it independently of managed Ghidra installations and plugins:

```bash
uv tool upgrade ghidra-manager
```

For development from a checkout:

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

Representative output:

```text
Active Ghidra:      <ghidra-version>
Active plugin:      ghidra-lx-loader <plugin-version> (installed)
Active plugin:      mcp <plugin-version> (installed)
Previous pair:      Ghidra <previous-version>; plugins mcp
Upstream Ghidra:    <ghidra-version>
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

Representative ready output:

```text
OK      active-pair: Ghidra <version>; plugins ghidra-lx-loader, mcp
OK      project: /projects/ripper.gpr
OK      instance: PID <pid> on http://127.0.0.1:8089
OK      program: RIPPER.EXE is open
OK      analysis: RIPPER.EXE analyzed; 847 functions
Doctor result: ready
```

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

The bundled registry is
[`src/ghidra_manager/plugin_registry.json`](https://github.com/alexbevi/ghidra-manager/blob/main/src/ghidra_manager/plugin_registry.json),
not a remote marketplace. Its initial reviewed catalog contains `mcp` and
`ghidra-lx-loader`. Discovery is read-only and works before Ghidra is installed.
Plugin versions are resolved from stable GitHub releases when a plugin is
installed or updated rather than being pinned in the registry.

`discover` shows registry membership and whether each plugin is selected in
the active pair:

```text
mcp | GhidraMCP | selected | bethington/ghidra-mcp
ghidra-lx-loader | Ghidra LX Loader | selected | yetmorecode/ghidra-lx-loader
```

`list` shows the resolved artifacts for the active Ghidra release:

```text
Plugins for Ghidra <ghidra-version>:
ghidra-lx-loader | <plugin-version> | <release-tag> | <source-commit>
mcp | <plugin-version> | <release-tag> | <source-commit>
```

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
├── coverage/blobs/
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

Representative output:

```text
Projects known to Ghidra <version>:
ripper | ready | last-opened | active MCP port 8089 (PID <pid>) | /projects/ripper.gpr
harvester | ready | recent | inactive | /projects/harvester.gpr
2 recorded projects from <ghidra-settings>/preferences
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

Representative output:

```text
Opening /projects/ripper.gpr with Ghidra <version> and JDK 21...
Launcher PID <launcher-pid> | log <manager-home>/launch-logs/<launch>.log
Waiting up to 180 seconds for project ripper on ports 8089-8104...
GhidraMCP instance ready:
MCP port 8089 | PID <pid> | project ripper | http://127.0.0.1:8089
Open programs: RIPPER.LE
```

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

Representative output:

```text
MCP port 8089 | PID <pid> | project ripper | http://127.0.0.1:8089
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

## Use With Codex

The bundled [`ghidra-manager` skill](https://github.com/alexbevi/ghidra-manager/blob/main/skills/ghidra-manager/SKILL.md) teaches
Codex the manager's command boundaries, plugin lifecycle, launch checks, and
comparison safeguards. The repository directory is the source of truth; install
or link `skills/ghidra-manager` as `$CODEX_HOME/skills/ghidra-manager` and start
a new Codex session to make `$ghidra-manager` available. Once the skill and
bridge are available, a request can name the skill explicitly:

```text
Use $ghidra-manager to inspect the active Ghidra pair, discover the reviewed
plugins, open the ripper project, and confirm its MCP program before making any
changes.
```

The CLI identifies a live project; GhidraMCP identifies programs inside it.
When multiple programs are open, use their full Ghidra project paths on MCP
calls instead of relying on the active tab:

```text
/RIPPER.LE
/v1.05/RIPPER.EXE
```

`--program` is optional on `open` and `doctor`. Supply it when readiness depends
on one exact open program. Within MCP calls, always supply `program` when more
than one program is open.

## End-to-End Example: Compare RIPPER With v1.05

This example starts with an analyzed `/RIPPER.LE` in a recorded project named
`ripper` and a patched DOS/4GW executable at
`/path/to/Ripper/RIPPER/RIPPER.EXE`.

### 1. Install the reviewed runtime

Install Ghidra, inspect the bundled registry, and add both plugins before
launching Ghidra:

```bash
ghidra-manager sync
ghidra-manager plugins discover
ghidra-manager plugins install mcp
ghidra-manager plugins install ghidra-lx-loader
ghidra-manager plugins list
```

Plugin installation compiles each stable release for the active Ghidra version.
Close manager-owned Ghidra processes before installing or updating a plugin.

### 2. Register the bridge and verify the project

```bash
codex mcp add ghidra -- ghidra-manager bridge
ghidra-manager projects
ghidra-manager open ripper --program RIPPER.LE
ghidra-manager instances
ghidra-manager doctor ripper --program RIPPER.LE
```

At this point the manager has proven which Ghidra, plugin set, JDK, project,
process, port, and program are in use.

### 3. Import the patched executable through MCP

The manager does not duplicate Ghidra's import API. Ask Codex to use GhidraMCP
after the verified launch:

```text
Use $ghidra-manager. In the ripper project, create the virtual folder /v1.05
and import /path/to/Ripper/RIPPER/RIPPER.EXE there with the LX loader. Keep
/RIPPER.LE unchanged. Run analysis, save the new program, and verify its format,
project path, and function count through MCP.
```

The important verification is the loader result, not just a successful import:

```text
name:              RIPPER.EXE
project path:      /v1.05/RIPPER.EXE
executable format: Linear Executable (LE-Style DOS)
language:          x86:LE:32:default
analysis:          complete
```

### 4. Compare and synchronize conservatively

Both binaries can share one MCP instance while remaining unambiguous:

```text
/RIPPER.LE            original documentation source
/v1.05/RIPPER.EXE     patched v1.05 target
```

For programs in one project, ask Codex to query GhidraMCP with those full paths.
Transfer function documentation only for unique exact normalized-code matches,
preserve target conflicts, and review changed functions separately. Portable
datatype graphs such as structures, enums, arrays, pointers, and function
signatures can be copied source-to-target after equivalence checks; do not copy
address-derived `switchD_*` namespaces between rebuilt binaries.

The RIPPER run that informed this tutorial produced:

```text
Original /RIPPER.LE:        1,682 functions, 561 data types
Target /v1.05/RIPPER.EXE:     847 functions, 567 data types
Unique exact matches:          675 functions
Target documentation:          679/847 functions (80.2%)
Copied source data types:       561/561 equivalent
```

Those counts are specific to this sample. The reusable value is the guarded
workflow: reproducible plugins, verified runtime identity, explicit program
paths, exact-match transfer, conflict preservation, and post-save health checks.

Finish with:

```bash
ghidra-manager doctor ripper --program RIPPER.EXE
ghidra-manager instances
```

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

`compare` requires two distinct responding project instances. For two programs
inside one project, use the full-path MCP workflow in the RIPPER example instead
of trying to launch the same project twice.

## Track Reimplementation Coverage

Coverage tracking relates a Ghidra-analyzed source binary to an external
reimplementation without treating a function mention or commit message as
proof of completed behavior. Generated evidence and human-reviewed coverage
statuses remain separate, and no coverage command mutates a Ghidra program.

Initialize a local coverage workspace from the reimplementation checkout:

```bash
ghidra-manager coverage init \
  --repository /path/to/scummvm \
  --adapter scummvm \
  --project ripper \
  --program /RIPPER.LE \
  --scope engines/ripper
```

The default workspace is `reports/coverage/` inside that repository. The
command adds `/reports/coverage/` to the checkout's local
`.git/info/exclude`; it does not edit the tracked `.gitignore`. Profiles,
reviewed ledgers, snapshots, evidence, retained plans, and reports stay local
and uncommitted. The manager home contains only disposable content-addressed
scan payloads.

With the exact project and program open, create a read-only scan plan:

```bash
ghidra-manager coverage scan
ghidra-manager coverage plans
ghidra-manager coverage apply reports/coverage/plans/<plan>.json
ghidra-manager coverage seed
ghidra-manager coverage apply reports/coverage/plans/<seed-plan>.json
```

`scan` reads the program, Git history, source comments, architecture anchors,
and adapter registries. It refuses a dirty reimplementation checkout unless
`--allow-dirty` is supplied. A dirty scan records the tracked diff and included
untracked-file content in its repository fingerprint.

Applying a plan rechecks the profile, reviewed ledger, repository revision and
content, snapshot identity, and live Ghidra program when the scan was live.
Apply publishes immutable snapshot/evidence files and updates active pointers,
but never changes `ledger.json`. Reviewers edit that JSON ledger manually and
validate it:

```bash
ghidra-manager coverage validate
ghidra-manager coverage report
```

`seed` automates the ledger bookkeeping after a scan has been applied. It
creates a retained plan that adds missing functions and behavioral units as
`unreviewed`/`unknown`, attaches exact generated evidence to functions, and
publishes a deterministic `review-queue.json`. Applying a seed plan may refresh
evidence, subsystem, or reachability on records that are still unreviewed. It
never changes an already reviewed scope, status, notes, deviations, or
verification record.

Review-queue suggestions are advisory. The seed may suggest `partial` only
when an unsupported diagnostic is explicitly linked to the same original
function. A diagnostic elsewhere in the same source file raises review
priority but leaves the suggestion `unknown`. Seed never suggests `complete`,
`equivalent`, `not_applicable`, or a verified state. Candidates are ordered by
deterministic evidence, diagnostic, and reachability factors so review can
begin with the strongest mappings.

The ScummVM RIPPER adapter also seeds a small catalog of player-visible
scenarios, including startup, new-game bootstrap, scripted transitions,
puzzles, WAC, Cyber, combat, save/restore, and chapter progression. These are
ordinary unreviewed behavioral records with `unit_type: "scenario"`; the
adapter does not claim that they work. Reviewers provide their scope, status,
player impact, known deviations, and verification records in `ledger.json`.

Reports lead with assessment readiness and evidence quality before showing any
coverage ratio. When no in-scope denominator has been reviewed, the Markdown
report says that implementation coverage and gap analysis are unavailable
instead of presenting `0 / 0` as a result. If a current review queue exists,
the report includes its suggested in-scope count, confidence distribution, and
subsystem backlog. Evidence-link counts remain traceability signals rather than
completion claims.

The engineering section distinguishes function traceability, conservative
reviewed coverage, the partial-inclusive coverage ceiling, behavioral-unit
status, verification state, and instruction-weighted views. Behavioral coverage
is the primary functional signal when reviewed units exist. Reports include a
subsystem matrix with reviewed totals, status counts, and independently
verified-unit counts; function-count and instruction-weighted metrics remain
engineering detail. A player-scenario table shows scope, status,
verification, and player impact separately. The report also selects
deterministic representative completed, equivalent, partial, and missing
findings, including player impact, known missing branches, and deviations when
reviewers supplied them. A stored snapshot supports scanning and report
regeneration without a live Ghidra instance:

```bash
ghidra-manager coverage scan \
  --offline-snapshot sha256:<snapshot-id>
```

Compare two canonical reports explicitly:

```bash
ghidra-manager coverage diff base.json head.json \
  --json coverage-diff.json \
  --markdown coverage-diff.md
```

Diffs retain exact record-level added, removed, resolved, reopened,
reclassified, verification, and evidence-only changes. Their Markdown begins
with player-visible newly covered behavior, regressions, reviewed new gaps,
verification upgrades or downgrades, and critical-progression changes. Merely
discovering a new unreviewed source unit records it as added; it is not labeled
as a new gap.

The initial ScummVM adapter recognizes RIPPER function/address anchors, script
opcodes, scene actions, architecture references, and unsupported diagnostics.
Those observations seed evidence only. `complete`, `partial`, `equivalent`,
`missing`, `not_applicable`, and verification states are reviewer decisions.

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
