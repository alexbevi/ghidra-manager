# Local Ghidra Manager

This directory manages a compatible Ghidra and
[GhidraMCP](https://github.com/bethington/ghidra-mcp) installation from one
script. It follows stable GitHub releases, verifies every downloaded asset with
its published SHA-256 digest, and installs GhidraMCP directly into the matching
Ghidra distribution.

## Prerequisites

The manager currently targets macOS. It requires:

- `curl`, `unzip`, and `shasum` from macOS
- [`jq`](https://jqlang.github.io/jq/)
- [`uv`](https://docs.astral.sh/uv/) for the isolated MCP bridge runtime
- a 64-bit JDK 21 for running Ghidra

Install the non-system prerequisites with Homebrew when needed:

```bash
brew install jq uv openjdk@21
```

## Install Or Update

Resolve and install the newest compatible stable pair:

```bash
./ghidra-manager.sh sync
```

The GhidraMCP release declares the Ghidra version it supports. When Ghidra has
a newer release that GhidraMCP does not yet declare, the manager keeps the
compatible Ghidra version and reports the held update.

Preview release selection without retaining downloads:

```bash
./ghidra-manager.sh sync --dry-run
```

Show active and upstream versions:

```bash
./ghidra-manager.sh status
```

The manager retains the current pair and one previous pair. Return to the
previous pair with:

```bash
./ghidra-manager.sh rollback
```

Close managed Ghidra instances before syncing or rolling back. Rollback also
reinstalls the retained extension, which keeps the bridge and Ghidra plugin at
the same version when both pairs use one Ghidra release.

`GH_TOKEN` or `GITHUB_TOKEN` may be set to authenticate GitHub API requests.
Unauthenticated requests also work within GitHub's public rate limit.

## Managed Layout

All downloaded and generated state is ignored by Git under `.managed/`:

```text
.managed/
├── ghidra/<version>/
├── ghidra-mcp/<version>/
├── pairs/<ghidra-and-mcp-versions>/
├── current -> pairs/<active-pair>/
├── previous -> pairs/<rollback-pair>/
├── python/
└── uv-cache/
```

GhidraMCP is extracted into the managed Ghidra installation's
`Ghidra/Extensions/GhidraMCP` directory, following Ghidra's documented
system-managed extension layout. Existing Ghidra installations elsewhere on
the machine are not changed.

Do not edit `.managed/` by hand. Run `sync` to repair missing or inconsistent
managed files. Close managed Ghidra instances before installing an update.

## Run Ghidra And The MCP Bridge

Launch the active installation with JDK 21:

```bash
./ghidra-manager.sh launch
```

On the first launch of a new Ghidra settings version:

1. Open or create a project and launch CodeBrowser.
2. Select **File > Configure > Configure All Plugins** and enable
   **GhidraMCP**.
3. Select **Tools > GhidraMCP > Start MCP Server**.

The plugin listens on `127.0.0.1:8089` by default. The stdio bridge connects
MCP clients to that plugin. Register its stable manager command with Codex:

```bash
codex mcp add ghidra -- /Users/alex/Workspace/ghidra/ghidra-manager.sh bridge
```

The bridge command uses `uv` to provision Python 3.13 and its dependencies
under `.managed/`; it does not use the system Python environment. To inspect
the upstream bridge options directly, run:

```bash
./ghidra-manager.sh bridge --help
```

## Compare Binaries Across Instances

Launch one Ghidra process per project and wait for each GhidraMCP server:

```bash
./ghidra-manager.sh launch-multi \
  /path/to/first-project.gpr \
  /path/to/second-project.gpr
```

Each project path and project filename must be different because Ghidra locks
projects for exclusive use and GhidraMCP selects instances by project name.
Explicit projects that are already active are rejected. If paths are omitted,
`launch-multi` opens two instances by default and you must select a different,
uniquely named project in each window:

```bash
./ghidra-manager.sh launch-multi --count 2
```

Open CodeBrowser and enable GhidraMCP in every new instance. The command waits
up to 180 seconds for the new endpoints, then prints verified output containing
the PID, project, URL, and distinct MCP port for each instance. Adjust the wait
or the plugin's configured base port when needed:

```bash
./ghidra-manager.sh launch-multi --count 2 --timeout 300 --base-port 8089
```

Multi-launch uses detached foreground launchers so the Ghidra processes remain
running if command output is redirected or piped. Startup logs are retained
under `.managed/launch-logs/` for troubleshooting.

List all currently responding instances without launching more:

```bash
./ghidra-manager.sh instances
```

List the projects recorded by the active Ghidra version:

```bash
./ghidra-manager.sh projects
```

This reads Ghidra's `RecentProjects` and `LastOpenedProject` registry rather
than searching arbitrary directories. Each result shows whether its `.gpr` and
`.rep` storage is ready, incomplete, or missing; whether it was last opened;
and whether it currently has a responding MCP port. Stale recent entries remain
visible as `missing` so they can be diagnosed or removed in Ghidra.

GhidraMCP automatically tries the 16-port range beginning at its configured
port, which is `8089-8104` by default. Its bridge exposes `list_instances` and
`connect_instance`; use those tools to select the first project, inspect it,
switch to the second project, compare it, and switch back for reverse-direction
checks. Project names must be distinct enough for `connect_instance` to select
them unambiguously.

## Troubleshooting

- **JDK 21 not found:** run `brew install openjdk@21`, then retry `launch`.
- **GitHub API rate limit:** set `GH_TOKEN` or `GITHUB_TOKEN` and retry.
- **MCP connection refused:** open CodeBrowser, enable GhidraMCP, and start its
  server from the **Tools > GhidraMCP** menu.
- **Multi-launch timed out:** finish opening CodeBrowser and enabling GhidraMCP
  in each new window, then run `./ghidra-manager.sh instances` to print ports.
- **Custom plugin port:** pass the configured value through `--base-port` or
  set `GHIDRA_MCP_BASE_PORT` before running discovery or multi-launch.
- **No recorded projects:** launch the managed Ghidra version once so it creates
  its preferences registry, then open the projects you want it to remember.
- **Update refused while Ghidra is running:** close the managed Ghidra process
  before replacing or rolling back its extension.
