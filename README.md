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

## Troubleshooting

- **JDK 21 not found:** run `brew install openjdk@21`, then retry `launch`.
- **GitHub API rate limit:** set `GH_TOKEN` or `GITHUB_TOKEN` and retry.
- **MCP connection refused:** open CodeBrowser, enable GhidraMCP, and start its
  server from the **Tools > GhidraMCP** menu.
- **Update refused while Ghidra is running:** close the managed Ghidra process
  before replacing or rolling back its extension.
