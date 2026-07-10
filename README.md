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
- a 64-bit JDK 21 for running Ghidra

Install the non-system prerequisites with Homebrew when needed:

```bash
brew install jq openjdk@21
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

`GH_TOKEN` or `GITHUB_TOKEN` may be set to authenticate GitHub API requests.
Unauthenticated requests also work within GitHub's public rate limit.

## Managed Layout

All downloaded and generated state is ignored by Git under `.managed/`:

```text
.managed/
├── ghidra/<version>/
├── ghidra-mcp/<version>/
├── pairs/<ghidra-and-mcp-versions>/
└── current -> pairs/<active-pair>/
```

GhidraMCP is extracted into the managed Ghidra installation's
`Ghidra/Extensions/GhidraMCP` directory, following Ghidra's documented
system-managed extension layout. Existing Ghidra installations elsewhere on
the machine are not changed.

Do not edit `.managed/` by hand. Run `sync` to repair missing or inconsistent
managed files. Close managed Ghidra instances before installing an update.

