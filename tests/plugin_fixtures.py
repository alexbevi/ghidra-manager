from ghidra_manager.models import PairMetadata, PluginMetadata


def mcp_plugin(version: str = "5.14.2", tag: str | None = None) -> PluginMetadata:
    resolved_tag = tag or f"v{version}"
    return PluginMetadata(
        plugin_id="mcp",
        version=version,
        tag=resolved_tag,
        commit="a" * 40,
        extension_name="GhidraMCP",
        extension_root="GhidraMCP",
        artifact=f"plugins/mcp/12.1.2/{'a' * 40}/extension.zip",
        digest=f"sha256:{'0' * 64}",
        runtime_files=(("bridge", "plugins/mcp/bridge_mcp_ghidra.py"),),
    )


def managed_pair(
    pair_id: str = "pair",
    ghidra_version: str = "12.1.2",
    ghidra_tag: str = "ghidra-tag",
    *,
    plugins: tuple[PluginMetadata, ...] | None = None,
) -> PairMetadata:
    return PairMetadata(
        pair_id=pair_id,
        ghidra_version=ghidra_version,
        ghidra_tag=ghidra_tag,
        plugins=plugins if plugins is not None else (mcp_plugin(),),
    )
