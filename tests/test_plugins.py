import pytest

from ghidra_manager.errors import ManagerError
from ghidra_manager.plugins import (
    load_registry,
    parse_registry,
    plugin_definition,
    resolve_plugin_source,
)


def test_bundled_registry_contains_initial_plugins() -> None:
    plugins = load_registry()

    assert [plugin.plugin_id for plugin in plugins] == ["mcp", "ghidra-lx-loader"]
    assert plugin_definition("mcp").runtime_file("bridge") == "bridge_mcp_ghidra.py"
    assert "ghidra_mcp_bridge" in (
        plugin_definition("mcp").runtime_asset_pattern("bridge") or ""
    )
    assert plugin_definition("ghidra-lx-loader").extension_name == "LxLoader"


def test_registry_rejects_duplicate_ids() -> None:
    entry = {
        "id": "demo",
        "name": "Demo",
        "description": "Demo plugin",
        "repository": "owner/demo",
        "extension_name": "Demo",
        "extension_root": "Demo",
        "build_task": "buildExtension",
        "artifact_pattern": "dist/*.zip",
    }

    with pytest.raises(ManagerError, match="Duplicate plugin ID"):
        parse_registry({"schema_version": 1, "plugins": [entry, entry]})


def test_registry_rejects_unsafe_paths() -> None:
    entry = {
        "id": "demo",
        "name": "Demo",
        "description": "Demo plugin",
        "repository": "owner/demo",
        "extension_name": "Demo",
        "extension_root": "../Demo",
        "build_task": "buildExtension",
        "artifact_pattern": "dist/*.zip",
    }

    with pytest.raises(ManagerError, match="safe relative path"):
        parse_registry({"schema_version": 1, "plugins": [entry]})


def test_unknown_plugin_lists_available_ids() -> None:
    with pytest.raises(ManagerError, match="Available plugins: mcp, ghidra-lx-loader"):
        plugin_definition("missing")


def test_resolve_plugin_source_dereferences_annotated_tag() -> None:
    class Client:
        responses = {
            "repos/bethington/ghidra-mcp/releases/latest": {"tag_name": "v5.14.2"},
            "repos/bethington/ghidra-mcp/git/ref/tags/v5.14.2": {
                "object": {"type": "tag", "sha": "b" * 40}
            },
            f"repos/bethington/ghidra-mcp/git/tags/{'b' * 40}": {
                "object": {"type": "commit", "sha": "a" * 40}
            },
        }

        def get_json(self, endpoint: str) -> object:
            return self.responses[endpoint]

        def download(self, url, destination) -> None:  # type: ignore[no-untyped-def]
            raise AssertionError("resolution must not download source")

    source = resolve_plugin_source(Client(), plugin_definition("mcp"))

    assert source.version == "5.14.2"
    assert source.commit == "a" * 40
    assert source.archive_url.endswith(f"/zipball/{'a' * 40}")
    assert source.runtime_assets == ()


def test_resolve_plugin_source_includes_digest_verified_runtime_asset() -> None:
    digest = f"sha256:{'1' * 64}"

    class Client:
        responses = {
            "repos/bethington/ghidra-mcp/releases/latest": {
                "tag_name": "v6.0.0",
                "assets": [
                    {
                        "name": "ghidra_mcp_bridge-6.0.0-py3-none-any.whl",
                        "browser_download_url": "https://download.test/bridge.whl",
                        "digest": digest,
                    }
                ],
            },
            "repos/bethington/ghidra-mcp/git/ref/tags/v6.0.0": {
                "object": {"type": "commit", "sha": "a" * 40}
            },
        }

        def get_json(self, endpoint: str) -> object:
            return self.responses[endpoint]

        def download(self, url, destination) -> None:  # type: ignore[no-untyped-def]
            raise AssertionError("resolution must not download assets")

    source = resolve_plugin_source(Client(), plugin_definition("mcp"))

    assert len(source.runtime_assets) == 1
    name, asset = source.runtime_assets[0]
    assert name == "bridge"
    assert asset.digest == digest


def test_registry_rejects_shell_build_task() -> None:
    entry = {
        "id": "demo",
        "name": "Demo",
        "description": "Demo plugin",
        "repository": "owner/demo",
        "extension_name": "Demo",
        "extension_root": "Demo",
        "build_task": "buildExtension; touch bad",
        "artifact_pattern": "dist/*.zip",
    }

    with pytest.raises(ManagerError, match="Invalid plugin build task"):
        parse_registry({"schema_version": 1, "plugins": [entry]})
