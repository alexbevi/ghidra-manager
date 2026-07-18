import pytest

from ghidra_manager.errors import ManagerError
from ghidra_manager.plugins import load_registry, parse_registry, plugin_definition


def test_bundled_registry_contains_initial_plugins() -> None:
    plugins = load_registry()

    assert [plugin.plugin_id for plugin in plugins] == ["mcp", "ghidra-lx-loader"]
    assert plugin_definition("mcp").runtime_file("bridge") == "bridge_mcp_ghidra.py"
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
