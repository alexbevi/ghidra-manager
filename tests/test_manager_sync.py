import hashlib
import io
import json
import os
import stat
import zipfile
from pathlib import Path

import pytest

from ghidra_manager.config import ManagerPaths
from ghidra_manager.errors import ManagerError
from ghidra_manager.manager import Manager
from ghidra_manager.storage import StateStore

COMMIT = "a" * 40


def _zip(files: dict[str, tuple[bytes, int]]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for name, (content, mode) in files.items():
            info = zipfile.ZipInfo(name)
            info.external_attr = (stat.S_IFREG | mode) << 16
            archive.writestr(info, content)
    return output.getvalue()


def _asset(name: str, content: bytes) -> dict[str, str]:
    return {
        "name": name,
        "browser_download_url": f"https://download.test/{name}",
        "digest": f"sha256:{hashlib.sha256(content).hexdigest()}",
    }


class SyncClient:
    def __init__(self) -> None:
        self.downloads: list[str] = []
        self.ghidra = _zip(
            {
                "ghidra_12.1.2_PUBLIC/ghidraRun": (b"#!/bin/sh\n", 0o755),
                "ghidra_12.1.2_PUBLIC/ghidraRun.bat": (b"@echo off\r\n", 0o644),
                "ghidra_12.1.2_PUBLIC/Ghidra/application.properties": (
                    b"application.version=12.1.2\napplication.release.name=PUBLIC\n",
                    0o644,
                ),
                "ghidra_12.1.2_PUBLIC/support/gradle/gradlew": (b"#!/bin/sh\n", 0o755),
                "ghidra_12.1.2_PUBLIC/support/gradle/gradlew.bat": (
                    b"@echo off\r\n",
                    0o644,
                ),
            }
        )
        self.source = _zip(
            {
                "source/bridge_mcp_ghidra.py": (b"# /// script\n", 0o644),
                "source/requirements.txt": (b"mcp\n", 0o644),
            }
        )
        self.responses: dict[str, object] = {
            "repos/NationalSecurityAgency/ghidra/releases/latest": {
                "name": "Ghidra 12.1.2",
                "tag_name": "Ghidra_12.1.2_build",
                "assets": [_asset("ghidra_12.1.2_PUBLIC_20260623.zip", self.ghidra)],
            },
            "repos/bethington/ghidra-mcp/releases/latest": {"tag_name": "v5.14.2"},
            "repos/bethington/ghidra-mcp/git/ref/tags/v5.14.2": {
                "object": {"type": "commit", "sha": COMMIT}
            },
        }

    def get_json(self, endpoint: str) -> object:
        return self.responses[endpoint]

    def download(self, url: str, destination: Path) -> None:
        self.downloads.append(url)
        destination.write_bytes(self.source if "/zipball/" in url else self.ghidra)


def _fake_build(
    _install: Path,
    source: Path,
    _task: str,
    _java_home: Path,
    _cache: Path,
) -> str:
    output = source / "build/distributions/GhidraMCP-5.14.2.zip"
    output.parent.mkdir(parents=True)
    output.write_bytes(
        _zip(
            {
                "GhidraMCP/extension.properties": (
                    b"name=GhidraMCP\n"
                    b"description=Ghidra MCP Plugin version 5.14.2.\n"
                    b"version=12.1.2\n",
                    0o644,
                ),
                "GhidraMCP/lib/plugin.jar": (b"plugin", 0o644),
            }
        )
    )
    return "BUILD SUCCESSFUL"


def test_sync_installs_plugin_free_ghidra_and_is_idempotent(tmp_path: Path) -> None:
    paths = ManagerPaths(tmp_path / "managed")
    client = SyncClient()
    manager = Manager(paths, client, process_check=lambda _: False)

    lines = manager.sync()

    assert lines[-1] == "Active pair: Ghidra 12.1.2; plugins none."
    state = json.loads(paths.state.read_text(encoding="utf-8"))
    assert state["current"] == "ghidra-12.1.2__plugins-none"
    assert state["schema_version"] == 2
    assert not (paths.ghidra / "12.1.2/Ghidra/Extensions/GhidraMCP").exists()
    if os.name != "nt":
        assert (paths.ghidra / "12.1.2/ghidraRun").stat().st_mode & stat.S_IXUSR

    second = manager.sync()

    assert second[-1] == "Already current: Ghidra 12.1.2; plugins none."
    assert sum("ghidra_12.1.2" in url for url in client.downloads) == 1


def test_sync_dry_run_does_not_create_state(tmp_path: Path) -> None:
    paths = ManagerPaths(tmp_path / "managed")
    manager = Manager(paths, SyncClient(), process_check=lambda _: False)

    lines = manager.sync(dry_run=True)

    assert lines[-1] == "Dry run: would activate Ghidra 12.1.2; plugins none."
    assert not paths.state.exists()


def test_plugin_install_is_cached_and_rollback_restores_empty_set(
    monkeypatch, tmp_path: Path
) -> None:  # type: ignore[no-untyped-def]
    paths = ManagerPaths(tmp_path / "managed")
    client = SyncClient()
    manager = Manager(paths, client, process_check=lambda _: False)
    monkeypatch.setattr("ghidra_manager.manager.find_java21", lambda: tmp_path / "jdk")
    monkeypatch.setattr("ghidra_manager.manager.run_plugin_build", _fake_build)
    manager.sync()

    assert manager.plugin_install("mcp") == ["Installed plugin mcp 5.14.2 for Ghidra 12.1.2."]
    state = StateStore(paths).load()
    assert state.current is not None
    pair = StateStore(paths).pair(state.current)
    assert pair.plugin("mcp") is not None
    installed = paths.ghidra / "12.1.2/Ghidra/Extensions/GhidraMCP"
    assert (installed / ".manager-plugin.json").is_file()
    assert manager.plugin_install("mcp") == ["Plugin already current: mcp 5.14.2."]
    assert sum("/zipball/" in url for url in client.downloads) == 1

    assert manager.rollback() == ["Rolled back to Ghidra 12.1.2; plugins none."]
    assert not installed.exists()


def test_plugin_install_refuses_running_ghidra_without_changing_state(
    tmp_path: Path,
) -> None:
    paths = ManagerPaths(tmp_path / "managed")
    manager = Manager(paths, SyncClient(), process_check=lambda _: False)
    manager.sync()
    state = StateStore(paths).load()
    blocked = Manager(paths, SyncClient(), process_check=lambda _: True)

    with pytest.raises(ManagerError, match="Close the managed Ghidra"):
        blocked.plugin_install("mcp")

    assert StateStore(paths).load() == state


def test_mcp_workflows_fail_with_install_hint(tmp_path: Path) -> None:
    paths = ManagerPaths(tmp_path / "managed")
    manager = Manager(paths, SyncClient(), process_check=lambda _: False)
    manager.sync()

    with pytest.raises(ManagerError, match="plugins install mcp"):
        manager.require_mcp()

    checks = manager.doctor()
    extension = next(check for check in checks if check.name == "extension")
    assert extension.level == "error"
    assert "plugins install mcp" in extension.detail


def test_failed_plugin_build_leaves_pair_and_extensions_unchanged(
    monkeypatch, tmp_path: Path
) -> None:  # type: ignore[no-untyped-def]
    paths = ManagerPaths(tmp_path / "managed")
    manager = Manager(paths, SyncClient(), process_check=lambda _: False)
    manager.sync()
    original = StateStore(paths).load()
    monkeypatch.setattr("ghidra_manager.manager.find_java21", lambda: tmp_path / "jdk")

    def fail_build(*_args, **_kwargs):  # type: ignore[no-untyped-def]
        raise ManagerError("Plugin build failed")

    monkeypatch.setattr("ghidra_manager.manager.run_plugin_build", fail_build)

    with pytest.raises(ManagerError, match="Plugin build failed"):
        manager.plugin_install("mcp")

    assert StateStore(paths).load() == original
    assert not (paths.ghidra / "12.1.2/Ghidra/Extensions/GhidraMCP").exists()
