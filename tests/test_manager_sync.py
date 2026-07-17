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
from ghidra_manager.models import ManagerState, PairMetadata
from ghidra_manager.storage import StateStore, atomic_json


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
        self.files = {
            "GhidraMCP-5.14.2.zip": _zip(
                {
                    "GhidraMCP/extension.properties": (
                        b"name=GhidraMCP\n"
                        b"description=Ghidra MCP Plugin version 5.14.2.\n"
                        b"version=12.1.2\n",
                        0o644,
                    ),
                    "GhidraMCP/lib/plugin.jar": (b"plugin", 0o644),
                }
            ),
            "bridge_mcp_ghidra.py": b"# /// script\n",
            "requirements.txt": b"mcp\n",
            "ghidra_12.1.2_PUBLIC_20260623.zip": _zip(
                {
                    "ghidra_12.1.2_PUBLIC/ghidraRun": (b"#!/bin/sh\n", 0o755),
                    "ghidra_12.1.2_PUBLIC/ghidraRun.bat": (b"@echo off\r\n", 0o644),
                    "ghidra_12.1.2_PUBLIC/Ghidra/application.properties": (
                        b"application.version=12.1.2\napplication.release.name=PUBLIC\n",
                        0o644,
                    ),
                }
            ),
        }
        self.responses: dict[str, object] = {
            "repos/bethington/ghidra-mcp/releases/latest": {
                "tag_name": "v5.14.2",
                "assets": [
                    _asset(name, self.files[name])
                    for name in (
                        "GhidraMCP-5.14.2.zip",
                        "bridge_mcp_ghidra.py",
                        "requirements.txt",
                    )
                ],
            },
            "repos/NationalSecurityAgency/ghidra/releases/tags/Ghidra_12.1.2_build": {
                "assets": [
                    _asset(
                        "ghidra_12.1.2_PUBLIC_20260623.zip",
                        self.files["ghidra_12.1.2_PUBLIC_20260623.zip"],
                    )
                ]
            },
            "repos/NationalSecurityAgency/ghidra/releases/latest": {"name": "Ghidra 12.2"},
        }

    def get_json(self, endpoint: str) -> object:
        return self.responses[endpoint]

    def download(self, url: str, destination: Path) -> None:
        name = url.rsplit("/", 1)[-1]
        self.downloads.append(name)
        destination.write_bytes(self.files[name])


def test_sync_installs_and_is_idempotent(tmp_path: Path) -> None:
    paths = ManagerPaths(tmp_path / "managed")
    client = SyncClient()
    manager = Manager(paths, client, process_check=lambda _: False)

    lines = manager.sync()

    assert lines[-1] == "Active pair: Ghidra 12.1.2 with GhidraMCP 5.14.2."
    state = json.loads(paths.state.read_text(encoding="utf-8"))
    assert state["current"] == "ghidra-12.1.2__mcp-5.14.2"
    assert state["previous"] is None
    installed = paths.ghidra / "12.1.2/Ghidra/Extensions/GhidraMCP/extension.properties"
    assert installed.is_file()
    if os.name != "nt":
        assert (paths.ghidra / "12.1.2/ghidraRun").stat().st_mode & stat.S_IXUSR

    second = manager.sync()

    assert second[-1] == "Already current: Ghidra 12.1.2 with GhidraMCP 5.14.2."
    assert client.downloads.count("ghidra_12.1.2_PUBLIC_20260623.zip") == 1


def test_sync_dry_run_does_not_create_state(tmp_path: Path) -> None:
    paths = ManagerPaths(tmp_path / "managed")
    manager = Manager(paths, SyncClient(), process_check=lambda _: False)

    lines = manager.sync(dry_run=True)

    assert lines[-1] == "Dry run: would activate Ghidra 12.1.2 with GhidraMCP 5.14.2."
    assert not paths.state.exists()


def test_rollback_reinstalls_shared_ghidra_extension(tmp_path: Path) -> None:
    paths = ManagerPaths(tmp_path / "managed")
    manager = Manager(paths, SyncClient(), process_check=lambda _: False)
    manager.sync()
    store = StateStore(paths)
    current = store.load().current
    assert current is not None
    previous = PairMetadata(
        pair_id="ghidra-12.1.2__mcp-5.14.1",
        ghidra_version="12.1.2",
        mcp_version="5.14.1",
        ghidra_tag="Ghidra_12.1.2_build",
        mcp_tag="v5.14.1",
    )
    store.save_pair(previous)
    component = paths.mcp / previous.mcp_version
    component.mkdir(parents=True)
    extension_name = "GhidraMCP-5.14.1.zip"
    (component / extension_name).write_bytes(
        _zip(
            {
                "GhidraMCP/extension.properties": (
                    b"name=GhidraMCP\n"
                    b"description=Ghidra MCP Plugin version 5.14.1.\n"
                    b"version=12.1.2\n",
                    0o644,
                )
            }
        )
    )
    atomic_json(component / "metadata.json", {"extension_asset": extension_name})
    store.save(ManagerState(current=current, previous=previous.pair_id))

    assert manager.rollback() == ["Rolled back to Ghidra 12.1.2 with GhidraMCP 5.14.1."]
    assert store.load() == ManagerState(current=previous.pair_id, previous=current)
    installed = paths.ghidra / "12.1.2/Ghidra/Extensions/GhidraMCP/extension.properties"
    assert "5.14.1" in installed.read_text(encoding="utf-8")


def test_rollback_refuses_running_ghidra_without_changing_state(tmp_path: Path) -> None:
    paths = ManagerPaths(tmp_path / "managed")
    manager = Manager(paths, SyncClient(), process_check=lambda _: False)
    manager.sync()
    store = StateStore(paths)
    state = store.load()
    store.save(ManagerState(current=state.current, previous=state.current))
    blocked = Manager(paths, SyncClient(), process_check=lambda _: True)

    with pytest.raises(ManagerError, match="Close the managed Ghidra"):
        blocked.rollback()

    assert store.load() == ManagerState(current=state.current, previous=state.current)
