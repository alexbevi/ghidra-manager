from pathlib import Path
from unittest.mock import Mock

import pytest

from ghidra_manager.config import ManagerPaths
from ghidra_manager.errors import ManagerError
from ghidra_manager.manager import Manager
from ghidra_manager.mcp import Instance
from ghidra_manager.models import ManagerState
from ghidra_manager.storage import StateStore
from tests.plugin_fixtures import managed_pair
from tests.test_manager_sync import SyncClient


def _manager(tmp_path: Path, discovery) -> Manager:  # type: ignore[no-untyped-def]
    paths = ManagerPaths(tmp_path / "managed")
    store = StateStore(paths)
    pair = managed_pair()
    store.save_pair(pair)
    store.save(ManagerState(current="pair"))
    return Manager(paths, SyncClient(), instance_discovery=discovery)


def test_launch_multi_waits_for_new_mcp_pids(monkeypatch, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    projects = [tmp_path / "one.gpr", tmp_path / "two.gpr"]
    for project in projects:
        project.write_text("", encoding="utf-8")
    baseline = [Instance(8089, 10, "existing")]
    ready = baseline + [Instance(8090, 20, "one"), Instance(8091, 21, "two")]
    scans = iter([baseline, ready])
    manager = _manager(tmp_path, lambda _: next(scans))
    started: list[Path | None] = []

    def start(_install, project, _java, log):  # type: ignore[no-untyped-def]
        started.append(project)
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text("", encoding="utf-8")
        return Mock(pid=100 + len(started), poll=lambda: None)

    monkeypatch.setattr("ghidra_manager.manager.find_java21", lambda: tmp_path / "jdk")
    monkeypatch.setattr("ghidra_manager.manager.start_ghidra_instance", start)
    monkeypatch.setattr("ghidra_manager.manager.time.sleep", lambda _: None)

    lines = manager.launch_multi([str(path) for path in projects], timeout=5)

    assert started == [path.resolve() for path in projects]
    assert lines[-2:] == [
        "MCP port 8090 | PID 20 | project one | http://127.0.0.1:8090",
        "MCP port 8091 | PID 21 | project two | http://127.0.0.1:8091",
    ]


def test_launch_multi_rejects_duplicate_project_names(tmp_path: Path) -> None:
    first = tmp_path / "a/demo.gpr"
    second = tmp_path / "b/demo.gpr"
    first.parent.mkdir()
    second.parent.mkdir()
    first.write_text("", encoding="utf-8")
    second.write_text("", encoding="utf-8")
    manager = _manager(tmp_path, lambda _: [])

    with pytest.raises(ManagerError, match="Project names must be unique"):
        manager.launch_multi([str(first), str(second)])
