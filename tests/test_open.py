from pathlib import Path
from unittest.mock import Mock

import pytest
from test_manager_sync import SyncClient

from ghidra_manager.config import ManagerPaths
from ghidra_manager.errors import ManagerError
from ghidra_manager.manager import Manager
from ghidra_manager.mcp import Instance
from ghidra_manager.models import ManagerState, PairMetadata
from ghidra_manager.storage import StateStore


def _manager(monkeypatch, tmp_path: Path, discovery) -> tuple[Manager, Path]:  # type: ignore[no-untyped-def]
    paths = ManagerPaths(tmp_path / "managed")
    store = StateStore(paths)
    pair = PairMetadata("pair", "12.1.2", "5.14.2", "ghidra-tag", "mcp-tag")
    store.save_pair(pair)
    store.save(ManagerState(current="pair"))
    application = paths.ghidra / "12.1.2/Ghidra/application.properties"
    application.parent.mkdir(parents=True)
    application.write_text(
        "application.version=12.1.2\napplication.release.name=PUBLIC\n", encoding="utf-8"
    )
    settings = tmp_path / "settings"
    settings.mkdir()
    project = tmp_path / "demo.gpr"
    project.write_text("", encoding="utf-8")
    project.with_suffix(".rep").mkdir()
    (settings / "preferences").write_text(
        f"LastOpenedProject=ghidra:{project}\nRecentProjects=\n", encoding="utf-8"
    )
    monkeypatch.setattr("ghidra_manager.manager.ghidra_settings_dir", lambda *_: settings)
    return Manager(paths, SyncClient(), instance_discovery=discovery), project


def test_open_resolves_recorded_name_and_waits_for_program(
    monkeypatch, tmp_path: Path
) -> None:
    ready = Instance(8089, 20, "demo", ("DEMO.EXE",))
    scans = iter([[], [ready]])
    manager, project = _manager(monkeypatch, tmp_path, lambda _: next(scans))
    started: list[Path | None] = []

    def start(_install, selected, _java, log):  # type: ignore[no-untyped-def]
        started.append(selected)
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text("", encoding="utf-8")
        return Mock(pid=10, poll=lambda: None)

    monkeypatch.setattr("ghidra_manager.manager.find_java21", lambda: tmp_path / "jdk")
    monkeypatch.setattr("ghidra_manager.manager.start_ghidra_instance", start)
    monkeypatch.setattr("ghidra_manager.manager.time.sleep", lambda _: None)

    lines = manager.open_project("demo", program="DEMO.EXE", timeout=5)

    assert started == [project.resolve()]
    assert lines[-2:] == [
        "MCP port 8089 | PID 20 | project demo | http://127.0.0.1:8089",
        "Open programs: DEMO.EXE",
    ]


def test_open_rejects_active_project(monkeypatch, tmp_path: Path) -> None:
    active = Instance(8089, 20, "demo", ("DEMO.EXE",))
    manager, _ = _manager(monkeypatch, tmp_path, lambda _: [active])

    with pytest.raises(ManagerError, match="already active"):
        manager.open_project("demo")


def test_open_reports_early_exit(monkeypatch, tmp_path: Path) -> None:
    manager, project = _manager(monkeypatch, tmp_path, lambda _: [])

    def start(_install, selected, _java, log):  # type: ignore[no-untyped-def]
        assert selected == project.resolve()
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text("startup failed", encoding="utf-8")
        return Mock(pid=10, poll=lambda: 1)

    monkeypatch.setattr("ghidra_manager.manager.find_java21", lambda: tmp_path / "jdk")
    monkeypatch.setattr("ghidra_manager.manager.start_ghidra_instance", start)
    monkeypatch.setattr("ghidra_manager.manager.time.sleep", lambda _: None)

    with pytest.raises(ManagerError, match="startup failed"):
        manager.open_project(str(project))
