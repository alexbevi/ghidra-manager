from pathlib import Path

from ghidra_manager.config import ManagerPaths
from ghidra_manager.manager import Manager
from ghidra_manager.mcp import Instance
from ghidra_manager.models import ManagerState
from ghidra_manager.storage import StateStore
from tests.plugin_fixtures import managed_pair
from tests.test_manager_sync import SyncClient


def test_projects_reports_storage_and_active_state(monkeypatch, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    paths = ManagerPaths(tmp_path / "managed")
    store = StateStore(paths)
    pair = managed_pair()
    store.save_pair(pair)
    store.save(ManagerState(current="pair"))
    application = paths.ghidra / "12.1.2/Ghidra/application.properties"
    application.parent.mkdir(parents=True)
    application.write_text(
        "application.version=12.1.2\napplication.release.name=PUBLIC\n", encoding="utf-8"
    )
    settings = tmp_path / "settings"
    project = tmp_path / "demo"
    project.with_suffix(".gpr").write_text("", encoding="utf-8")
    project.with_suffix(".rep").mkdir()
    settings.mkdir()
    preferences = settings / "preferences"
    missing = tmp_path / "missing"
    preferences.write_text(
        f"LastOpenedProject=ghidra:{project}.gpr\nRecentProjects={project};{missing}\n",
        encoding="utf-8",
    )
    monkeypatch.setattr("ghidra_manager.manager.ghidra_settings_dir", lambda *_: settings)
    manager = Manager(
        paths,
        SyncClient(),
        instance_discovery=lambda _: [Instance(8089, 99, "demo")],
    )

    lines = manager.projects()

    assert lines[1] == (
        f"demo | ready | last-opened | active MCP port 8089 (PID 99) | {project}.gpr"
    )
    assert lines[2] == f"missing | missing | recent | inactive | {missing}.gpr"
    assert lines[-1] == f"2 recorded projects from {preferences}"
