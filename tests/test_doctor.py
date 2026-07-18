from pathlib import Path

from ghidra_manager.config import ManagerPaths
from ghidra_manager.manager import Manager
from ghidra_manager.mcp import AnalysisStatus, Instance, ServerInfo
from ghidra_manager.models import ManagerState
from ghidra_manager.storage import StateStore
from tests.plugin_fixtures import managed_pair
from tests.test_manager_sync import SyncClient


def _manager(monkeypatch, tmp_path: Path, instances: list[Instance]) -> Manager:  # type: ignore[no-untyped-def]
    paths = ManagerPaths(tmp_path / "managed")
    store = StateStore(paths)
    pair = managed_pair()
    store.save_pair(pair)
    store.save(ManagerState(current="pair"))
    install = paths.ghidra / "12.1.2"
    application = install / "Ghidra/application.properties"
    application.parent.mkdir(parents=True)
    application.write_text(
        "application.version=12.1.2\napplication.release.name=PUBLIC\n",
        encoding="utf-8",
    )
    (install / "ghidraRun").write_text("", encoding="utf-8")
    extension = install / "Ghidra/Extensions/GhidraMCP/extension.properties"
    extension.parent.mkdir(parents=True)
    extension.write_text("description=Ghidra MCP Plugin version 5.14.2.\n", encoding="utf-8")
    settings = tmp_path / "settings"
    settings.mkdir()
    project = tmp_path / "demo.gpr"
    project.write_text("", encoding="utf-8")
    project.with_suffix(".rep").mkdir()
    (settings / "preferences").write_text(
        f"LastOpenedProject=ghidra:{project}\nRecentProjects=\n", encoding="utf-8"
    )
    monkeypatch.setattr("ghidra_manager.manager.ghidra_settings_dir", lambda *_: settings)
    monkeypatch.setattr("ghidra_manager.manager.find_java21", lambda: tmp_path / "jdk")
    return Manager(paths, SyncClient(), instance_discovery=lambda _: instances)


def test_doctor_reports_ready_project(monkeypatch, tmp_path: Path) -> None:
    instance = Instance(8089, 20, "demo", ("DEMO.EXE",))
    manager = _manager(monkeypatch, tmp_path, [instance])
    monkeypatch.setattr(
        "ghidra_manager.manager.probe_server",
        lambda _: ServerInfo("5.14.2", "12.1.2", "21.0.11", 206),
    )
    monkeypatch.setattr(
        "ghidra_manager.manager.probe_analysis",
        lambda _port, program: AnalysisStatus(program, False, True, 123),
    )

    checks = manager.doctor("demo", program="DEMO.EXE")

    assert not [check for check in checks if check.level != "ok"]
    assert checks[-1].detail == "DEMO.EXE analyzed; 123 functions"


def test_doctor_reports_missing_instance(monkeypatch, tmp_path: Path) -> None:
    manager = _manager(monkeypatch, tmp_path, [])

    checks = manager.doctor("demo", program="DEMO.EXE")

    errors = {check.name: check.detail for check in checks if check.level == "error"}
    assert errors["instance"] == "no MCP instance reports project demo"
    assert errors["program"] == "--program requires one responding project instance"


def test_doctor_without_project_probes_each_live_server(monkeypatch, tmp_path: Path) -> None:
    instance = Instance(8089, 20, "demo", ("DEMO.EXE",))
    manager = _manager(monkeypatch, tmp_path, [instance])
    monkeypatch.setattr(
        "ghidra_manager.manager.probe_server",
        lambda _: ServerInfo("5.14.2", "12.1.2", "21.0.11", 206),
    )

    checks = manager.doctor()

    server = next(check for check in checks if check.name == "mcp-server:8089")
    assert server.level == "ok"
    assert "206 endpoints" in server.detail


def test_doctor_rejects_mismatched_live_server(monkeypatch, tmp_path: Path) -> None:
    instance = Instance(8089, 20, "demo", ("DEMO.EXE",))
    manager = _manager(monkeypatch, tmp_path, [instance])
    monkeypatch.setattr(
        "ghidra_manager.manager.probe_server",
        lambda _: ServerInfo("6.0.0", "12.2", "22.0.1", 0),
    )
    monkeypatch.setattr(
        "ghidra_manager.manager.probe_analysis",
        lambda _port, program: AnalysisStatus(program, False, True, 123),
    )

    checks = manager.doctor("demo")

    server = next(check for check in checks if check.name == "mcp-server")
    assert server.level == "error"
    assert "plugin 6.0.0" in server.detail
    assert "endpoint catalog is empty" in server.detail
