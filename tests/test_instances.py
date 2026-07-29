from pathlib import Path

from ghidra_manager.config import ManagerPaths
from ghidra_manager.instance_state import InstanceStore, ManagedInstanceRecord
from ghidra_manager.manager import Manager
from ghidra_manager.mcp import Instance
from ghidra_manager.models import ManagerState
from ghidra_manager.storage import StateStore
from tests.plugin_fixtures import managed_pair
from tests.test_manager_sync import SyncClient


def _record(pid: int, project: str, version: str = "12.1.2") -> ManagedInstanceRecord:
    return ManagedInstanceRecord(
        pid=pid,
        launcher_pid=pid - 1,
        port=8089 + pid,
        project=project,
        project_path=f"/projects/{project}.gpr",
        log_path=f"/logs/{project}.log",
        ghidra_version=version,
        started_at=pid,
    )


def test_instance_reports_merge_live_endpoints_and_retained_records(
    monkeypatch, tmp_path: Path
) -> None:
    paths = ManagerPaths(tmp_path / "managed")
    state = StateStore(paths)
    state.save_pair(managed_pair())
    state.save(ManagerState(current="pair"))
    records = InstanceStore(paths)
    records.upsert(_record(20, "managed"))
    records.upsert(_record(30, "no-mcp"))
    records.upsert(_record(40, "stale"))
    live = [
        Instance(8089, 20, "managed", ("GAME.EXE",)),
        Instance(8090, 50, "external", ("OTHER.EXE",)),
    ]
    manager = Manager(paths, SyncClient(), instance_discovery=lambda _: live)
    monkeypatch.setattr(
        "ghidra_manager.manager.managed_ghidra_process",
        lambda pid, _install: pid in {20, 30},
    )

    reports = manager.instance_reports()

    by_pid = {report.pid: report for report in reports}
    assert by_pid[20].owned is True
    assert by_pid[20].health == "ready"
    assert by_pid[20].programs == ("GAME.EXE",)
    assert by_pid[30].health == "mcp-unavailable"
    assert by_pid[30].url is None
    assert by_pid[40].health == "stale"
    assert by_pid[50].owned is False
    assert by_pid[50].log_path is None


def test_live_pid_reuse_does_not_inherit_ownership(monkeypatch, tmp_path: Path) -> None:
    paths = ManagerPaths(tmp_path / "managed")
    state = StateStore(paths)
    state.save_pair(managed_pair())
    state.save(ManagerState(current="pair"))
    InstanceStore(paths).upsert(_record(20, "old-project"))
    manager = Manager(
        paths,
        SyncClient(),
        instance_discovery=lambda _: [Instance(8089, 20, "new-project")],
    )
    monkeypatch.setattr("ghidra_manager.manager.managed_ghidra_process", lambda *_: True)

    report = manager.instance_reports()[0]

    assert report.project == "new-project"
    assert report.owned is False
    assert report.log_path is None
