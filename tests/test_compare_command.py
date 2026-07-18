from pathlib import Path

from ghidra_manager.config import ManagerPaths
from ghidra_manager.manager import Manager
from ghidra_manager.mcp import Instance
from ghidra_manager.models import ManagerState
from ghidra_manager.storage import StateStore
from tests.plugin_fixtures import managed_pair
from tests.test_manager_sync import SyncClient


def _manager(tmp_path: Path) -> Manager:
    paths = ManagerPaths(tmp_path / "managed")
    store = StateStore(paths)
    store.save_pair(managed_pair(ghidra_tag="ghidra"))
    store.save(ManagerState(current="pair"))
    return Manager(
        paths,
        SyncClient(),
        instance_discovery=lambda _: [
            Instance(8089, 10, "source"),
            Instance(8090, 11, "target"),
        ],
    )


def test_compare_dispatches_packaged_engine(monkeypatch, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    manager = _manager(tmp_path)
    captured: list[str] = []

    def main(arguments):  # type: ignore[no-untyped-def]
        captured.extend(arguments)
        return 0

    monkeypatch.setattr("ghidra_manager.manager.compare_engine.main", main)

    assert manager.compare("source", "target") == 0
    assert captured == [
        "generate",
        str(manager.paths.home),
        "1",
        "10",
        "source",
        "8089",
        "10",
        "target",
        "8090",
        "11",
    ]


def test_compare_apply_dispatches_existing_plan(monkeypatch, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    manager = _manager(tmp_path)
    captured: list[str] = []
    monkeypatch.setattr(
        "ghidra_manager.manager.compare_engine.main",
        lambda arguments: captured.extend(arguments) or 0,
    )
    plan = tmp_path / "plan.json"

    assert manager.compare_apply(plan) == 0
    assert captured == ["apply", str(manager.paths.home), "1", "10", str(plan)]
