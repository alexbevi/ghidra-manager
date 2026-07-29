import json
from dataclasses import replace
from pathlib import Path

import pytest

from ghidra_manager.config import ManagerPaths
from ghidra_manager.errors import ManagerError
from ghidra_manager.instance_state import InstanceStore, ManagedInstanceRecord


def _record(pid: int = 20) -> ManagedInstanceRecord:
    return ManagedInstanceRecord(
        pid=pid,
        launcher_pid=10,
        port=8089,
        project="demo",
        project_path="/projects/demo.gpr",
        log_path="/logs/demo.log",
        ghidra_version="12.1.2",
        started_at=1234,
    )


def test_instance_store_round_trip_is_sorted_and_private(tmp_path: Path) -> None:
    paths = ManagerPaths(tmp_path)
    store = InstanceStore(paths)

    store.upsert(_record(30))
    store.upsert(_record(20))

    assert [record.pid for record in store.load()] == [20, 30]
    assert json.loads(paths.instances.read_text(encoding="utf-8"))["schema_version"] == 1
    assert paths.instances.stat().st_mode & 0o777 == 0o600


def test_instance_store_upserts_and_removes_by_pid(tmp_path: Path) -> None:
    store = InstanceStore(ManagerPaths(tmp_path))
    store.upsert(_record())
    changed = replace(_record(), port=9000)
    store.upsert(changed)

    assert store.load() == [changed]
    store.remove(20)
    assert store.load() == []


def test_instance_store_rejects_unknown_schema(tmp_path: Path) -> None:
    paths = ManagerPaths(tmp_path)
    paths.instances.write_text('{"schema_version":2,"instances":[]}', encoding="utf-8")

    with pytest.raises(ManagerError, match="Unsupported managed instance state schema"):
        InstanceStore(paths).load()
