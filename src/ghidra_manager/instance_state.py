"""Persistent records for instances launched through verified manager workflows."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Any, Literal

from ghidra_manager.config import ManagerPaths
from ghidra_manager.errors import ManagerError
from ghidra_manager.storage import atomic_json

INSTANCE_STATE_VERSION = 1
InstanceHealth = Literal["ready", "mcp-unavailable", "stale"]


@dataclass(frozen=True, slots=True)
class ManagedInstanceRecord:
    pid: int
    launcher_pid: int
    port: int
    project: str
    project_path: str | None
    log_path: str
    ghidra_version: str
    started_at: int


@dataclass(frozen=True, slots=True)
class InstanceReport:
    pid: int
    port: int
    project: str
    programs: tuple[str, ...]
    url: str | None
    owned: bool
    health: InstanceHealth
    launcher_pid: int | None = None
    project_path: str | None = None
    log_path: str | None = None
    ghidra_version: str | None = None
    started_at: int | None = None

    def as_dict(self) -> dict[str, object]:
        value = asdict(self)
        value["programs"] = list(self.programs)
        return value


class InstanceStore:
    def __init__(self, paths: ManagerPaths):
        self.paths = paths

    def load(self) -> list[ManagedInstanceRecord]:
        if not self.paths.instances.is_file():
            return []
        try:
            raw: Any = json.loads(self.paths.instances.read_text(encoding="utf-8"))
            if raw.get("schema_version") != INSTANCE_STATE_VERSION:
                raise ManagerError("Unsupported managed instance state schema")
            records = [self._record(item) for item in raw["instances"]]
        except ManagerError:
            raise
        except (AttributeError, KeyError, OSError, TypeError, ValueError) as exc:
            raise ManagerError(f"Invalid managed instance state: {self.paths.instances}") from exc
        if len({record.pid for record in records}) != len(records):
            raise ManagerError(f"Duplicate PIDs in managed instance state: {self.paths.instances}")
        return sorted(records, key=lambda record: record.pid)

    def get(self, pid: int) -> ManagedInstanceRecord | None:
        return next((record for record in self.load() if record.pid == pid), None)

    def upsert(self, record: ManagedInstanceRecord) -> None:
        records = [item for item in self.load() if item.pid != record.pid]
        records.append(record)
        self._save(records)

    def remove(self, pid: int) -> None:
        records = self.load()
        retained = [record for record in records if record.pid != pid]
        if len(retained) != len(records):
            self._save(retained)

    def _save(self, records: list[ManagedInstanceRecord]) -> None:
        atomic_json(
            self.paths.instances,
            {
                "schema_version": INSTANCE_STATE_VERSION,
                "instances": [
                    asdict(record) for record in sorted(records, key=lambda item: item.pid)
                ],
            },
            mode=0o600,
        )

    @staticmethod
    def _record(raw: object) -> ManagedInstanceRecord:
        if not isinstance(raw, dict):
            raise ManagerError("Invalid managed instance record")
        record = ManagedInstanceRecord(
            pid=int(raw["pid"]),
            launcher_pid=int(raw["launcher_pid"]),
            port=int(raw["port"]),
            project=str(raw["project"]),
            project_path=str(raw["project_path"]) if raw.get("project_path") is not None else None,
            log_path=str(raw["log_path"]),
            ghidra_version=str(raw["ghidra_version"]),
            started_at=int(raw["started_at"]),
        )
        if record.pid <= 0 or record.launcher_pid <= 0 or record.port <= 0:
            raise ManagerError("Invalid managed instance process or port")
        if not record.project or not record.log_path or not record.ghidra_version:
            raise ManagerError("Incomplete managed instance record")
        return record
