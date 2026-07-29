from pathlib import Path

import psutil
import pytest

from ghidra_manager import processes
from ghidra_manager.errors import ManagerError


class FakeProcess:
    def __init__(self, command: list[str], *, time_out_once: bool = False) -> None:
        self.command = command
        self.time_out_once = time_out_once
        self.terminated = False
        self.killed = False

    def cmdline(self) -> list[str]:
        return self.command

    def terminate(self) -> None:
        self.terminated = True

    def kill(self) -> None:
        self.killed = True

    def wait(self, timeout: int) -> int:
        if self.time_out_once:
            self.time_out_once = False
            raise psutil.TimeoutExpired(timeout)
        return 0


def test_stop_rejects_process_outside_managed_install(monkeypatch, tmp_path: Path) -> None:
    process = FakeProcess(["java", "-Dapplication.name=ghidra.Ghidra", "/other/Ghidra"])
    monkeypatch.setattr(processes.psutil, "Process", lambda _: process)

    with pytest.raises(ManagerError, match="Refusing to stop PID 42"):
        processes.stop_managed_ghidra(42, tmp_path / "managed/Ghidra")

    assert not process.terminated


def test_stop_escalates_only_when_force_is_enabled(monkeypatch, tmp_path: Path) -> None:
    install = tmp_path / "managed/Ghidra"
    process = FakeProcess(
        ["java", "-Dapplication.name=ghidra.Ghidra", str(install / "support")],
        time_out_once=True,
    )
    monkeypatch.setattr(processes.psutil, "Process", lambda _: process)

    processes.stop_managed_ghidra(42, install, timeout=3, force=True)

    assert process.terminated
    assert process.killed


def test_stop_timeout_requires_explicit_force(monkeypatch, tmp_path: Path) -> None:
    install = tmp_path / "managed/Ghidra"
    process = FakeProcess(
        ["java", "-Dapplication.name=ghidra.Ghidra", str(install / "support")],
        time_out_once=True,
    )
    monkeypatch.setattr(processes.psutil, "Process", lambda _: process)

    with pytest.raises(ManagerError, match="rerun with --force"):
        processes.stop_managed_ghidra(42, install, timeout=3)

    assert process.terminated
    assert not process.killed
