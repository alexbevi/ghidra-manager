"""Cross-platform managed-process inspection."""

from __future__ import annotations

from pathlib import Path

import psutil

from ghidra_manager.errors import ManagerError


def managed_ghidra_running(components: Path) -> bool:
    marker = str(components.resolve()).casefold()
    for process in psutil.process_iter(["cmdline"]):
        try:
            command = " ".join(process.info.get("cmdline") or []).casefold()
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
            continue
        if marker in command and ("ghidra.ghidra" in command or "ghidrarun" in command):
            return True
    return False


def managed_ghidra_process(pid: int, install: Path) -> bool:
    """Return whether PID belongs to Ghidra under the exact managed install."""
    try:
        process = psutil.Process(pid)
        command = " ".join(process.cmdline()).casefold()
    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
        return False
    marker = str(install.resolve()).casefold()
    return marker in command and ("ghidra.ghidra" in command or "ghidrarun" in command)


def stop_managed_ghidra(
    pid: int,
    install: Path,
    *,
    timeout: int = 10,
    force: bool = False,
) -> None:
    """Stop one verified managed Ghidra process, optionally escalating to kill."""
    if timeout <= 0:
        raise ManagerError("Stop timeout must be a positive integer")
    if not managed_ghidra_process(pid, install):
        raise ManagerError(
            f"Refusing to stop PID {pid}: it is not part of the active managed Ghidra install"
        )
    try:
        process = psutil.Process(pid)
        process.terminate()
        process.wait(timeout=timeout)
    except psutil.NoSuchProcess:
        return
    except psutil.TimeoutExpired as exc:
        if not force:
            raise ManagerError(
                f"Ghidra PID {pid} did not stop within {timeout} seconds; "
                "rerun with --force to kill it"
            ) from exc
        try:
            process.kill()
            process.wait(timeout=timeout)
        except psutil.NoSuchProcess:
            return
        except psutil.TimeoutExpired as kill_exc:
            raise ManagerError(f"Ghidra PID {pid} did not exit after it was killed") from kill_exc
