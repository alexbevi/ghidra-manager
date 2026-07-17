"""Cross-platform managed-process inspection."""

from __future__ import annotations

from pathlib import Path

import psutil


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
