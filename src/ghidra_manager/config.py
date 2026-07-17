"""Cross-platform configuration and managed-state paths."""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path


def default_manager_home(
    *,
    platform: str | None = None,
    environ: Mapping[str, str] | None = None,
    home: Path | None = None,
) -> Path:
    """Return the platform-native location for large managed payloads."""
    platform = platform or sys.platform
    environ = environ or os.environ
    home = home or Path.home()

    override = environ.get("GHIDRA_MANAGER_HOME")
    if override:
        return Path(override).expanduser().resolve()
    if platform == "win32":
        local_app_data = environ.get("LOCALAPPDATA")
        if local_app_data:
            return Path(local_app_data) / "ghidra-manager"
        return home / "ghidra-manager"
    if platform == "darwin":
        return home / "Library" / "Application Support" / "ghidra-manager"
    data_home = environ.get("XDG_DATA_HOME")
    if data_home:
        return Path(data_home) / "ghidra-manager"
    return home / ".local" / "share" / "ghidra-manager"


@dataclass(frozen=True, slots=True)
class ManagerPaths:
    """All runtime paths derived from one managed-state root."""

    home: Path

    @classmethod
    def discover(cls) -> ManagerPaths:
        return cls(default_manager_home())

    @property
    def ghidra(self) -> Path:
        return self.home / "ghidra"

    @property
    def mcp(self) -> Path:
        return self.home / "ghidra-mcp"

    @property
    def pairs(self) -> Path:
        return self.home / "pairs"

    @property
    def state(self) -> Path:
        return self.home / "state.json"
