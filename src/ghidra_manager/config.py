"""Cross-platform configuration and managed-state paths."""

from __future__ import annotations

import json
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


def default_config_file(
    *,
    platform: str | None = None,
    environ: Mapping[str, str] | None = None,
    home: Path | None = None,
) -> Path:
    platform = platform or sys.platform
    environ = environ or os.environ
    home = home or Path.home()
    if platform == "win32":
        root = Path(environ.get("APPDATA", home / "AppData" / "Roaming"))
    elif platform == "darwin":
        root = home / "Library" / "Application Support"
    else:
        root = Path(environ.get("XDG_CONFIG_HOME", home / ".config"))
    return root / "ghidra-manager" / "config.json"


def _legacy_home(cwd: Path) -> Path | None:
    for candidate in (cwd.resolve(), *cwd.resolve().parents):
        managed = candidate / ".managed"
        old_harness = (candidate / "ghidra-manager.sh").is_file()
        python_checkout = (candidate / "pyproject.toml").is_file()
        if managed.is_dir() and (old_harness or python_checkout) and (managed / "current").exists():
            return managed
    return None


def _write_home_pointer(path: Path, manager_home: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(
        json.dumps({"schema_version": 1, "home": str(manager_home)}, indent=2) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


@dataclass(frozen=True, slots=True)
class ManagerPaths:
    """All runtime paths derived from one managed-state root."""

    home: Path

    @classmethod
    def discover(
        cls,
        *,
        cwd: Path | None = None,
        platform: str | None = None,
        environ: Mapping[str, str] | None = None,
        user_home: Path | None = None,
    ) -> ManagerPaths:
        environ = environ or os.environ
        override = environ.get("GHIDRA_MANAGER_HOME")
        if override:
            return cls(Path(override).expanduser().resolve())
        config_file = default_config_file(
            platform=platform, environ=environ, home=user_home
        )
        try:
            config: object = json.loads(config_file.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, ValueError):
            config = None
        if isinstance(config, dict) and isinstance(config.get("home"), str):
            return cls(Path(config["home"]).expanduser().resolve())
        legacy = _legacy_home(cwd or Path.cwd())
        if legacy is not None:
            _write_home_pointer(config_file, legacy)
            return cls(legacy)
        return cls(
            default_manager_home(platform=platform, environ=environ, home=user_home)
        )

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

    @property
    def python(self) -> Path:
        return self.home / "python"

    @property
    def uv_cache(self) -> Path:
        return self.home / "uv-cache"
