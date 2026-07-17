"""Operating-system-specific Ghidra paths and runtime behavior."""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping
from pathlib import Path


def ghidra_settings_dir(
    version: str,
    release_name: str,
    *,
    platform: str | None = None,
    environ: Mapping[str, str] | None = None,
    home: Path | None = None,
) -> Path:
    platform = platform or sys.platform
    environ = environ or os.environ
    home = home or Path.home()
    directory = f"ghidra_{version}_{release_name}"
    if platform == "win32":
        root = Path(environ.get("APPDATA", home / "AppData" / "Roaming"))
    elif platform == "darwin":
        root = home / "Library"
    else:
        root = Path(environ.get("XDG_CONFIG_HOME", home / ".config"))
    return root / "ghidra" / directory
