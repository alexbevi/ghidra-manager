"""Operating-system-specific Ghidra paths and runtime behavior."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path

from ghidra_manager.errors import ManagerError


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


def _java_major(java_home: Path) -> int | None:
    executable = java_home / "bin" / ("java.exe" if sys.platform == "win32" else "java")
    if not executable.is_file():
        return None
    try:
        result = subprocess.run(
            [str(executable), "-version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except OSError:
        return None
    match = re.search(r'version "([0-9]+)', result.stdout + result.stderr)
    return int(match.group(1)) if match else None


def find_java21(
    *,
    platform: str | None = None,
    environ: Mapping[str, str] | None = None,
) -> Path:
    platform = platform or sys.platform
    environ = environ or os.environ
    candidates: list[Path] = []
    if environ.get("JAVA_HOME"):
        candidates.append(Path(environ["JAVA_HOME"]))
    if platform == "darwin":
        java_home_tool = Path("/usr/libexec/java_home")
        if java_home_tool.is_file():
            result = subprocess.run(
                [str(java_home_tool), "-v", "21"],
                check=False,
                capture_output=True,
                text=True,
            )
            if result.returncode == 0 and result.stdout.strip():
                candidates.append(Path(result.stdout.strip()))
    executable = shutil.which(
        "java.exe" if platform == "win32" else "java", path=environ.get("PATH")
    )
    if executable:
        candidates.append(Path(executable).resolve().parent.parent)
    if platform == "darwin":
        brew = shutil.which("brew", path=environ.get("PATH"))
        if brew:
            result = subprocess.run(
                [brew, "--prefix", "openjdk@21"],
                check=False,
                capture_output=True,
                text=True,
            )
            if result.returncode == 0 and result.stdout.strip():
                candidates.append(Path(result.stdout.strip()))
    for candidate in candidates:
        if _java_major(candidate) == 21:
            return candidate
    raise ManagerError(
        "JDK 21 not found. Set JAVA_HOME or place a Java 21 executable on PATH."
    )


def run_ghidra(
    install: Path,
    arguments: list[str],
    java_home: Path,
    *,
    platform: str | None = None,
) -> int:
    platform = platform or sys.platform
    environment = os.environ.copy()
    environment["JAVA_HOME"] = str(java_home)
    environment["PATH"] = str(java_home / "bin") + os.pathsep + environment.get("PATH", "")
    if platform == "win32":
        launcher = install / "ghidraRun.bat"
        if not launcher.is_file():
            raise ManagerError("Active Ghidra launcher is missing. Run sync to repair it.")
        command_line = subprocess.list2cmdline([str(launcher), *arguments])
        command = [environment.get("COMSPEC", "cmd.exe"), "/d", "/s", "/c", command_line]
    else:
        launcher = install / "ghidraRun"
        if not launcher.is_file():
            raise ManagerError("Active Ghidra launcher is missing. Run sync to repair it.")
        command = [str(launcher), *arguments]
    try:
        return subprocess.run(command, check=False, env=environment).returncode
    except OSError as exc:
        raise ManagerError(f"Failed to launch Ghidra: {exc}") from exc


def start_ghidra_instance(
    install: Path,
    project: Path | None,
    java_home: Path,
    log_path: Path,
    *,
    platform: str | None = None,
) -> subprocess.Popen[bytes]:
    platform = platform or sys.platform
    environment = os.environ.copy()
    environment["JAVA_HOME"] = str(java_home)
    environment["PATH"] = str(java_home / "bin") + os.pathsep + environment.get("PATH", "")
    arguments = ["fg", "jdk", "Ghidra", "", "  ", "ghidra.GhidraRun"]
    if project is not None:
        arguments.append(str(project))
    log_path.parent.mkdir(parents=True, exist_ok=True)
    if platform == "win32":
        launcher = install / "support" / "launch.bat"
        command_line = subprocess.list2cmdline([str(launcher), *arguments])
        command = [environment.get("COMSPEC", "cmd.exe"), "/d", "/s", "/c", command_line]
        creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) | getattr(
            subprocess, "DETACHED_PROCESS", 0
        )
        start_new_session = False
    else:
        launcher = install / "support" / "launch.sh"
        command = [str(launcher), *arguments]
        creationflags = 0
        start_new_session = True
    if not launcher.is_file():
        raise ManagerError("Active Ghidra launcher is missing. Run sync to repair it.")
    try:
        with log_path.open("wb") as log:
            return subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                env=environment,
                creationflags=creationflags,
                start_new_session=start_new_session,
            )
    except OSError as exc:
        raise ManagerError(f"Failed to launch Ghidra instance: {exc}") from exc
