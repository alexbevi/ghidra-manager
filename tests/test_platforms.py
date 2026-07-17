import stat
from pathlib import Path

import pytest

from ghidra_manager.errors import ManagerError
from ghidra_manager.platforms import (
    find_java21,
    ghidra_settings_dir,
    run_ghidra,
    start_ghidra_instance,
)


def test_ghidra_settings_paths() -> None:
    assert ghidra_settings_dir(
        "12.1.2", "PUBLIC", platform="darwin", environ={}, home=Path("/Users/tester")
    ) == Path("/Users/tester/Library/ghidra/ghidra_12.1.2_PUBLIC")
    assert ghidra_settings_dir(
        "12.1.2", "PUBLIC", platform="linux", environ={}, home=Path("/home/tester")
    ) == Path("/home/tester/.config/ghidra/ghidra_12.1.2_PUBLIC")
    assert ghidra_settings_dir(
        "12.1.2",
        "PUBLIC",
        platform="win32",
        environ={"APPDATA": r"C:\Users\tester\AppData\Roaming"},
        home=Path("/unused"),
    ) == Path(r"C:\Users\tester\AppData\Roaming") / "ghidra/ghidra_12.1.2_PUBLIC"


def test_find_java21_from_java_home(monkeypatch, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    java_home = tmp_path / "jdk"
    java = java_home / "bin/java"
    java.parent.mkdir(parents=True)
    java.write_text("#!/bin/sh\necho 'openjdk version \"21.0.1\"' >&2\n", encoding="utf-8")
    java.chmod(java.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setattr("ghidra_manager.platforms.sys.platform", "linux")

    assert (
        find_java21(platform="linux", environ={"JAVA_HOME": str(java_home), "PATH": ""})
        == java_home
    )


def test_missing_java21_is_actionable(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr("ghidra_manager.platforms.shutil.which", lambda *_args, **_kwargs: None)

    with pytest.raises(ManagerError, match="Set JAVA_HOME"):
        find_java21(platform="linux", environ={"PATH": ""})


def test_unix_launcher_receives_arguments(tmp_path: Path) -> None:
    install = tmp_path / "ghidra"
    launcher = install / "ghidraRun"
    output = tmp_path / "arguments"
    install.mkdir()
    launcher.write_text(f"#!/bin/sh\nprintf '%s' \"$*\" > '{output}'\n", encoding="utf-8")
    launcher.chmod(launcher.stat().st_mode | stat.S_IXUSR)

    assert run_ghidra(install, ["project.gpr", "--flag"], tmp_path, platform="linux") == 0
    assert output.read_text(encoding="utf-8") == "project.gpr --flag"


def test_detached_unix_launcher_uses_foreground_mode(tmp_path: Path) -> None:
    install = tmp_path / "ghidra"
    launcher = install / "support/launch.sh"
    project = tmp_path / "demo.gpr"
    output = tmp_path / "arguments"
    log = tmp_path / "launch.log"
    launcher.parent.mkdir(parents=True)
    launcher.write_text(f"#!/bin/sh\nprintf '%s' \"$*\" > '{output}'\n", encoding="utf-8")
    launcher.chmod(launcher.stat().st_mode | stat.S_IXUSR)
    project.write_text("", encoding="utf-8")

    process = start_ghidra_instance(install, project, tmp_path, log, platform="linux")
    assert process.wait(timeout=5) == 0
    assert output.read_text(encoding="utf-8") == (
        f"fg jdk Ghidra     ghidra.GhidraRun {project}"
    )
