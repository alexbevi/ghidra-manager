from pathlib import Path
from types import SimpleNamespace

from ghidra_manager.platforms import run_headless_fixture


def test_headless_fixture_windows_uses_platform_adapter(tmp_path, monkeypatch):
    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr("ghidra_manager.platforms.subprocess.run", run)
    assert (
        run_headless_fixture(
            Path("C:/Ghidra"),
            ["C:/temporary fixture", "fixture"],
            Path("C:/Java"),
            tmp_path / "log",
            platform="win32",
        )
        == 0
    )
    command, options = calls[0]
    assert command[-1].endswith('"C:/temporary fixture" fixture')
    assert "analyzeHeadless.bat" in command[-1]
    assert options["timeout"] == 180
    assert options["env"]["JAVA_HOME"] == "C:/Java"
