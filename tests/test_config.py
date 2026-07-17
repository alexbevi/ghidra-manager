from pathlib import Path

from ghidra_manager.config import default_manager_home


def test_explicit_manager_home_wins() -> None:
    result = default_manager_home(
        platform="linux",
        environ={"GHIDRA_MANAGER_HOME": "~/custom"},
        home=Path("/home/tester"),
    )

    assert result == Path("~/custom").expanduser().resolve()


def test_platform_defaults() -> None:
    assert default_manager_home(
        platform="win32",
        environ={"LOCALAPPDATA": r"C:\Users\tester\AppData\Local"},
        home=Path("/unused"),
    ) == Path(r"C:\Users\tester\AppData\Local") / "ghidra-manager"
    assert default_manager_home(
        platform="darwin", environ={}, home=Path("/Users/tester")
    ) == Path("/Users/tester/Library/Application Support/ghidra-manager")
    assert default_manager_home(
        platform="linux", environ={}, home=Path("/home/tester")
    ) == Path("/home/tester/.local/share/ghidra-manager")
    assert default_manager_home(
        platform="linux", environ={"XDG_DATA_HOME": "/data"}, home=Path("/home/tester")
    ) == Path("/data/ghidra-manager")
