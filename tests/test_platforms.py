from pathlib import Path

from ghidra_manager.platforms import ghidra_settings_dir


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
