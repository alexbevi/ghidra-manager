"""Isolated live tests of packaged Ghidra collectors and transactions."""

from __future__ import annotations

from importlib.resources import files
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from ghidra_manager.config import ManagerPaths
from ghidra_manager.errors import ManagerError
from ghidra_manager.platforms import find_java21, run_headless_fixture
from ghidra_manager.storage import StateStore


def run(root: Path) -> dict[str, Any]:
    paths = ManagerPaths.discover()
    store = StateStore(paths)
    state = store.load()
    if state.current is None:
        raise ManagerError("A managed Ghidra installation is required for fixture tests")
    pair = store.pair(state.current)
    directory = root / "artifacts" / "selftest"
    directory.mkdir(parents=True, exist_ok=True)
    log = directory / "headless.log"
    with TemporaryDirectory(prefix="ghidra-manager-fixture-") as temporary:
        fixture = Path(temporary) / "fixture.bin"
        fixture.write_bytes(b"\xc3\xc3")
        code = run_headless_fixture(
            paths.ghidra / pair.ghidra_version,
            [
                temporary,
                "fixture",
                "-import",
                str(fixture),
                "-loader",
                "BinaryLoader",
                "-processor",
                "x86:LE:32:default",
                "-cspec",
                "windows",
                "-noanalysis",
                "-scriptPath",
                str(files("ghidra_manager.campaign")),
                "-postScript",
                "CampaignFixture.java",
                temporary,
                "prepare",
                "-postScript",
                "CampaignFixture.java",
                temporary,
                "failure",
                "-postScript",
                "CampaignFixture.java",
                temporary,
                "verify",
                "-postScript",
                "CampaignFixture.java",
                temporary,
                "layout-failure",
                "-postScript",
                "CampaignFixture.java",
                temporary,
                "layout-verify",
                "-deleteProject",
            ],
            find_java21(),
            log,
        )
    passed = code == 0 and all(
        marker in log.read_text(errors="replace")
        for marker in ["CAMPAIGN_FIXTURE_PASS", "CAMPAIGN_LAYOUT_PASS"]
    )
    if not passed:
        raise ManagerError(f"Campaign fixture failed; inspect {log}")
    return {"passed": True, "log": str(log), "retail_program_modified": False}
