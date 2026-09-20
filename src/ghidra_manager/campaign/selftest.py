"""Isolated live tests of packaged Ghidra collectors and transactions."""

from __future__ import annotations

from importlib.resources import files
from pathlib import Path
from shutil import copy2
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
        fixture.write_bytes(b"\x50\xc3\xc3\xc3\xc3")
        code = run_headless_fixture(
            paths.ghidra / pair.ghidra_version,
            [
                temporary,
                "fixture",
                "-import",
                str(fixture),
                "-loader",
                "BinaryLoader",
                "-loader-baseAddr",
                "0x1000",
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
                "dynamic-global",
                "-postScript",
                "CampaignFixture.java",
                temporary,
                "layout-failure",
                "-postScript",
                "CampaignFixture.java",
                temporary,
                "layout-verify",
                "-postScript",
                "CampaignFixture.java",
                temporary,
                "repair-trial",
                "-postScript",
                "CampaignFixture.java",
                temporary,
                "repair-verify",
                "-postScript",
                "CampaignFixture.java",
                temporary,
                "repair-apply",
                "-postScript",
                "CampaignFixture.java",
                temporary,
                "repair-stable",
                "-postScript",
                "CampaignFixture.java",
                temporary,
                "abi",
                "-deleteProject",
            ],
            find_java21(),
            log,
        )
        for artifact in Path(temporary).glob("*.json"):
            copy2(artifact, directory / artifact.name)
    passed = code == 0 and all(
        marker in log.read_text(errors="replace")
        for marker in [
            "CAMPAIGN_FIXTURE_PASS",
            "CAMPAIGN_DYNAMIC_GLOBAL_PASS",
            "CAMPAIGN_LAYOUT_PASS",
            "CAMPAIGN_ABI_PASS",
            "CAMPAIGN_REPAIR_TRIAL_PASS",
            "CAMPAIGN_REPAIR_CAPTURE_PASS",
            "CAMPAIGN_REPAIR_ASYNC_PASS",
            "CAMPAIGN_REPAIR_APPLIED",
            "CAMPAIGN_REPAIR_STABLE_PASS",
        ]
    )
    if not passed:
        raise ManagerError(f"Campaign fixture failed; inspect {log}")
    from ghidra_manager.campaign.inventory import read
    from ghidra_manager.campaign.repairs import readback

    readback(
        read(directory / "repair-args.json")["plan"],
        read(directory / "before-repair.json"),
        read(directory / "trial-snapshot.json"),
    )
    return {"passed": True, "log": str(log), "retail_program_modified": False}
