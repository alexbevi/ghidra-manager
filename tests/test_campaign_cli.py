import json
from pathlib import Path

import pytest

from ghidra_manager.cli import run
from ghidra_manager.errors import ManagerError


def initialize(root: Path) -> None:
    assert run(["campaign", "--state", str(root), "init", "--project", "fixture",
                "--program", "fixture.exe", "--program-path", "/fixture.exe"]) == 0


def test_lifecycle_and_deterministic_report(tmp_path, capsys):
    root = tmp_path / "campaign"
    initialize(root)
    capsys.readouterr()
    assert run(["campaign", "--state", str(root), "--json", "status"]) == 0
    assert json.loads(capsys.readouterr().out)["identity"]["program_path"] == "/fixture.exe"
    run(["campaign", "--state", str(root), "report"])
    first = capsys.readouterr().out
    run(["campaign", "--state", str(root), "report"])
    assert capsys.readouterr().out == first
    before = (root / "project.json").read_bytes()
    with pytest.raises(SystemExit, match="refusing to overwrite"):
        initialize(root)
    assert (root / "project.json").read_bytes() == before


def test_missing_campaign_does_not_initialize(tmp_path):
    root = tmp_path / "missing"
    with pytest.raises(ManagerError):
        run(["campaign", "--state", str(root), "status"])
    assert not root.exists()
