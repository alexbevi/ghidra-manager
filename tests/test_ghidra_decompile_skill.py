from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

SKILL_ROOT = Path(__file__).parents[1] / "skills" / "ghidra-decompile"
INIT_SCRIPT = SKILL_ROOT / "scripts" / "init_project.py"
VALIDATE_SCRIPT = SKILL_ROOT / "scripts" / "validate_project.py"


def run_script(script: Path, *args: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(script), *(str(arg) for arg in args)],
        check=False,
        capture_output=True,
        text=True,
    )


def initialize_campaign(root: Path) -> None:
    result = run_script(
        INIT_SCRIPT,
        "--output",
        root,
        "--project",
        "test-project",
        "--program",
        "GAME.EXE",
        "--program-path",
        "/GAME.EXE",
    )
    assert result.returncode == 0, result.stderr


def test_initializer_seeds_analysis_fidelity_gate(tmp_path: Path) -> None:
    root = tmp_path / "campaign"
    initialize_campaign(root)

    project = json.loads((root / "project.json").read_text(encoding="utf-8"))
    progress = json.loads((root / "progress.json").read_text(encoding="utf-8"))
    tasks = json.loads((root / "tasks.json").read_text(encoding="utf-8"))

    assert project["schema_version"] == 2
    assert project["derived_programs"] == []
    assert progress["phase"] == "analysis-fidelity"
    assert progress["analysis_fidelity"]["status"] == "pending"
    assert (root / "artifacts").is_dir()
    task_by_id = {task["id"]: task for task in tasks["tasks"]}
    assert task_by_id["index-entry-graph"]["depends_on"] == [
        "assess-analysis-fidelity"
    ]
    assert run_script(VALIDATE_SCRIPT, root).returncode == 0


def test_validator_checks_derived_program_provenance(tmp_path: Path) -> None:
    root = tmp_path / "campaign"
    initialize_campaign(root)
    project_path = root / "project.json"
    project = json.loads(project_path.read_text(encoding="utf-8"))
    project["derived_programs"] = [
        {
            "id": "overlay-image-1",
            "role": "overlay-aware-analysis",
            "source_digest": "sha256:" + "1" * 64,
            "digest": "sha256:" + "2" * 64,
            "path": "artifacts/game-overlays.exe",
            "ghidra_program_path": "/GAME_OVERLAYS.EXE",
            "size": 1234,
            "format": "Old-style DOS Executable (MZ)",
            "language": "x86:LE:16:Real Mode",
            "image_base": "0000:0000",
            "transform": {
                "tool": "overlay-flattener",
                "source_commit": "a" * 40,
                "arguments": ["--map-overlays"],
            },
            "address_mapping": {"kind": "segment-preserving"},
            "validation": {"functions_total": 120},
        }
    ]
    project_path.write_text(json.dumps(project, indent=2) + "\n", encoding="utf-8")

    assert run_script(VALIDATE_SCRIPT, root).returncode == 0

    project["derived_programs"][0]["digest"] = "not-a-digest"
    project_path.write_text(json.dumps(project, indent=2) + "\n", encoding="utf-8")
    result = run_script(VALIDATE_SCRIPT, root)
    assert result.returncode == 1
    assert "digest must be sha256:<64 lowercase hex>" in result.stderr
