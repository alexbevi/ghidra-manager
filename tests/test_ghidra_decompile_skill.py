from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

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


def initialize_campaign(root: Path, *, profile: str = "symbol-recovery") -> None:
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
        "--profile",
        profile,
    )
    assert result.returncode == 0, result.stderr


def test_initializer_seeds_analysis_fidelity_gate(tmp_path: Path) -> None:
    root = tmp_path / "campaign"
    initialize_campaign(root)

    project = json.loads((root / "project.json").read_text(encoding="utf-8"))
    progress = json.loads((root / "progress.json").read_text(encoding="utf-8"))
    tasks = json.loads((root / "tasks.json").read_text(encoding="utf-8"))

    assert project["schema_version"] == 2
    assert project["profile"] == "symbol-recovery"
    assert project["derived_programs"] == []
    assert progress["phase"] == "analysis-fidelity"
    assert progress["analysis_fidelity"]["status"] == "pending"
    assert (root / "artifacts").is_dir()
    assert (root / "traces").is_dir()
    assert (root / "behaviors.jsonl").is_file()
    assert (root / "coverage.jsonl").is_file()
    assert (root / "runtime.jsonl").is_file()
    assert (root / "resources.jsonl").is_file()
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


def test_initializer_records_reimplementation_profile(tmp_path: Path) -> None:
    root = tmp_path / "campaign"
    initialize_campaign(root, profile="reimplementation")

    project = json.loads((root / "project.json").read_text(encoding="utf-8"))
    tasks = json.loads((root / "tasks.json").read_text(encoding="utf-8"))
    assert project["profile"] == "reimplementation"
    assert "model-behavior-slices" in {task["id"] for task in tasks["tasks"]}
    assert "capture-runtime-evidence" in {task["id"] for task in tasks["tasks"]}
    assert "index-resource-graph" in {task["id"] for task in tasks["tasks"]}
    assert run_script(VALIDATE_SCRIPT, root).returncode == 0


def test_validator_checks_behavior_slice_contract(tmp_path: Path) -> None:
    root = tmp_path / "campaign"
    initialize_campaign(root, profile="reimplementation")
    behavior = {
        "id": "behavior-main-menu",
        "title": "Run the main menu",
        "program": "/GAME.EXE",
        "retail_roots": ["1234:0000"],
        "trigger": {
            "route": "Startup after initialization",
            "inputs": [],
            "preconditions": ["Resources loaded"],
        },
        "state_reads": ["menu state"],
        "state_writes": ["selected action"],
        "control_flow": ["Dispatch until exit"],
        "resources": ["MENU.DAT"],
        "timing_and_ownership": ["Menu owns input"],
        "side_effects": ["Persist selection"],
        "error_and_fallback_paths": ["Return failure on missing data"],
        "evidence_ids": ["ev-menu-001"],
        "confidence": "high",
        "verification": "static",
        "status": "evidenced",
        "unresolved": [],
        "source_task": "model-behavior-slices",
        "timestamp": "2026-01-01T00:00:00Z",
    }
    behavior_path = root / "behaviors.jsonl"
    behavior_path.write_text(json.dumps(behavior) + "\n", encoding="utf-8")
    assert run_script(VALIDATE_SCRIPT, root).returncode == 0

    behavior["status"] = "complete-looking"
    behavior_path.write_text(json.dumps(behavior) + "\n", encoding="utf-8")
    result = run_script(VALIDATE_SCRIPT, root)
    assert result.returncode == 1
    assert "invalid behavior status" in result.stderr


def test_validator_keeps_coverage_dimensions_separate(tmp_path: Path) -> None:
    root = tmp_path / "campaign"
    initialize_campaign(root, profile="reimplementation")
    coverage: dict[str, Any] = {
        "id": "coverage-main-menu",
        "behavior_id": "behavior-main-menu",
        "scope": {
            "retail_data": "retail-v1.0",
            "binary_digest": "sha256:" + "1" * 64,
            "target_revision": "abc123",
        },
        "shipped_data_reachability": {
            "status": "reachable",
            "evidence_ids": ["ev-data-001"],
        },
        "reusable_interpreter": {"status": "not_applicable", "evidence_ids": []},
        "implementation": {"status": "missing", "evidence_ids": []},
        "semantic_parity": {"status": "unknown", "evidence_ids": []},
        "review_state": "reviewed",
        "confidence": "high",
        "reviewed_by": "coordinator",
        "timestamp": "2026-01-01T00:00:00Z",
    }
    coverage_path = root / "coverage.jsonl"
    coverage_path.write_text(json.dumps(coverage) + "\n", encoding="utf-8")
    assert run_script(VALIDATE_SCRIPT, root).returncode == 0

    coverage["semantic_parity"]["status"] = "looks-good"
    coverage_path.write_text(json.dumps(coverage) + "\n", encoding="utf-8")
    result = run_script(VALIDATE_SCRIPT, root)
    assert result.returncode == 1
    assert "invalid semantic_parity status" in result.stderr


def test_validator_requires_target_for_runtime_match(tmp_path: Path) -> None:
    root = tmp_path / "campaign"
    initialize_campaign(root, profile="reimplementation")
    runtime: dict[str, Any] = {
        "id": "runtime-main-menu-001",
        "behavior_id": "behavior-main-menu",
        "route": {
            "steps": ["Start the executable", "Enter the main menu"],
            "inputs": [],
            "preconditions": ["Retail data installed"],
        },
        "retail": {
            "environment": "emulator",
            "revision": "sha256:" + "1" * 64,
            "observations": ["Menu owns input"],
            "artifacts": ["traces/menu-retail.log"],
        },
        "target": None,
        "comparison": {
            "status": "retail-observed",
            "matched": [],
            "differences": [],
            "not_observed": ["Target implementation"],
        },
        "evidence_ids": ["ev-runtime-001"],
        "review_state": "reviewed",
        "timestamp": "2026-01-01T00:00:00Z",
    }
    runtime_path = root / "runtime.jsonl"
    runtime_path.write_text(json.dumps(runtime) + "\n", encoding="utf-8")
    assert run_script(VALIDATE_SCRIPT, root).returncode == 0

    runtime["comparison"]["status"] = "matched"
    runtime_path.write_text(json.dumps(runtime) + "\n", encoding="utf-8")
    result = run_script(VALIDATE_SCRIPT, root)
    assert result.returncode == 1
    assert "matched comparison requires a target observation" in result.stderr


def test_validator_requires_program_root_for_traced_resource(tmp_path: Path) -> None:
    root = tmp_path / "campaign"
    initialize_campaign(root, profile="reimplementation")
    resource: dict[str, Any] = {
        "id": "resource-prologue",
        "data_set": "retail-v1.0",
        "canonical_id": "PROLOGUE.RUN",
        "kind": "compiled-scene-script",
        "container": "SCRIPT.PL",
        "member": "PROLOGUE.RUN",
        "digest": "sha256:" + "1" * 64,
        "dispatch_values": ["callback-opcode:0x24"],
        "parser_roots": ["1234:0000"],
        "dispatcher_roots": [],
        "consumer_roots": [],
        "reachability": {"status": "reachable", "route": "Prologue scene"},
        "evidence_ids": ["ev-resource-001"],
        "status": "traced",
        "source_task": "index-resource-graph",
        "timestamp": "2026-01-01T00:00:00Z",
    }
    resource_path = root / "resources.jsonl"
    resource_path.write_text(json.dumps(resource) + "\n", encoding="utf-8")
    assert run_script(VALIDATE_SCRIPT, root).returncode == 0

    resource["parser_roots"] = []
    resource_path.write_text(json.dumps(resource) + "\n", encoding="utf-8")
    result = run_script(VALIDATE_SCRIPT, root)
    assert result.returncode == 1
    assert "traced resource requires a program root" in result.stderr
