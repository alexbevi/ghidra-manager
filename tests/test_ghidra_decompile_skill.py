from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

SKILL_ROOT = Path(__file__).parents[1] / "skills" / "ghidra-decompile"
INIT_SCRIPT = SKILL_ROOT / "scripts" / "init_project.py"
VALIDATE_SCRIPT = SKILL_ROOT / "scripts" / "validate_project.py"
REPORT_SCRIPT = SKILL_ROOT / "scripts" / "report_project.py"


def test_skill_local_reference_links_resolve() -> None:
    skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
    local_links = re.findall(r"\]\((references/[^)#]+\.md)\)", skill)

    assert local_links
    assert all((SKILL_ROOT / link).is_file() for link in local_links)


def run_script(script: Path, *args: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(script), *(str(arg) for arg in args)],
        check=False,
        capture_output=True,
        text=True,
    )


def initialize_campaign(
    root: Path,
    *,
    profile: str = "symbol-recovery",
    target: str | None = None,
) -> None:
    target_args = ["--target", target] if target is not None else []
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
        *target_args,
    )
    assert result.returncode == 0, result.stderr


def append_jsonl(path: Path, record: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record) + "\n")


def add_evidence(root: Path, evidence_id: str) -> None:
    append_jsonl(
        root / "evidence.jsonl",
        {
            "id": evidence_id,
            "category": "control-flow",
            "addresses": ["1234:0000"],
            "claim": "Test evidence",
        },
    )


def add_behavior(root: Path, behavior_id: str = "behavior-main-menu") -> None:
    append_jsonl(
        root / "behaviors.jsonl",
        {
            "id": behavior_id,
            "title": "Run the main menu",
            "program": "/GAME.EXE",
            "retail_roots": ["1234:0000"],
            "trigger": {"route": "Startup", "inputs": [], "preconditions": []},
            "state_reads": [],
            "state_writes": [],
            "control_flow": ["Dispatch until exit"],
            "resources": [],
            "timing_and_ownership": [],
            "side_effects": [],
            "error_and_fallback_paths": [],
            "evidence_ids": [],
            "confidence": "medium",
            "verification": "static",
            "status": "evidenced",
            "unresolved": [],
            "source_task": "model-behavior-slices",
            "timestamp": "2026-01-01T00:00:00Z",
        },
    )


def test_initializer_seeds_analysis_fidelity_gate(tmp_path: Path) -> None:
    root = tmp_path / "campaign"
    initialize_campaign(root)

    project = json.loads((root / "project.json").read_text(encoding="utf-8"))
    progress = json.loads((root / "progress.json").read_text(encoding="utf-8"))
    tasks = json.loads((root / "tasks.json").read_text(encoding="utf-8"))

    assert project["schema_version"] == 2
    assert project["profile"] == "symbol-recovery"
    assert project["target"] is None
    assert project["derived_programs"] == []
    assert progress["phase"] == "analysis-fidelity"
    assert progress["analysis_fidelity"]["status"] == "pending"
    assert (root / "artifacts").is_dir()
    assert (root / "traces").is_dir()
    assert (root / "behaviors.jsonl").is_file()
    assert (root / "coverage.jsonl").is_file()
    assert (root / "runtime.jsonl").is_file()
    assert (root / "resources.jsonl").is_file()
    assert (root / "mappings.jsonl").is_file()
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
    artifact_content = b"flattened overlay image"
    artifact_path = root / "artifacts" / "game-overlays.exe"
    artifact_path.write_bytes(artifact_content)
    artifact_digest = "sha256:" + hashlib.sha256(artifact_content).hexdigest()
    project["derived_programs"] = [
        {
            "id": "overlay-image-1",
            "role": "overlay-aware-analysis",
            "source_digest": "sha256:" + "1" * 64,
            "digest": artifact_digest,
            "path": "artifacts/game-overlays.exe",
            "ghidra_program_path": "/GAME_OVERLAYS.EXE",
            "size": len(artifact_content),
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
    add_evidence(root, "ev-menu-001")
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
    add_behavior(root)
    add_evidence(root, "ev-data-001")
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
    add_behavior(root)
    add_evidence(root, "ev-runtime-001")
    (root / "traces" / "menu-retail.log").write_text("menu owns input\n", encoding="utf-8")
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
    add_evidence(root, "ev-resource-001")
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


def test_validator_checks_scummvm_implementation_mapping(tmp_path: Path) -> None:
    root = tmp_path / "campaign"
    initialize_campaign(root, profile="reimplementation", target="scummvm")
    add_behavior(root)
    add_evidence(root, "ev-menu-001")
    project = json.loads((root / "project.json").read_text(encoding="utf-8"))
    tasks = json.loads((root / "tasks.json").read_text(encoding="utf-8"))
    assert project["target"]["kind"] == "scummvm"
    assert "map-scummvm-implementation" in {task["id"] for task in tasks["tasks"]}

    mapping: dict[str, Any] = {
        "id": "mapping-main-menu",
        "behavior_id": "behavior-main-menu",
        "target": {
            "kind": "scummvm",
            "repository": "/checkout/scummvm",
            "revision": "abc123",
            "paths": ["engines/example/menu.cpp"],
            "symbols": ["ExampleEngine::runMainMenu"],
        },
        "retail_contract": ["Menu owns input until selection"],
        "strategy": "faithful",
        "service_substitutions": [],
        "retained_engine_semantics": ["Persist selection before launch"],
        "validation": {
            "unit_tests": ["menu transition test"],
            "fixtures": ["menu resource"],
            "interactive_replay": ["Select the first mission"],
        },
        "evidence_ids": ["ev-menu-001"],
        "confidence": "high",
        "status": "ready",
        "source_task": "map-scummvm-implementation",
        "timestamp": "2026-01-01T00:00:00Z",
    }
    mapping_path = root / "mappings.jsonl"
    mapping_path.write_text(json.dumps(mapping) + "\n", encoding="utf-8")
    assert run_script(VALIDATE_SCRIPT, root).returncode == 0

    mapping["strategy"] = "copy-the-assembly"
    mapping_path.write_text(json.dumps(mapping) + "\n", encoding="utf-8")
    result = run_script(VALIDATE_SCRIPT, root)
    assert result.returncode == 1
    assert "invalid mapping strategy" in result.stderr


def test_validator_rejects_dangling_behavior_evidence(tmp_path: Path) -> None:
    root = tmp_path / "campaign"
    initialize_campaign(root, profile="reimplementation")
    add_behavior(root)
    behavior_path = root / "behaviors.jsonl"
    behavior = json.loads(behavior_path.read_text(encoding="utf-8"))
    behavior["evidence_ids"] = ["ev-missing"]
    behavior_path.write_text(json.dumps(behavior) + "\n", encoding="utf-8")

    result = run_script(VALIDATE_SCRIPT, root)
    assert result.returncode == 1
    assert "unknown evidence id ev-missing" in result.stderr


def test_reporter_renders_deterministic_campaign_summary(tmp_path: Path) -> None:
    root = tmp_path / "campaign"
    initialize_campaign(root, profile="reimplementation", target="scummvm")

    first = run_script(REPORT_SCRIPT, root)
    second = run_script(REPORT_SCRIPT, root)
    assert first.returncode == 0, first.stderr
    assert first.stdout == second.stdout
    assert "# Campaign Report: GAME.EXE" in first.stdout
    assert "## Shipped-data reachability" in first.stdout

    report_path = root / "REPORT.md"
    written = run_script(REPORT_SCRIPT, root, "--output", report_path)
    assert written.returncode == 0, written.stderr
    assert report_path.read_text(encoding="utf-8") == first.stdout
