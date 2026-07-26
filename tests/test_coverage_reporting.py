from copy import deepcopy
from typing import Any

from ghidra_manager.coverage.model import (
    EVIDENCE_SCHEMA,
    LEDGER_SCHEMA,
    PROFILE_SCHEMA,
    SCHEMA_VERSION,
    SNAPSHOT_SCHEMA,
)
from ghidra_manager.coverage.reporting import build_diff, build_report, markdown_report


def inputs() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    profile = {
        "schema": PROFILE_SCHEMA,
        "version": SCHEMA_VERSION,
        "id": "demo",
    }
    snapshot = {
        "schema": SNAPSHOT_SCHEMA,
        "version": SCHEMA_VERSION,
        "snapshot_id": "sha256:snapshot",
        "functions": [
            {"id": "fn:1", "instruction_count": 10},
            {"id": "fn:2", "instruction_count": 30},
            {"id": "fn:3", "instruction_count": None},
        ],
    }
    evidence = {
        "schema": EVIDENCE_SCHEMA,
        "version": SCHEMA_VERSION,
        "scan_id": "sha256:evidence",
        "repository": {
            "revision": "abc",
            "content_fingerprint": "sha256:repo",
        },
        "facts": [{"id": "diagnostic:1", "kind": "diagnostic"}],
        "behavioral_units": [],
    }
    ledger = {
        "schema": LEDGER_SCHEMA,
        "version": SCHEMA_VERSION,
        "profile_id": "demo",
        "records": [
            {
                "id": "fn:1",
                "kind": "function",
                "scope": {"state": "in_scope"},
                "status": "complete",
                "verification": {"state": "static_verified"},
                "evidence": ["evidence:1"],
                "reachability": "direct_static",
            },
            {
                "id": "fn:2",
                "kind": "function",
                "scope": {"state": "in_scope"},
                "status": "partial",
                "verification": {"state": "unverified"},
                "evidence": [],
                "reachability": "data_driven",
            },
            {
                "id": "unit:1",
                "kind": "behavioral_unit",
                "subsystem": "scripts",
                "scope": {"state": "in_scope"},
                "status": "missing",
                "verification": {"state": "unverified"},
                "evidence": ["diagnostic:1"],
                "priority": 2,
                "reachability": "runtime_observed",
            },
        ],
    }
    return profile, ledger, snapshot, evidence


def test_report_separates_traceability_coverage_and_behavioral_units() -> None:
    profile, ledger, snapshot, evidence = inputs()

    report = build_report(profile, ledger, snapshot, evidence)

    assert report["metrics"]["function_traceability"] == {
        "numerator": 1,
        "denominator": 2,
        "ratio": 0.5,
    }
    assert report["metrics"]["conservative_coverage"]["ratio"] == 0.5
    assert report["metrics"]["coverage_ceiling"]["ratio"] == 1.0
    assert report["metrics"]["instruction_weighted"]["conservative_coverage"]["ratio"] == 0.25
    assert report["metrics"]["behavioral_units_by_subsystem"]["scripts"]["missing"] == 1
    assert report["metrics"]["behavioral_coverage"]["conservative_coverage"] == {
        "numerator": 0,
        "denominator": 1,
        "ratio": 0.0,
    }
    assert report["subsystem_dashboard"]["scripts"]["statuses"]["missing"] == 1
    assert report["gaps"][0]["id"] == "unit:1"
    markdown = markdown_report(report)
    assert "upper bound" in markdown
    assert "Instruction-weighted views measure code size" in markdown
    assert "Verification Distribution" in markdown
    assert "## Behavioral Coverage by Subsystem" in markdown
    assert "| scripts | 1 / 1 | 0 | 0 | 0 | 1 | 0 | 0 |" in markdown


def test_subsystem_dashboard_separates_reviewed_and_unreviewed_units() -> None:
    profile, ledger, snapshot, evidence = inputs()
    ledger["records"].extend(
        [
            {
                "id": "unit:2",
                "kind": "behavioral_unit",
                "subsystem": "scripts",
                "scope": {"state": "unreviewed"},
                "status": "unknown",
                "verification": {"state": "unverified"},
                "evidence": [],
            },
            {
                "id": "unit:3",
                "kind": "behavioral_unit",
                "subsystem": "puzzles",
                "scope": {"state": "in_scope"},
                "status": "equivalent",
                "verification": {
                    "state": "runtime_verified",
                    "records": ["run:puzzle"],
                },
                "evidence": [],
            },
        ]
    )

    report = build_report(profile, ledger, snapshot, evidence)

    scripts = report["subsystem_dashboard"]["scripts"]
    assert scripts["reviewed"] == 1
    assert scripts["unreviewed"] == 1
    assert scripts["total"] == 2
    assert report["subsystem_dashboard"]["puzzles"]["verification"] == {
        "runtime_verified": 1
    }
    assert report["metrics"]["behavioral_coverage"]["conservative_coverage"] == {
        "numerator": 1,
        "denominator": 2,
        "ratio": 0.5,
    }


def test_report_treats_player_scenarios_as_reviewed_coverage_units() -> None:
    profile, ledger, snapshot, evidence = inputs()
    ledger["records"].append(
        {
            "id": "scenario:new-game",
            "kind": "behavioral_unit",
            "unit_type": "scenario",
            "subsystem": "game-progression",
            "scope": {"state": "in_scope"},
            "status": "complete",
            "verification": {
                "state": "runtime_verified",
                "records": ["run:new-game"],
            },
            "critical_progression": True,
            "player_impact": "The player can begin the game.",
            "original": {"label": "Start a new game"},
            "evidence": [],
        }
    )

    report = build_report(profile, ledger, snapshot, evidence)

    assert report["metrics"]["critical_scenarios"]["conservative_coverage"] == {
        "numerator": 1,
        "denominator": 1,
        "ratio": 1.0,
    }
    assert report["metrics"]["critical_scenarios"]["verified"]["ratio"] == 1.0
    assert report["critical_scenarios"][0]["label"] == "Start a new game"
    markdown = markdown_report(report)
    assert "## Critical Player Scenarios" in markdown
    assert "The player can begin the game." in markdown


def test_report_surfaces_representative_reviewed_findings() -> None:
    profile, ledger, snapshot, evidence = inputs()
    partial = ledger["records"][1]
    partial["subsystem"] = "puzzles"
    partial["player_impact"] = "The puzzle can be entered but not completed."
    partial["known_missing"] = ["completion branch"]
    partial["deviations"] = ["temporary placeholder art"]
    partial["original"] = {"name": "RunPuzzle"}
    partial["critical_progression"] = True

    report = build_report(profile, ledger, snapshot, evidence)

    finding = report["representative_findings"]["partial"][0]
    assert finding["label"] == "RunPuzzle"
    assert finding["known_missing"] == ["completion branch"]
    gap = next(item for item in report["gaps"] if item["id"] == "fn:2")
    assert gap["subsystem"] == "puzzles"
    assert gap["player_impact"] == "The puzzle can be entered but not completed."
    markdown = markdown_report(report)
    assert "## Representative Reviewed Findings" in markdown
    assert "### Partial implementations" in markdown
    assert "Known missing: completion branch" in markdown


def test_report_exposes_assessment_and_evidence_readiness() -> None:
    profile, ledger, snapshot, evidence = inputs()
    ledger["records"].append(
        {
            "id": "fn:3",
            "kind": "function",
            "scope": {"state": "unreviewed"},
            "status": "unknown",
            "verification": {"state": "unverified"},
            "evidence": [],
        }
    )
    evidence["facts"].append(
        {
            "id": "source:1",
            "kind": "source_anchor",
            "claim": "mapped",
            "original_targets": ["fn:1"],
            "implementation_targets": [{"path": "engine/demo.cpp"}],
            "unresolved_original": None,
        }
    )
    evidence["facts"].append(
        {
            "id": "source:2",
            "kind": "source_anchor",
            "claim": "mentioned",
            "original_targets": [],
            "implementation_targets": [{"path": "engine/demo.cpp"}],
            "unresolved_original": {"name": "Missing", "address": "0x1234"},
        }
    )
    queue = {
        "candidates": [
            {
                "record_id": "fn:3",
                "suggested_scope": "in_scope",
                "confidence": "high",
                "subsystem": "scripts",
            }
        ]
    }

    report = build_report(profile, ledger, snapshot, evidence, queue)

    assert report["assessment"]["review_readiness"] == {
        "numerator": 3,
        "denominator": 4,
        "ratio": 0.75,
    }
    assert report["assessment"]["review_queue"]["suggested_in_scope"] == 1
    assert report["evidence_summary"]["linked_functions"] == 1
    assert report["evidence_summary"]["unresolved_anchors"] == 1
    markdown = markdown_report(report)
    assert "## Executive Summary" in markdown
    assert "## Assessment Readiness" in markdown
    assert "## Evidence Readiness" in markdown


def test_report_does_not_describe_unreviewed_state_as_no_gaps() -> None:
    profile, _ledger, snapshot, evidence = inputs()
    ledger = {
        "schema": LEDGER_SCHEMA,
        "version": SCHEMA_VERSION,
        "profile_id": "demo",
        "records": [
            {
                "id": "fn:1",
                "kind": "function",
                "scope": {"state": "unreviewed"},
                "status": "unknown",
                "verification": {"state": "unverified"},
                "evidence": [],
            }
        ],
    }

    report = build_report(profile, ledger, snapshot, evidence)
    markdown = markdown_report(report)

    assert "Implementation coverage cannot yet be estimated" in markdown
    assert "Gap analysis is unavailable" in markdown


def test_diff_distinguishes_resolved_reopened_and_evidence_only_changes() -> None:
    profile, ledger, snapshot, evidence = inputs()
    base = build_report(profile, ledger, snapshot, evidence)
    head_ledger = deepcopy(ledger)
    head_ledger["records"][0]["status"] = "partial"
    head_ledger["records"][1]["status"] = "complete"
    head_ledger["records"][2]["evidence"] = ["diagnostic:1", "evidence:2"]
    head = build_report(profile, head_ledger, snapshot, evidence)

    difference = build_diff(base, head)["changes"]

    assert difference["reopened"] == ["fn:1"]
    assert difference["resolved"] == ["fn:2"]
    assert difference["evidence_only"] == ["unit:1"]
