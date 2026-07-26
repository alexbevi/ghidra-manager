from copy import deepcopy
from typing import Any

from ghidra_manager.coverage.model import (
    EVIDENCE_SCHEMA,
    LEDGER_SCHEMA,
    PROFILE_SCHEMA,
    SCHEMA_VERSION,
    SNAPSHOT_SCHEMA,
)
from ghidra_manager.coverage.seeding import AUTOMATED_STATUSES, build_seed


def seed_inputs() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    profile = {
        "schema": PROFILE_SCHEMA,
        "version": SCHEMA_VERSION,
        "id": "demo",
    }
    ledger = {
        "schema": LEDGER_SCHEMA,
        "version": SCHEMA_VERSION,
        "profile_id": "demo",
        "records": [
            {
                "id": "fn:program:ram:00001000",
                "kind": "function",
                "subsystem": "runtime",
                "scope": {"state": "in_scope", "category": "game_logic"},
                "status": "complete",
                "verification": {"state": "unverified", "records": []},
                "evidence": ["manual:evidence"],
                "reachability": "direct_static",
                "notes": "reviewed",
            }
        ],
    }
    snapshot = {
        "schema": SNAPSHOT_SCHEMA,
        "version": SCHEMA_VERSION,
        "snapshot_id": "sha256:snapshot",
        "functions": [
            {
                "id": "fn:program:ram:00001000",
                "name": "Entry",
                "address": {"space": "ram", "offset": "0x00001000"},
                "instruction_count": 5,
            },
            {
                "id": "fn:program:ram:00002000",
                "name": "RunPuzzle",
                "address": {"space": "ram", "offset": "0x00002000"},
                "instruction_count": 10,
            },
        ],
        "entry_points": [
            {"address": {"space": "ram", "offset": "0x00001000"}}
        ],
        "call_graph": [
            {
                "caller": "fn:program:ram:00001000",
                "callee": "fn:program:ram:00002000",
            }
        ],
        "declared_roots": [],
        "declared_edges": [],
    }
    evidence = {
        "schema": EVIDENCE_SCHEMA,
        "version": SCHEMA_VERSION,
        "scan_id": "sha256:evidence",
        "facts": [
            {
                "id": "evidence:source",
                "kind": "source_anchor",
                "original_targets": ["fn:program:ram:00002000"],
                "implementation_targets": [
                    {"path": "engines/ripper/puzzles/demo.cpp"}
                ],
            },
            {
                "id": "evidence:commit",
                "kind": "commit_anchor",
                "original_targets": ["fn:program:ram:00002000"],
                "implementation_targets": [
                    {"path": "engines/ripper/puzzles/demo.cpp"}
                ],
            },
            {
                "id": "evidence:diagnostic",
                "kind": "diagnostic",
                "original_targets": ["fn:program:ram:00002000"],
                "implementation_targets": [
                    {"path": "engines/ripper/puzzles/demo.cpp"}
                ],
            },
        ],
        "behavioral_units": [
            {
                "id": "scummvm-ripper:scene-action:11",
                "kind": "behavioral_unit",
                "subsystem": "scene-actions",
                "label": "Puzzle",
                "provider": "scummvm.scene-actions",
                "source": {"path": "engines/ripper/script.h", "value": 11},
            }
        ],
    }
    return profile, ledger, snapshot, evidence


def test_seed_preserves_reviewed_records_and_builds_advisory_queue() -> None:
    profile, ledger, snapshot, evidence = seed_inputs()

    seeded, queue, summary = build_seed(profile, ledger, snapshot, evidence)

    records = {record["id"]: record for record in seeded["records"]}
    assert records["fn:program:ram:00001000"]["status"] == "complete"
    assert records["fn:program:ram:00001000"]["notes"] == "reviewed"
    candidate_record = records["fn:program:ram:00002000"]
    assert candidate_record["status"] == "unknown"
    assert candidate_record["scope"]["state"] == "unreviewed"
    assert candidate_record["subsystem"] == "puzzles"
    assert candidate_record["reachability"] == "direct_static"
    assert candidate_record["evidence"] == [
        "evidence:commit",
        "evidence:diagnostic",
        "evidence:source",
    ]
    candidates = {candidate["record_id"]: candidate for candidate in queue["candidates"]}
    puzzle = candidates["fn:program:ram:00002000"]
    assert puzzle["suggested_status"] == "partial"
    assert puzzle["suggested_scope"] == "in_scope"
    assert puzzle["confidence"] == "high"
    assert all(
        candidate["suggested_status"] in AUTOMATED_STATUSES
        for candidate in queue["candidates"]
    )
    assert "fn:program:ram:00001000" not in candidates
    assert summary == {
        "added_records": 2,
        "refreshed_unreviewed_records": 0,
        "preserved_records": 1,
        "review_candidates": 2,
        "linked_functions": 1,
        "partial_suggestions": 1,
    }


def test_seed_is_deterministic() -> None:
    inputs = seed_inputs()

    first = build_seed(*inputs)
    second = build_seed(*inputs)

    assert first == second


def test_behavioral_scenario_fields_survive_seeding() -> None:
    profile, ledger, snapshot, evidence = seed_inputs()
    evidence["behavioral_units"].append(
        {
            "id": "scummvm-ripper:scenario:new-game",
            "kind": "behavioral_unit",
            "unit_type": "scenario",
            "subsystem": "game-progression",
            "label": "Start a new game",
            "player_impact": "The player can enter the opening scene.",
            "critical_progression": True,
            "provider": "scummvm.ripper-scenarios",
            "source": {"kind": "adapter_catalog", "version": 1},
        }
    )

    seeded, queue, _summary = build_seed(profile, ledger, snapshot, evidence)

    scenario = next(
        item
        for item in seeded["records"]
        if item["id"] == "scummvm-ripper:scenario:new-game"
    )
    assert scenario["unit_type"] == "scenario"
    assert scenario["critical_progression"] is True
    assert scenario["player_impact"] == "The player can enter the opening scene."
    candidate = next(
        item
        for item in queue["candidates"]
        if item["record_id"] == "scummvm-ripper:scenario:new-game"
    )
    assert candidate["priority"] == 30
    assert candidate["reasons"] == ["explicit player-visible scenario"]


def test_same_file_diagnostic_does_not_imply_partial() -> None:
    profile, ledger, snapshot, evidence = seed_inputs()
    unlinked = deepcopy(evidence)
    diagnostic = next(
        fact for fact in unlinked["facts"] if fact["kind"] == "diagnostic"
    )
    diagnostic["original_targets"] = []

    _seeded, queue, _summary = build_seed(profile, ledger, snapshot, unlinked)

    candidate = next(
        item
        for item in queue["candidates"]
        if item["record_id"] == "fn:program:ram:00002000"
    )
    assert candidate["suggested_status"] == "unknown"
    assert "same source file requires review" in " ".join(candidate["reasons"])
