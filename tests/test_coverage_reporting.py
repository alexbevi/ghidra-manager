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
    assert report["gaps"][0]["id"] == "unit:1"
    markdown = markdown_report(report)
    assert "upper bound" in markdown
    assert "Instruction-weighted views measure code size" in markdown
    assert "Verification Distribution" in markdown


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
