"""Deterministic coverage calculations and canonical report construction."""

from __future__ import annotations

from collections import Counter
from typing import Any

from ghidra_manager.coverage.model import (
    REPORT_SCHEMA,
    SCHEMA_VERSION,
    with_content_id,
)

IMPLEMENTED = {"complete", "equivalent"}
CEILING = IMPLEMENTED | {"partial"}
GAPS = {"missing", "partial", "unknown"}


def _ratio(numerator: int, denominator: int) -> dict[str, int | float | None]:
    return {
        "numerator": numerator,
        "denominator": denominator,
        "ratio": numerator / denominator if denominator else None,
    }


def _behavioral_dashboard(
    records: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    dashboard: dict[str, dict[str, Any]] = {}
    for record in records:
        if record.get("kind") != "behavioral_unit":
            continue
        subsystem = str(record.get("subsystem", "unspecified"))
        row = dashboard.setdefault(
            subsystem,
            {
                "total": 0,
                "reviewed": 0,
                "unreviewed": 0,
                "in_scope": 0,
                "out_of_scope": 0,
                "statuses": Counter(),
                "verification": Counter(),
            },
        )
        row["total"] += 1
        scope = record.get("scope", {}).get("state")
        if scope == "unreviewed":
            row["unreviewed"] += 1
            continue
        row["reviewed"] += 1
        if scope == "out_of_scope":
            row["out_of_scope"] += 1
            continue
        if scope == "in_scope":
            row["in_scope"] += 1
            row["statuses"][str(record.get("status", "unknown"))] += 1
            verification = str(
                record.get("verification", {}).get("state", "unverified")
            )
            row["verification"][verification] += 1
    return {
        subsystem: {
            **{key: value for key, value in row.items() if key not in {"statuses", "verification"}},
            "statuses": dict(sorted(row["statuses"].items())),
            "verification": dict(sorted(row["verification"].items())),
        }
        for subsystem, row in sorted(dashboard.items())
    }


def _merged_behavioral_records(
    records: list[dict[str, Any]],
    evidence: dict[str, Any],
) -> list[dict[str, Any]]:
    """Overlay reviewed ledger records on discovered behavioral inventory."""
    merged: dict[str, dict[str, Any]] = {}
    for unit in evidence.get("behavioral_units", []):
        if not isinstance(unit, dict) or not isinstance(unit.get("id"), str):
            continue
        merged[str(unit["id"])] = {
            "id": unit["id"],
            "kind": "behavioral_unit",
            "unit_type": unit.get("unit_type", "registry"),
            "subsystem": unit.get("subsystem", "unassigned"),
            "scope": {"state": "unreviewed"},
            "status": "unknown",
            "verification": {"state": "unverified", "records": []},
            "critical_progression": bool(unit.get("critical_progression")),
            "player_impact": unit.get("player_impact"),
            "original": {
                "label": unit.get("label"),
                "provider": unit.get("provider"),
                "source": unit.get("source"),
            },
        }
    for record in records:
        if record.get("kind") != "behavioral_unit" or not isinstance(
            record.get("id"), str
        ):
            continue
        identifier = str(record["id"])
        merged[identifier] = {**merged.get(identifier, {}), **record}
    return [merged[identifier] for identifier in sorted(merged)]


def _record_label(record: dict[str, Any]) -> str:
    original = record.get("original", {})
    if isinstance(original, dict):
        for field in ("label", "name"):
            value = original.get(field)
            if isinstance(value, str) and value:
                return value
    label = record.get("label")
    return str(label) if isinstance(label, str) and label else str(record["id"])


def _finding(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": record["id"],
        "label": _record_label(record),
        "kind": record.get("kind"),
        "subsystem": record.get("subsystem", "unassigned"),
        "status": record.get("status"),
        "verification": record.get("verification", {}).get("state", "unverified"),
        "critical_progression": bool(record.get("critical_progression")),
        "priority": int(record.get("priority", 0)),
        "player_impact": record.get("player_impact"),
        "known_missing": record.get("known_missing", []),
        "deviations": record.get("deviations", []),
        "notes": record.get("notes"),
        "implementation": record.get("implementation", {}),
        "evidence": sorted(record.get("evidence", [])),
    }


def build_report(
    profile: dict[str, Any],
    ledger: dict[str, Any],
    snapshot: dict[str, Any],
    evidence: dict[str, Any],
    review_queue: dict[str, Any] | None = None,
) -> dict[str, Any]:
    records = [item for item in ledger.get("records", []) if isinstance(item, dict)]
    in_scope = [
        item for item in records if item.get("scope", {}).get("state") == "in_scope"
    ]
    out_of_scope = [
        item for item in records if item.get("scope", {}).get("state") == "out_of_scope"
    ]
    in_scope_functions = [item for item in in_scope if item.get("kind") == "function"]
    status_counts = Counter(str(item.get("status")) for item in in_scope_functions)
    verification = Counter(
        str(item.get("verification", {}).get("state", "unverified")) for item in in_scope
    )
    function_records = in_scope_functions
    function_map = {
        str(item["id"]): item
        for item in snapshot.get("functions", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    weighted_denominator = 0
    weighted_implemented = 0
    weighted_ceiling = 0
    missing_weights = 0
    for record in function_records:
        function = function_map.get(str(record.get("id")))
        weight = function.get("instruction_count") if function else None
        if not isinstance(weight, int):
            missing_weights += 1
            continue
        weighted_denominator += weight
        if record.get("status") in IMPLEMENTED:
            weighted_implemented += weight
        if record.get("status") in CEILING:
            weighted_ceiling += weight
    diagnostic_ids = {
        str(item["id"])
        for item in evidence.get("facts", [])
        if isinstance(item, dict) and item.get("kind") == "diagnostic"
    }
    reachability_rank = {
        "runtime_observed": 5,
        "direct_static": 4,
        "data_driven": 3,
        "declared_indirect": 2,
        "unknown": 1,
        "proven_unreachable": 0,
    }
    gaps = [item for item in in_scope if item.get("status") in GAPS]
    gaps.sort(
        key=lambda item: (
            -int(item.get("priority", 0)),
            -int(bool(item.get("critical_progression"))),
            -int(bool(diagnostic_ids.intersection(item.get("evidence", [])))),
            -reachability_rank.get(str(item.get("reachability", "unknown")), 1),
            str(item.get("id")),
        )
    )
    findings = [
        item for item in in_scope if item.get("status") in IMPLEMENTED | {"partial", "missing"}
    ]
    findings.sort(
        key=lambda item: (
            -int(bool(item.get("critical_progression"))),
            -int(item.get("priority", 0)),
            str(item.get("id")),
        )
    )
    reviewed_function_ids = {
        str(item.get("id"))
        for item in records
        if item.get("kind") == "function"
        and item.get("scope", {}).get("state") != "unreviewed"
    }
    inventory_function_ids = set(function_map)
    behavioral_records = _merged_behavioral_records(records, evidence)
    behavioral_inventory_ids = {str(item["id"]) for item in behavioral_records}
    reviewed_behavioral_ids = {
        str(item["id"])
        for item in behavioral_records
        if item.get("scope", {}).get("state") != "unreviewed"
    }
    in_scope_behavioral = [
        item
        for item in behavioral_records
        if item.get("scope", {}).get("state") == "in_scope"
    ]
    behavioral_statuses = Counter(
        str(item.get("status", "unknown")) for item in in_scope_behavioral
    )
    verified_behavioral = sum(
        item.get("verification", {}).get("state") != "unverified"
        for item in in_scope_behavioral
    )
    scenario_records = [
        item
        for item in behavioral_records
        if item.get("unit_type", "registry") == "scenario"
    ]
    in_scope_scenarios = [
        item
        for item in scenario_records
        if item.get("scope", {}).get("state") == "in_scope"
    ]
    scenario_statuses = Counter(
        str(item.get("status", "unknown")) for item in in_scope_scenarios
    )
    reviewed_scenarios = [
        item
        for item in scenario_records
        if item.get("scope", {}).get("state") != "unreviewed"
    ]
    verified_scenarios = sum(
        item.get("verification", {}).get("state") != "unverified"
        for item in in_scope_scenarios
    )
    reviewed_records = len(reviewed_function_ids) + len(reviewed_behavioral_ids)
    inventory_records = len(inventory_function_ids) + len(behavioral_inventory_ids)
    candidates = [
        item
        for item in (review_queue or {}).get("candidates", [])
        if isinstance(item, dict)
    ]
    candidate_confidence = Counter(
        str(item.get("confidence", "unknown")) for item in candidates
    )
    candidate_subsystems = Counter(
        str(item.get("subsystem", "unassigned")) for item in candidates
    )
    facts = [
        item for item in evidence.get("facts", []) if isinstance(item, dict)
    ]
    active_fact_ids = {
        str(item["id"]) for item in facts if isinstance(item.get("id"), str)
    }
    stale_evidence_references = {
        str(reference)
        for record in records
        for reference in record.get("evidence", [])
        if isinstance(reference, str) and reference not in active_fact_ids
    }
    linked = sum(
        bool(set(item.get("evidence", [])) & active_fact_ids)
        for item in in_scope_functions
    )
    linked_function_ids = {
        str(target)
        for fact in facts
        for target in fact.get("original_targets", [])
        if isinstance(target, str) and target in function_map
    }
    implementation_paths = {
        str(target["path"])
        for fact in facts
        for target in fact.get("implementation_targets", [])
        if isinstance(target, dict) and isinstance(target.get("path"), str)
    }
    report: dict[str, Any] = {
        "schema": REPORT_SCHEMA,
        "version": SCHEMA_VERSION,
        "profile_id": profile["id"],
        "inputs": {
            "snapshot_id": snapshot["snapshot_id"],
            "evidence_scan_id": evidence["scan_id"],
            "repository_revision": evidence["repository"]["revision"],
            "repository_fingerprint": evidence["repository"]["content_fingerprint"],
            "repository_dirty": bool(evidence["repository"].get("dirty")),
        },
        "inventory": {
            "functions": len(snapshot.get("functions", [])),
            "behavioral_units": len(evidence.get("behavioral_units", [])),
            "ledger_records": len(records),
            "scope_reviewed": reviewed_records,
            "scope_unreviewed": len(inventory_function_ids - reviewed_function_ids)
            + len(behavioral_inventory_ids - reviewed_behavioral_ids),
            "behavioral_units_unreviewed": len(
                behavioral_inventory_ids - reviewed_behavioral_ids
            ),
            "excluded": len(out_of_scope),
            "not_applicable": sum(
                item.get("status") == "not_applicable" for item in out_of_scope
            ),
        },
        "assessment": {
            "review_readiness": _ratio(reviewed_records, inventory_records),
            "functions": {
                "reviewed": len(reviewed_function_ids),
                "unreviewed": len(inventory_function_ids - reviewed_function_ids),
                "total": len(inventory_function_ids),
            },
            "behavioral_units": {
                "reviewed": len(reviewed_behavioral_ids),
                "unreviewed": len(
                    behavioral_inventory_ids - reviewed_behavioral_ids
                ),
                "total": len(behavioral_inventory_ids),
            },
            "review_queue": {
                "available": review_queue is not None,
                "candidates": len(candidates),
                "suggested_in_scope": sum(
                    item.get("suggested_scope") == "in_scope"
                    for item in candidates
                ),
                "confidence_distribution": dict(
                    sorted(candidate_confidence.items())
                ),
                "candidates_by_subsystem": dict(
                    sorted(candidate_subsystems.items())
                ),
            },
        },
        "evidence_summary": {
            "facts": len(facts),
            "fact_kind_distribution": dict(
                sorted(Counter(str(item.get("kind", "unknown")) for item in facts).items())
            ),
            "claim_distribution": dict(
                sorted(Counter(str(item.get("claim", "unknown")) for item in facts).items())
            ),
            "linked_functions": len(linked_function_ids),
            "unresolved_anchors": sum(
                isinstance(item.get("unresolved_original"), dict) for item in facts
            ),
            "implementation_paths": len(implementation_paths),
            "behavioral_units": len(evidence.get("behavioral_units", [])),
            "stale_references": len(stale_evidence_references),
        },
        "metrics": {
            "function_traceability": _ratio(linked, len(in_scope_functions)),
            "conservative_coverage": _ratio(
                sum(status_counts[status] for status in IMPLEMENTED),
                len(in_scope_functions),
            ),
            "coverage_ceiling": _ratio(
                sum(status_counts[status] for status in CEILING),
                len(in_scope_functions),
            ),
            "behavioral_coverage": {
                "conservative_coverage": _ratio(
                    sum(behavioral_statuses[status] for status in IMPLEMENTED),
                    len(in_scope_behavioral),
                ),
                "coverage_ceiling": _ratio(
                    sum(behavioral_statuses[status] for status in CEILING),
                    len(in_scope_behavioral),
                ),
                "verified": _ratio(
                    verified_behavioral,
                    len(in_scope_behavioral),
                ),
                "status_distribution": dict(sorted(behavioral_statuses.items())),
            },
            "player_scenarios": {
                "review_readiness": _ratio(
                    len(reviewed_scenarios),
                    len(scenario_records),
                ),
                "conservative_coverage": _ratio(
                    sum(scenario_statuses[status] for status in IMPLEMENTED),
                    len(in_scope_scenarios),
                ),
                "coverage_ceiling": _ratio(
                    sum(scenario_statuses[status] for status in CEILING),
                    len(in_scope_scenarios),
                ),
                "verified": _ratio(verified_scenarios, len(in_scope_scenarios)),
                "status_distribution": dict(sorted(scenario_statuses.items())),
            },
            "status_distribution": dict(sorted(status_counts.items())),
            "verification_distribution": dict(sorted(verification.items())),
            "instruction_weighted": {
                "conservative_coverage": _ratio(
                    weighted_implemented, weighted_denominator
                ),
                "coverage_ceiling": _ratio(weighted_ceiling, weighted_denominator),
                "functions_without_weight": missing_weights,
            },
        },
        "subsystem_dashboard": _behavioral_dashboard(behavioral_records),
        "representative_findings": {
            status: [
                _finding(item)
                for item in findings
                if item.get("status") == status
            ][:5]
            for status in ("complete", "equivalent", "partial", "missing")
        },
        "player_scenarios": [
            {
                "id": item["id"],
                "label": item.get("original", {}).get("label")
                or item.get("label")
                or item["id"],
                "scope": item.get("scope", {}).get("state", "unreviewed"),
                "status": item.get("status", "unknown"),
                "verification": item.get("verification", {}).get(
                    "state", "unverified"
                ),
                "critical_progression": bool(item.get("critical_progression")),
                "player_impact": item.get("player_impact"),
                "known_missing": item.get("known_missing", []),
                "deviations": item.get("deviations", []),
            }
            for item in sorted(
                scenario_records,
                key=lambda record: (
                    -int(bool(record.get("critical_progression"))),
                    str(record.get("id")),
                ),
            )
        ],
        "gaps": [
            {
                "id": item["id"],
                "status": item["status"],
                "priority": item.get("priority", 0),
                "critical_progression": bool(item.get("critical_progression")),
                "diagnostic": bool(diagnostic_ids.intersection(item.get("evidence", []))),
                "reachability": item.get("reachability", "unknown"),
                "label": _record_label(item),
                "subsystem": item.get("subsystem", "unassigned"),
                "player_impact": item.get("player_impact"),
                "known_missing": item.get("known_missing", []),
                "deviations": item.get("deviations", []),
            }
            for item in gaps
        ],
        "classifications": [
            {
                "id": item["id"],
                "label": _record_label(item),
                "kind": item.get("kind"),
                "unit_type": item.get("unit_type"),
                "subsystem": item.get("subsystem", "unassigned"),
                "scope": item.get("scope", {}).get("state"),
                "status": item.get("status"),
                "verification": item.get("verification", {}).get("state"),
                "critical_progression": bool(item.get("critical_progression")),
                "player_impact": item.get("player_impact"),
                "known_missing": item.get("known_missing", []),
                "deviations": item.get("deviations", []),
                "evidence": sorted(item.get("evidence", [])),
            }
            for item in sorted(records, key=lambda record: str(record.get("id")))
        ],
    }
    return with_content_id(report, "report_id")
