"""Coverage calculations, Markdown rendering, and report diffs."""

from __future__ import annotations

from collections import Counter
from typing import Any

from ghidra_manager.coverage.model import (
    DIFF_SCHEMA,
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
    unreviewed = [
        item for item in records if item.get("scope", {}).get("state") == "unreviewed"
    ]
    in_scope_functions = [item for item in in_scope if item.get("kind") == "function"]
    status_counts = Counter(str(item.get("status")) for item in in_scope_functions)
    verification = Counter(
        str(item.get("verification", {}).get("state", "unverified")) for item in in_scope
    )
    linked = sum(bool(item.get("evidence")) for item in in_scope_functions)
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
    subsystem_counts: dict[str, Counter[str]] = {}
    for record in in_scope:
        if record.get("kind") != "behavioral_unit":
            continue
        subsystem = str(record.get("subsystem", "unspecified"))
        subsystem_counts.setdefault(subsystem, Counter())[str(record.get("status"))] += 1
    reviewed_function_ids = {
        str(item.get("id"))
        for item in records
        if item.get("kind") == "function"
        and item.get("scope", {}).get("state") != "unreviewed"
    }
    inventory_function_ids = set(function_map)
    reviewed_behavioral_ids = {
        str(item.get("id"))
        for item in records
        if item.get("kind") == "behavioral_unit"
        and item.get("scope", {}).get("state") != "unreviewed"
    }
    inventory_behavioral_ids = {
        str(item["id"])
        for item in evidence.get("behavioral_units", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    function_record_ids = {
        str(item["id"])
        for item in records
        if item.get("kind") == "function" and isinstance(item.get("id"), str)
    }
    behavioral_records = [
        item for item in records if item.get("kind") == "behavioral_unit"
    ]
    reviewed_records = len(in_scope) + len(out_of_scope)
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
    linked_function_ids = {
        str(target)
        for fact in facts
        for target in fact.get("original_targets", [])
        if isinstance(target, str) and target in function_record_ids
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
        },
        "inventory": {
            "functions": len(snapshot.get("functions", [])),
            "behavioral_units": len(evidence.get("behavioral_units", [])),
            "ledger_records": len(records),
            "scope_reviewed": reviewed_records,
            "scope_unreviewed": len(inventory_function_ids - reviewed_function_ids)
            + sum(item.get("kind") != "function" for item in unreviewed),
            "behavioral_units_unreviewed": len(
                inventory_behavioral_ids - reviewed_behavioral_ids
            ),
            "excluded": len(out_of_scope)
            + sum(item.get("status") == "not_applicable" for item in records),
        },
        "assessment": {
            "review_readiness": _ratio(reviewed_records, len(records)),
            "functions": {
                "reviewed": len(reviewed_function_ids),
                "unreviewed": len(function_record_ids - reviewed_function_ids),
                "total": len(function_record_ids),
            },
            "behavioral_units": {
                "reviewed": len(reviewed_behavioral_ids),
                "unreviewed": len(behavioral_records)
                - len(reviewed_behavioral_ids),
                "total": len(behavioral_records),
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
            "status_distribution": dict(sorted(status_counts.items())),
            "verification_distribution": dict(sorted(verification.items())),
            "instruction_weighted": {
                "conservative_coverage": _ratio(
                    weighted_implemented, weighted_denominator
                ),
                "coverage_ceiling": _ratio(weighted_ceiling, weighted_denominator),
                "functions_without_weight": missing_weights,
            },
            "behavioral_units_by_subsystem": {
                key: dict(sorted(value.items()))
                for key, value in sorted(subsystem_counts.items())
            },
        },
        "gaps": [
            {
                "id": item["id"],
                "status": item["status"],
                "priority": item.get("priority", 0),
                "critical_progression": bool(item.get("critical_progression")),
                "diagnostic": bool(diagnostic_ids.intersection(item.get("evidence", []))),
                "reachability": item.get("reachability", "unknown"),
                "known_missing": item.get("known_missing", []),
            }
            for item in gaps
        ],
        "classifications": [
            {
                "id": item["id"],
                "kind": item.get("kind"),
                "scope": item.get("scope", {}).get("state"),
                "status": item.get("status"),
                "verification": item.get("verification", {}).get("state"),
                "evidence": sorted(item.get("evidence", [])),
            }
            for item in sorted(records, key=lambda record: str(record.get("id")))
        ],
    }
    return with_content_id(report, "report_id")


def markdown_report(report: dict[str, Any]) -> str:
    metrics = report["metrics"]
    assessment = report["assessment"]

    def metric(name: str) -> str:
        value = metrics[name]
        ratio = value["ratio"]
        percentage = "n/a" if ratio is None else f"{ratio * 100:.2f}%"
        return f"{value['numerator']} / {value['denominator']} ({percentage})"

    lines = [
        f"# Coverage Report: {report['profile_id']}",
        "",
        f"- Snapshot: `{report['inputs']['snapshot_id']}`",
        f"- Evidence: `{report['inputs']['evidence_scan_id']}`",
        f"- Repository revision: `{report['inputs']['repository_revision']}`",
        "",
        "## Executive Summary",
        "",
    ]
    if metrics["conservative_coverage"]["denominator"]:
        lines.extend(
            [
                f"- Conservative implementation coverage: "
                f"{metric('conservative_coverage')}",
                f"- Coverage ceiling: {metric('coverage_ceiling')}",
            ]
        )
    else:
        lines.append(
            "- Implementation coverage cannot yet be estimated because no "
            "in-scope functions have been reviewed."
        )
    lines.extend(
        [
            f"- Assessment readiness: "
            f"{assessment['review_readiness']['numerator']} / "
            f"{assessment['review_readiness']['denominator']} reviewed",
            f"- Behavioral-unit review: "
            f"{assessment['behavioral_units']['reviewed']} / "
            f"{assessment['behavioral_units']['total']} reviewed",
            "",
            "Completion, evidence linkage, and verification are separate claims.",
            "",
            "## Assessment Readiness",
            "",
            f"- Function records: {assessment['functions']['reviewed']} reviewed; "
            f"{assessment['functions']['unreviewed']} unreviewed",
            f"- Behavioral units: {assessment['behavioral_units']['reviewed']} reviewed; "
            f"{assessment['behavioral_units']['unreviewed']} unreviewed",
            f"- Excluded/not applicable: {report['inventory']['excluded']}",
        ]
    )
    queue = assessment["review_queue"]
    if queue["available"]:
        confidence = ", ".join(
            f"{key}={value}"
            for key, value in sorted(queue["confidence_distribution"].items())
        ) or "none"
        lines.extend(
            [
                f"- Advisory review queue: {queue['candidates']} candidates; "
                f"{queue['suggested_in_scope']} suggested in-scope",
                f"- Candidate confidence: {confidence}",
            ]
        )
    else:
        lines.append("- Advisory review queue: unavailable")
    evidence = report["evidence_summary"]
    fact_kinds = ", ".join(
        f"{key}={value}"
        for key, value in sorted(evidence["fact_kind_distribution"].items())
    ) or "none"
    lines.extend(
        [
            "",
            "## Evidence Readiness",
            "",
            f"- Evidence facts: {evidence['facts']} ({fact_kinds})",
            f"- Evidence-linked original functions: {evidence['linked_functions']}",
            f"- Reimplementation paths referenced: {evidence['implementation_paths']}",
            f"- Unresolved original anchors: {evidence['unresolved_anchors']}",
            f"- Discovered behavioral units: {evidence['behavioral_units']}",
            "",
            "Evidence indicates traceability and review readiness; it does not establish "
            "implementation completeness.",
            "",
            "## Engineering Metrics",
            "",
            f"- Function traceability: {metric('function_traceability')}",
            f"- Conservative implementation coverage: {metric('conservative_coverage')}",
            f"- Coverage ceiling: {metric('coverage_ceiling')}",
            f"- Scope-unreviewed functions/records: "
            f"{report['inventory']['scope_unreviewed']}",
            f"- Unreviewed behavioral units: "
            f"{report['inventory']['behavioral_units_unreviewed']}",
            "The coverage ceiling treats partial records as an upper bound, not "
            "completed behavior.",
            "Instruction-weighted views measure code size, not behavioral importance.",
            "",
            "### Reviewed Status Distribution",
            "",
        ]
    )
    status_distribution = metrics["status_distribution"]
    if status_distribution:
        lines.extend(
            f"- {status}: {count}"
            for status, count in sorted(status_distribution.items())
        )
    else:
        lines.append("No in-scope functions have been classified.")
    lines.extend(
        [
            "",
            "### Verification Distribution",
            "",
        ]
    )
    verification_distribution = metrics["verification_distribution"]
    if verification_distribution:
        lines.extend(
            f"- {state}: {count}"
            for state, count in sorted(verification_distribution.items())
        )
    else:
        lines.append("No in-scope records have verification classifications.")
    lines.extend(
        [
        "",
        "## Prioritized Gaps",
        "",
        ]
    )
    if not report["gaps"]:
        if report["inventory"]["scope_reviewed"]:
            lines.append("No gaps are recorded among reviewed in-scope records.")
        else:
            lines.append(
                "Gap analysis is unavailable because no records have a reviewed scope."
            )
    else:
        lines.extend(
            f"- `{gap['id']}` — {gap['status']}; reachability={gap['reachability']}; "
            f"priority={gap['priority']}"
            for gap in report["gaps"]
        )
    return "\n".join(lines) + "\n"


def build_diff(base: dict[str, Any], head: dict[str, Any]) -> dict[str, Any]:
    base_records = {str(item["id"]): item for item in base.get("classifications", [])}
    head_records = {str(item["id"]): item for item in head.get("classifications", [])}
    added = sorted(head_records.keys() - base_records.keys())
    removed = sorted(base_records.keys() - head_records.keys())
    resolved: list[str] = []
    reopened: list[str] = []
    reclassified: list[str] = []
    verification_changed: list[str] = []
    evidence_only: list[str] = []
    for identifier in sorted(base_records.keys() & head_records.keys()):
        before = base_records[identifier]
        after = head_records[identifier]
        before_status = before.get("status")
        after_status = after.get("status")
        if before_status in GAPS and after_status in IMPLEMENTED:
            resolved.append(identifier)
        elif before_status in IMPLEMENTED and after_status in GAPS:
            reopened.append(identifier)
        elif before_status != after_status or before.get("scope") != after.get("scope"):
            reclassified.append(identifier)
        if before.get("verification") != after.get("verification"):
            verification_changed.append(identifier)
        if (
            before.get("evidence") != after.get("evidence")
            and before_status == after_status
            and before.get("scope") == after.get("scope")
            and before.get("verification") == after.get("verification")
        ):
            evidence_only.append(identifier)
    result: dict[str, Any] = {
        "schema": DIFF_SCHEMA,
        "version": SCHEMA_VERSION,
        "base_report_id": base["report_id"],
        "head_report_id": head["report_id"],
        "base_revision": base["inputs"]["repository_revision"],
        "head_revision": head["inputs"]["repository_revision"],
        "changes": {
            "added": added,
            "added_gaps": [
                identifier
                for identifier in added
                if head_records[identifier].get("status") in GAPS
            ],
            "removed": removed,
            "resolved": resolved,
            "reopened": reopened,
            "reclassified": reclassified,
            "verification_changed": verification_changed,
            "evidence_only": evidence_only,
        },
    }
    return with_content_id(result, "diff_id")


def markdown_diff(value: dict[str, Any]) -> str:
    changes = value["changes"]
    lines = [
        "# Coverage Diff",
        "",
        f"- Base revision: `{value['base_revision']}`",
        f"- Head revision: `{value['head_revision']}`",
        f"- Added records: {len(changes['added'])}",
        f"- Removed records: {len(changes['removed'])}",
        f"- Resolved gaps: {len(changes['resolved'])}",
        f"- Reopened gaps: {len(changes['reopened'])}",
        f"- Reclassified gaps: {len(changes['reclassified'])}",
        f"- Verification changes: {len(changes['verification_changed'])}",
        f"- Evidence-only changes: {len(changes['evidence_only'])}",
        "",
    ]
    return "\n".join(lines)
