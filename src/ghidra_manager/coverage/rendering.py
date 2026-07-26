"""Human-readable rendering for canonical coverage reports."""

from __future__ import annotations

from typing import Any


def _ratio_text(value: dict[str, Any]) -> str:
    ratio = value["ratio"]
    percentage = "n/a" if ratio is None else f"{ratio * 100:.2f}%"
    return f"{value['numerator']} / {value['denominator']} ({percentage})"


def _append_executive_summary(lines: list[str], report: dict[str, Any]) -> None:
    metrics = report["metrics"]
    assessment = report["assessment"]
    behavioral = metrics["behavioral_coverage"]
    scenarios = metrics["player_scenarios"]
    lines.extend(["## Executive Summary", ""])
    if behavioral["conservative_coverage"]["denominator"]:
        lines.extend(
            [
                f"- Conservative functional coverage: "
                f"{_ratio_text(behavioral['conservative_coverage'])}",
                f"- Functional coverage ceiling: "
                f"{_ratio_text(behavioral['coverage_ceiling'])}",
                f"- Verified behavioral units: "
                f"{_ratio_text(behavioral['verified'])}",
            ]
        )
    elif metrics["conservative_coverage"]["denominator"]:
        lines.extend(
            [
                f"- Conservative function coverage: "
                f"{_ratio_text(metrics['conservative_coverage'])}",
                f"- Function coverage ceiling: "
                f"{_ratio_text(metrics['coverage_ceiling'])}",
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
            f"- Player-scenario review: "
            f"{scenarios['review_readiness']['numerator']} / "
            f"{scenarios['review_readiness']['denominator']} reviewed",
            "",
            "Completion, evidence linkage, and verification are separate claims.",
        ]
    )


def _append_assessment(lines: list[str], report: dict[str, Any]) -> None:
    assessment = report["assessment"]
    lines.extend(
        [
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
    if not queue["available"]:
        lines.append("- Advisory review queue: unavailable")
        return
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


def _append_subsystems(lines: list[str], report: dict[str, Any]) -> None:
    lines.extend(["", "## Behavioral Coverage by Subsystem", ""])
    dashboard = report["subsystem_dashboard"]
    if not dashboard:
        lines.append("No behavioral units are present in the reviewed ledger.")
        return
    lines.extend(
        [
            "| Subsystem | Reviewed | Complete | Equivalent | Partial | "
            "Missing | Unknown | Verified |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for subsystem, row in dashboard.items():
        statuses = row["statuses"]
        verified = sum(
            count
            for state, count in row["verification"].items()
            if state != "unverified"
        )
        lines.append(
            f"| {subsystem} | {row['reviewed']} / {row['total']} | "
            f"{statuses.get('complete', 0)} | "
            f"{statuses.get('equivalent', 0)} | "
            f"{statuses.get('partial', 0)} | "
            f"{statuses.get('missing', 0)} | "
            f"{statuses.get('unknown', 0)} | {verified} |"
        )
    lines.extend(
        [
            "",
            "Status counts include reviewed in-scope behavioral units. "
            "Reviewed totals also include explicit out-of-scope decisions.",
        ]
    )


def _append_scenarios(lines: list[str], report: dict[str, Any]) -> None:
    lines.extend(["", "## Player Scenarios", ""])
    scenarios = report["player_scenarios"]
    if not scenarios:
        lines.append("No player scenarios are defined.")
        return
    lines.extend(
        [
            "| Scenario | Scope review | Status | Verification | Player impact |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    for scenario in scenarios:
        impact = str(scenario["player_impact"] or "").replace("|", "\\|")
        lines.append(
            f"| {scenario['label']} | {scenario['scope']} | "
            f"{scenario['status']} | {scenario['verification']} | {impact} |"
        )
    lines.extend(
        [
            "",
            "Scenario coverage is derived only from reviewer-authored scope, status, "
            "and verification records.",
        ]
    )


def _append_findings(lines: list[str], report: dict[str, Any]) -> None:
    lines.extend(["", "## Representative Reviewed Findings", ""])
    finding_labels = {
        "complete": "Completed behavior",
        "equivalent": "Equivalent replacements",
        "partial": "Partial implementations",
        "missing": "Missing behavior",
    }
    any_findings = False
    for status, heading in finding_labels.items():
        findings = report["representative_findings"][status]
        if not findings:
            continue
        any_findings = True
        lines.extend([f"### {heading}", ""])
        for finding in findings:
            details = [
                f"subsystem={finding['subsystem']}",
                f"verification={finding['verification']}",
            ]
            if finding["critical_progression"]:
                details.append("critical progression")
            lines.append(
                f"- **{finding['label']}** (`{finding['id']}`): "
                f"{'; '.join(details)}"
            )
            if finding["player_impact"]:
                lines.append(f"  - Player impact: {finding['player_impact']}")
            if finding["known_missing"]:
                lines.append(
                    f"  - Known missing: {', '.join(map(str, finding['known_missing']))}"
                )
            if finding["deviations"]:
                lines.append(
                    f"  - Deviations: {', '.join(map(str, finding['deviations']))}"
                )
        lines.append("")
    if not any_findings:
        lines.append(
            "No reviewed complete, equivalent, partial, or missing findings are available."
        )


def _append_evidence_and_engineering(
    lines: list[str], report: dict[str, Any]
) -> None:
    evidence = report["evidence_summary"]
    metrics = report["metrics"]
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
            f"- Function traceability: "
            f"{_ratio_text(metrics['function_traceability'])}",
            f"- Conservative implementation coverage: "
            f"{_ratio_text(metrics['conservative_coverage'])}",
            f"- Coverage ceiling: {_ratio_text(metrics['coverage_ceiling'])}",
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
    lines.extend(["", "### Verification Distribution", ""])
    verification = metrics["verification_distribution"]
    if verification:
        lines.extend(
            f"- {state}: {count}"
            for state, count in sorted(verification.items())
        )
    else:
        lines.append("No in-scope records have verification classifications.")


def _append_gaps(lines: list[str], report: dict[str, Any]) -> None:
    lines.extend(["", "## Prioritized Gaps", ""])
    if report["gaps"]:
        lines.extend(
            f"- **{gap['label']}** (`{gap['id']}`) — {gap['status']}; "
            f"subsystem={gap['subsystem']}; reachability={gap['reachability']}; "
            f"priority={gap['priority']}"
            for gap in report["gaps"]
        )
    elif report["inventory"]["scope_reviewed"]:
        lines.append("No gaps are recorded among reviewed in-scope records.")
    else:
        lines.append(
            "Gap analysis is unavailable because no records have a reviewed scope."
        )


def markdown_report(report: dict[str, Any]) -> str:
    """Render the communication summary followed by engineering audit detail."""
    lines = [
        f"# Coverage Report: {report['profile_id']}",
        "",
        f"- Snapshot: `{report['inputs']['snapshot_id']}`",
        f"- Evidence: `{report['inputs']['evidence_scan_id']}`",
        f"- Repository revision: `{report['inputs']['repository_revision']}`",
        "",
    ]
    _append_executive_summary(lines, report)
    _append_assessment(lines, report)
    _append_subsystems(lines, report)
    _append_scenarios(lines, report)
    _append_findings(lines, report)
    _append_evidence_and_engineering(lines, report)
    _append_gaps(lines, report)
    return "\n".join(lines) + "\n"
