"""Deterministic coverage-report comparison and Markdown rendering."""

from __future__ import annotations

from typing import Any

from ghidra_manager.coverage.model import (
    DIFF_SCHEMA,
    SCHEMA_VERSION,
    with_content_id,
)

IMPLEMENTED = {"complete", "equivalent"}
GAPS = {"missing", "partial", "unknown"}
VERIFICATION_RANK = {
    "unverified": 0,
    "static_verified": 1,
    "test_verified": 2,
    "runtime_verified": 3,
    "retail_parity_tested": 4,
}


def _change_details(
    identifiers: list[str],
    records: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    return [
        {
            "id": identifier,
            "label": records[identifier].get("label", identifier),
            "kind": records[identifier].get("kind"),
            "unit_type": records[identifier].get("unit_type"),
            "subsystem": records[identifier].get("subsystem", "unassigned"),
            "status": records[identifier].get("status"),
            "verification": records[identifier].get("verification"),
            "critical_progression": bool(
                records[identifier].get("critical_progression")
            ),
            "player_impact": records[identifier].get("player_impact"),
        }
        for identifier in identifiers
    ]


def build_diff(base: dict[str, Any], head: dict[str, Any]) -> dict[str, Any]:
    """Compare two canonical reports without inferring unreviewed gaps."""
    base_records = {
        str(item["id"]): item for item in base.get("classifications", [])
    }
    head_records = {
        str(item["id"]): item for item in head.get("classifications", [])
    }
    added = sorted(head_records.keys() - base_records.keys())
    removed = sorted(base_records.keys() - head_records.keys())
    resolved: list[str] = []
    reopened: list[str] = []
    reclassified: list[str] = []
    verification_changed: list[str] = []
    verification_upgraded: list[str] = []
    verification_downgraded: list[str] = []
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
            before_rank = VERIFICATION_RANK.get(str(before.get("verification")), 0)
            after_rank = VERIFICATION_RANK.get(str(after.get("verification")), 0)
            if after_rank > before_rank:
                verification_upgraded.append(identifier)
            elif after_rank < before_rank:
                verification_downgraded.append(identifier)
        if (
            before.get("evidence") != after.get("evidence")
            and before_status == after_status
            and before.get("scope") == after.get("scope")
            and before.get("verification") == after.get("verification")
        ):
            evidence_only.append(identifier)

    added_gaps = [
        identifier
        for identifier in added
        if head_records[identifier].get("scope") == "in_scope"
        and head_records[identifier].get("status") in {"missing", "partial"}
    ]
    all_records = {**base_records, **head_records}
    critical_changes = [
        identifier
        for identifier in sorted(
            set(added)
            | set(removed)
            | set(resolved)
            | set(reopened)
            | set(reclassified)
            | set(verification_changed)
        )
        if all_records[identifier].get("critical_progression")
    ]
    result: dict[str, Any] = {
        "schema": DIFF_SCHEMA,
        "version": SCHEMA_VERSION,
        "base_report_id": base["report_id"],
        "head_report_id": head["report_id"],
        "base_revision": base["inputs"]["repository_revision"],
        "head_revision": head["inputs"]["repository_revision"],
        "changes": {
            "added": added,
            "added_gaps": added_gaps,
            "removed": removed,
            "resolved": resolved,
            "reopened": reopened,
            "reclassified": reclassified,
            "verification_changed": verification_changed,
            "verification_upgraded": verification_upgraded,
            "verification_downgraded": verification_downgraded,
            "evidence_only": evidence_only,
        },
        "player_facing": {
            "newly_covered": _change_details(resolved, head_records),
            "regressions": _change_details(reopened, head_records),
            "new_gaps": _change_details(added_gaps, head_records),
            "verification_upgrades": _change_details(
                verification_upgraded, head_records
            ),
            "verification_downgrades": _change_details(
                verification_downgraded, head_records
            ),
            "critical_changes": _change_details(critical_changes, all_records),
        },
    }
    return with_content_id(result, "diff_id")


def markdown_diff(value: dict[str, Any]) -> str:
    """Render a coverage diff with player-visible changes before audit detail."""
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
        f"- Verification upgrades: {len(changes['verification_upgraded'])}",
        f"- Verification downgrades: {len(changes['verification_downgraded'])}",
        f"- Evidence-only changes: {len(changes['evidence_only'])}",
        "",
        "## Player-Visible Changes",
        "",
    ]
    player_facing = value["player_facing"]
    sections = (
        ("newly_covered", "Newly covered behavior"),
        ("regressions", "Regressions or reopened gaps"),
        ("new_gaps", "New reviewed gaps"),
        ("verification_upgrades", "Verification upgrades"),
        ("verification_downgrades", "Verification downgrades"),
    )
    any_changes = False
    for key, heading in sections:
        items = player_facing[key]
        if not items:
            continue
        any_changes = True
        lines.extend([f"### {heading}", ""])
        for item in items:
            critical = "; critical progression" if item["critical_progression"] else ""
            impact = f"; {item['player_impact']}" if item["player_impact"] else ""
            lines.append(
                f"- **{item['label']}** (`{item['id']}`): "
                f"{item['status']}; verification={item['verification']}"
                f"{critical}{impact}"
            )
        lines.append("")
    if not any_changes:
        lines.extend(["No reviewed player-visible coverage changes.", ""])
    if player_facing["critical_changes"]:
        lines.extend(
            [
                "## Critical Progression Changes",
                "",
                *[
                    f"- **{item['label']}** (`{item['id']}`): "
                    f"{item['status']}; verification={item['verification']}"
                    for item in player_facing["critical_changes"]
                ],
                "",
            ]
        )
    return "\n".join(lines)
