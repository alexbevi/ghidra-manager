"""Deterministic ledger seeding and advisory review-queue generation."""

from __future__ import annotations

from collections import Counter, defaultdict, deque
from typing import Any

from ghidra_manager.coverage.model import (
    LEDGER_SCHEMA,
    REVIEW_QUEUE_SCHEMA,
    SCHEMA_VERSION,
    with_content_id,
)

AUTOMATED_STATUSES = {"unknown", "partial"}
SUBSYSTEM_PATTERNS = (
    ("puzzles", ("/puzzles/", "puzzle")),
    ("wac", ("/wac", "wac")),
    ("cyber", ("/cyber", "cyber")),
    ("combat", ("/combat", "combat")),
    ("inventory", ("/inventory", "inventory")),
    ("media", ("/media", "/iavf", "media", "video", "audio")),
    ("save-restore", ("/saveload", "save", "restore")),
    ("scripts", ("/script", "script")),
    ("scene-actions", ("/scene_dispatcher", "sceneaction")),
)


def _address_key(value: object) -> str | None:
    if not isinstance(value, dict):
        return None
    space = value.get("space")
    offset = value.get("offset")
    if not isinstance(space, str) or not isinstance(offset, str):
        return None
    try:
        normalized = int(offset, 16)
    except ValueError:
        return None
    return f"{space}:{normalized:08x}"


def _reachable_functions(snapshot: dict[str, Any]) -> set[str]:
    functions_by_address = {
        key: str(function["id"])
        for function in snapshot.get("functions", [])
        if isinstance(function, dict)
        and isinstance(function.get("id"), str)
        and (key := _address_key(function.get("address"))) is not None
    }
    roots = {
        function_id
        for entry in snapshot.get("entry_points", [])
        if isinstance(entry, dict)
        and (key := _address_key(entry.get("address"))) is not None
        and (function_id := functions_by_address.get(key)) is not None
    }
    for declared in snapshot.get("declared_roots", []):
        if not isinstance(declared, dict):
            continue
        value = declared.get("function_id") or declared.get("id")
        if isinstance(value, str):
            roots.add(value)
    adjacency: dict[str, set[str]] = defaultdict(set)
    for edge in snapshot.get("call_graph", []):
        if not isinstance(edge, dict):
            continue
        caller = edge.get("caller")
        callee = edge.get("callee")
        if isinstance(caller, str) and isinstance(callee, str):
            adjacency[caller].add(callee)
    reachable = set(roots)
    frontier = deque(sorted(roots))
    while frontier:
        caller = frontier.popleft()
        for callee in sorted(adjacency.get(caller, ())):
            if callee not in reachable:
                reachable.add(callee)
                frontier.append(callee)
    return reachable


def _declared_reachability(snapshot: dict[str, Any]) -> dict[str, str]:
    result: dict[str, str] = {}
    for edge in snapshot.get("declared_edges", []):
        if not isinstance(edge, dict):
            continue
        target = edge.get("target") or edge.get("callee") or edge.get("to")
        kind = edge.get("kind")
        if not isinstance(target, str):
            continue
        result[target] = "data_driven" if kind == "data_driven" else "declared_indirect"
    return result


def _subsystem(name: str, paths: set[str]) -> str:
    searchable = " ".join([name.lower(), *(path.lower() for path in sorted(paths))])
    for subsystem, patterns in SUBSYSTEM_PATTERNS:
        if any(pattern in searchable for pattern in patterns):
            return subsystem
    return "unassigned"


def _implementation_paths(facts: list[dict[str, Any]]) -> set[str]:
    return {
        str(target["path"])
        for fact in facts
        for target in fact.get("implementation_targets", [])
        if isinstance(target, dict) and isinstance(target.get("path"), str)
    }


def _function_candidate(
    function: dict[str, Any],
    facts: list[dict[str, Any]],
    *,
    diagnostic_paths: set[str],
    reachable: set[str],
    declared_reachability: dict[str, str],
) -> tuple[dict[str, Any], dict[str, Any]]:
    identifier = str(function["id"])
    fact_kinds = Counter(str(fact.get("kind")) for fact in facts)
    implementation_paths = _implementation_paths(facts)
    precise_facts = [fact for fact in facts if fact.get("kind") == "source_anchor"]
    precise_paths = _implementation_paths(precise_facts)
    diagnostic_overlap = sorted(precise_paths & diagnostic_paths)
    linked_diagnostic = bool(fact_kinds["diagnostic"])
    if identifier in reachable:
        reachability = "direct_static"
    else:
        reachability = declared_reachability.get(identifier, "unknown")
    evidence_ids = sorted(
        str(fact["id"]) for fact in facts if isinstance(fact.get("id"), str)
    )
    subsystem = _subsystem(
        str(function.get("name", "")),
        precise_paths or implementation_paths,
    )
    record: dict[str, Any] = {
        "id": identifier,
        "kind": "function",
        "subsystem": subsystem,
        "scope": {
            "state": "unreviewed",
            "category": None,
            "reason": None,
        },
        "status": "unknown",
        "verification": {"state": "unverified", "records": []},
        "evidence": evidence_ids,
        "reachability": reachability,
        "priority": 0,
        "critical_progression": False,
        "known_missing": [],
        "notes": None,
        "original": {
            "name": function.get("name"),
            "address": function.get("address"),
            "instruction_count": function.get("instruction_count"),
        },
    }
    reasons: list[str] = []
    priority = 0
    if fact_kinds["source_anchor"]:
        reasons.append("exact source anchor")
        priority += 20
    if fact_kinds["commit_anchor"]:
        reasons.append("commit anchor")
        priority += 15
    if fact_kinds["architecture_anchor"]:
        reasons.append("architecture anchor")
        priority += 5
    if linked_diagnostic:
        reasons.append("unsupported diagnostic explicitly linked to this function")
        priority += 25
    elif diagnostic_overlap:
        reasons.append("unsupported diagnostic in the same source file requires review")
        priority += 10
    if reachability == "direct_static":
        reasons.append("reachable from a configured entry point in the static call graph")
        priority += 10
    elif reachability in {"data_driven", "declared_indirect"}:
        reasons.append(f"{reachability.replace('_', ' ')} relationship declared")
        priority += 8
    suggested_scope = "in_scope" if evidence_ids else "unreviewed"
    suggested_status = "partial" if linked_diagnostic else "unknown"
    confidence = (
        "high"
        if fact_kinds["source_anchor"] and fact_kinds["commit_anchor"]
        else "medium"
        if evidence_ids
        else "low"
    )
    queue: dict[str, Any] = {
        "record_id": identifier,
        "kind": "function",
        "subsystem": subsystem,
        "suggested_scope": suggested_scope,
        "suggested_status": suggested_status,
        "confidence": confidence,
        "priority": priority,
        "reasons": reasons or ["no reimplementation evidence linked"],
        "evidence_summary": dict(sorted(fact_kinds.items())),
        "implementation_paths": sorted(implementation_paths),
        "diagnostic_paths": diagnostic_overlap,
        "reachability": reachability,
    }
    return record, queue


def _behavioral_candidate(unit: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    identifier = str(unit["id"])
    subsystem = str(unit.get("subsystem", "unassigned"))
    unit_type = str(unit.get("unit_type", "registry"))
    critical_progression = bool(unit.get("critical_progression"))
    record: dict[str, Any] = {
        "id": identifier,
        "kind": "behavioral_unit",
        "unit_type": unit_type,
        "subsystem": subsystem,
        "scope": {
            "state": "unreviewed",
            "category": None,
            "reason": None,
        },
        "status": "unknown",
        "verification": {"state": "unverified", "records": []},
        "evidence": [],
        "reachability": "data_driven",
        "priority": 0,
        "critical_progression": critical_progression,
        "player_impact": unit.get("player_impact"),
        "known_missing": [],
        "deviations": [],
        "notes": None,
        "original": {
            "label": unit.get("label"),
            "provider": unit.get("provider"),
            "source": unit.get("source"),
        },
    }
    queue: dict[str, Any] = {
        "record_id": identifier,
        "kind": "behavioral_unit",
        "subsystem": subsystem,
        "suggested_scope": "in_scope",
        "suggested_status": "unknown",
        "confidence": "medium",
        "priority": 30 if critical_progression else 20 if unit_type == "scenario" else 15,
        "reasons": [
            "explicit player-visible scenario"
            if unit_type == "scenario"
            else "explicit ScummVM behavioral registry entry"
        ],
        "evidence_summary": {},
        "implementation_paths": [],
        "diagnostic_paths": [],
        "reachability": "data_driven",
    }
    return record, queue


def build_seed(
    profile: dict[str, Any],
    ledger: dict[str, Any],
    snapshot: dict[str, Any],
    evidence: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, int]]:
    """Add missing unreviewed records and generate advisory review candidates."""
    facts_by_function: dict[str, list[dict[str, Any]]] = defaultdict(list)
    diagnostic_paths: set[str] = set()
    for raw_fact in evidence.get("facts", []):
        if not isinstance(raw_fact, dict):
            continue
        if raw_fact.get("kind") == "diagnostic":
            diagnostic_paths.update(_implementation_paths([raw_fact]))
        for target in raw_fact.get("original_targets", []):
            if isinstance(target, str):
                facts_by_function[target].append(raw_fact)
    reachable = _reachable_functions(snapshot)
    declared_reachability = _declared_reachability(snapshot)
    generated_records: dict[str, dict[str, Any]] = {}
    generated_queue: dict[str, dict[str, Any]] = {}
    for function in snapshot.get("functions", []):
        if not isinstance(function, dict) or not isinstance(function.get("id"), str):
            continue
        record, candidate = _function_candidate(
            function,
            facts_by_function.get(str(function["id"]), []),
            diagnostic_paths=diagnostic_paths,
            reachable=reachable,
            declared_reachability=declared_reachability,
        )
        generated_records[str(record["id"])] = record
        generated_queue[str(record["id"])] = candidate
    for unit in evidence.get("behavioral_units", []):
        if not isinstance(unit, dict) or not isinstance(unit.get("id"), str):
            continue
        record, candidate = _behavioral_candidate(unit)
        generated_records[str(record["id"])] = record
        generated_queue[str(record["id"])] = candidate
    existing = {
        str(record["id"]): record
        for record in ledger.get("records", [])
        if isinstance(record, dict) and isinstance(record.get("id"), str)
    }
    added = 0
    refreshed = 0
    preserved = 0
    merged: dict[str, dict[str, Any]] = {}
    for identifier, generated in generated_records.items():
        current = existing.get(identifier)
        if current is None:
            merged[identifier] = generated
            added += 1
            continue
        current_scope = current.get("scope", {})
        if isinstance(current_scope, dict) and current_scope.get("state") == "unreviewed":
            updated = dict(current)
            updated["evidence"] = list(generated.get("evidence", []))
            if current.get("reachability", "unknown") == "unknown":
                updated["reachability"] = generated["reachability"]
            if current.get("subsystem") in {None, "", "unassigned"}:
                updated["subsystem"] = generated["subsystem"]
            merged[identifier] = updated
            refreshed += 1
        else:
            merged[identifier] = current
            preserved += 1
    for identifier, current in existing.items():
        if identifier not in merged:
            merged[identifier] = current
            preserved += 1
    queue_candidates = [
        candidate
        for identifier, candidate in generated_queue.items()
        if merged[identifier].get("scope", {}).get("state") == "unreviewed"
    ]
    queue_candidates.sort(
        key=lambda candidate: (-int(candidate["priority"]), str(candidate["record_id"]))
    )
    if any(
        candidate["suggested_status"] not in AUTOMATED_STATUSES
        for candidate in queue_candidates
    ):
        raise AssertionError("Automated review queue proposed an authoritative status")
    seeded_ledger = {
        "schema": LEDGER_SCHEMA,
        "version": SCHEMA_VERSION,
        "profile_id": ledger["profile_id"],
        "records": [merged[key] for key in sorted(merged)],
    }
    queue: dict[str, Any] = {
        "schema": REVIEW_QUEUE_SCHEMA,
        "version": SCHEMA_VERSION,
        "profile_id": profile["id"],
        "snapshot_id": snapshot["snapshot_id"],
        "evidence_scan_id": evidence["scan_id"],
        "policy": {
            "advisory_only": True,
            "never_suggests": [
                "complete",
                "equivalent",
                "not_applicable",
                "verified",
            ],
        },
        "candidates": queue_candidates,
    }
    queue = with_content_id(queue, "queue_id")
    summary = {
        "added_records": added,
        "refreshed_unreviewed_records": refreshed,
        "preserved_records": preserved,
        "review_candidates": len(queue_candidates),
        "linked_functions": sum(bool(record["evidence"]) for record in generated_records.values()),
        "partial_suggestions": sum(
            candidate["suggested_status"] == "partial"
            for candidate in queue_candidates
        ),
    }
    return seeded_ledger, queue, summary
