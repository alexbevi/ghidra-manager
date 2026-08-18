#!/usr/bin/env python3
"""Validate durable state for a Ghidra decompilation campaign."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

REQUIRED_FILES = {
    "project.json",
    "progress.json",
    "tasks.json",
    "evidence.jsonl",
    "renames.jsonl",
    "ARCHITECTURE.md",
}
TASK_STATUSES = {
    "pending",
    "leased",
    "complete",
    "blocked",
    "needs-verification",
    "cancelled",
}
AUTHORITIES = {"read-only", "propose-only", "exclusive bounded mutation"}
SUPPORTED_SCHEMA_VERSIONS = {1, 2}
FIDELITY_STATUSES = {"pending", "ready", "blocked"}
CAMPAIGN_PROFILES = {"symbol-recovery", "reimplementation"}
BEHAVIOR_STATUSES = {
    "draft",
    "evidenced",
    "ready-for-implementation",
    "implemented",
    "verified",
}
BEHAVIOR_VERIFICATION = {"unverified", "static", "runtime-observed", "replay-matched"}
CONFIDENCE_LEVELS = {"low", "medium", "high"}
COVERAGE_STATUSES = {
    "complete",
    "partial",
    "equivalent",
    "missing",
    "not_applicable",
    "unknown",
}
REACHABILITY_STATUSES = {"reachable", "not_reachable", "unknown"}
REVIEW_STATES = {"proposed", "reviewed", "superseded"}
RUNTIME_COMPARISON_STATUSES = {
    "retail-observed",
    "matched",
    "mismatched",
    "inconclusive",
}
RESOURCE_STATUSES = {"discovered", "catalogued", "traced", "unresolved", "superseded"}
TARGET_KINDS = {"generic", "scummvm"}
MAPPING_STRATEGIES = {
    "faithful",
    "portable-equivalent",
    "intentional-deviation",
    "unimplemented",
}
MAPPING_STATUSES = {"draft", "ready", "implemented", "verified", "superseded"}
SHA256_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must contain a JSON object")
    return value


def validate_jsonl(path: Path, required: set[str]) -> list[str]:
    errors: list[str] = []
    seen: set[str] = set()
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            errors.append(f"{path.name}:{line_number}: invalid JSON: {exc.msg}")
            continue
        if not isinstance(value, dict):
            errors.append(f"{path.name}:{line_number}: expected object")
            continue
        missing = required - value.keys()
        if missing:
            errors.append(
                f"{path.name}:{line_number}: missing {', '.join(sorted(missing))}"
            )
        record_id = value.get("id")
        if isinstance(record_id, str):
            if record_id in seen:
                errors.append(f"{path.name}:{line_number}: duplicate id {record_id}")
            seen.add(record_id)
    return errors


def validate_derived_programs(root: Path, project: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    entries = project.get("derived_programs")
    if not isinstance(entries, list):
        return ["project.json: derived_programs must be an array"]
    if entries and not (root / "artifacts").is_dir():
        errors.append("project.json: derived programs require an artifacts directory")

    seen: set[str] = set()
    required = {
        "id",
        "role",
        "source_digest",
        "digest",
        "path",
        "ghidra_program_path",
        "size",
        "format",
        "language",
        "transform",
        "address_mapping",
        "validation",
    }
    for index, entry in enumerate(entries):
        prefix = f"project.json:derived_programs[{index}]"
        if not isinstance(entry, dict):
            errors.append(f"{prefix}: expected object")
            continue
        missing = required - entry.keys()
        if missing:
            errors.append(f"{prefix}: missing {', '.join(sorted(missing))}")
        entry_id = entry.get("id")
        if not isinstance(entry_id, str) or not entry_id:
            errors.append(f"{prefix}: id is required")
        elif entry_id in seen:
            errors.append(f"{prefix}: duplicate id {entry_id}")
        else:
            seen.add(entry_id)
        for field in ("source_digest", "digest"):
            value = entry.get(field)
            if not isinstance(value, str) or not SHA256_PATTERN.fullmatch(value):
                errors.append(f"{prefix}: {field} must be sha256:<64 lowercase hex>")
        transform = entry.get("transform")
        if not isinstance(transform, dict) or not transform.get("tool"):
            errors.append(f"{prefix}: transform.tool is required")
        elif not transform.get("version") and not transform.get("source_commit"):
            errors.append(f"{prefix}: transform needs immutable version or source_commit")
        if isinstance(transform, dict) and not isinstance(transform.get("arguments"), list):
            errors.append(f"{prefix}: transform.arguments must be an array")
    return errors


def validate_behaviors(path: Path) -> list[str]:
    required = {
        "id",
        "title",
        "program",
        "retail_roots",
        "trigger",
        "state_reads",
        "state_writes",
        "control_flow",
        "resources",
        "timing_and_ownership",
        "side_effects",
        "error_and_fallback_paths",
        "evidence_ids",
        "confidence",
        "verification",
        "status",
        "unresolved",
        "source_task",
        "timestamp",
    }
    errors = validate_jsonl(path, required)
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(record, dict):
            continue
        prefix = f"{path.name}:{line_number}"
        if record.get("status") not in BEHAVIOR_STATUSES:
            errors.append(f"{prefix}: invalid behavior status {record.get('status')!r}")
        if record.get("verification") not in BEHAVIOR_VERIFICATION:
            errors.append(
                f"{prefix}: invalid behavior verification {record.get('verification')!r}"
            )
        if record.get("confidence") not in CONFIDENCE_LEVELS:
            errors.append(f"{prefix}: invalid confidence {record.get('confidence')!r}")
        roots = record.get("retail_roots")
        if not isinstance(roots, list) or not roots:
            errors.append(f"{prefix}: retail_roots must be a non-empty array")
        trigger = record.get("trigger")
        if not isinstance(trigger, dict) or not trigger.get("route"):
            errors.append(f"{prefix}: trigger.route is required")
    return errors


def validate_coverage(path: Path) -> list[str]:
    dimensions = ("reusable_interpreter", "implementation", "semantic_parity")
    required = {
        "id",
        "behavior_id",
        "scope",
        "shipped_data_reachability",
        *dimensions,
        "review_state",
        "confidence",
        "reviewed_by",
        "timestamp",
    }
    errors = validate_jsonl(path, required)
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(record, dict):
            continue
        prefix = f"{path.name}:{line_number}"
        reachability = record.get("shipped_data_reachability")
        if not isinstance(reachability, dict) or reachability.get(
            "status"
        ) not in REACHABILITY_STATUSES:
            errors.append(f"{prefix}: invalid shipped-data reachability")
        for dimension in dimensions:
            value = record.get(dimension)
            if not isinstance(value, dict) or value.get("status") not in COVERAGE_STATUSES:
                errors.append(f"{prefix}: invalid {dimension} status")
        if record.get("review_state") not in REVIEW_STATES:
            errors.append(f"{prefix}: invalid review_state")
        if record.get("confidence") not in CONFIDENCE_LEVELS:
            errors.append(f"{prefix}: invalid confidence {record.get('confidence')!r}")
        if not isinstance(record.get("scope"), dict):
            errors.append(f"{prefix}: scope must be an object")
    return errors


def validate_runtime(path: Path) -> list[str]:
    required = {
        "id",
        "behavior_id",
        "route",
        "retail",
        "target",
        "comparison",
        "evidence_ids",
        "review_state",
        "timestamp",
    }
    errors = validate_jsonl(path, required)
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(record, dict):
            continue
        prefix = f"{path.name}:{line_number}"
        route = record.get("route")
        if not isinstance(route, dict) or not isinstance(route.get("steps"), list):
            errors.append(f"{prefix}: route.steps must be an array")
        elif not route["steps"]:
            errors.append(f"{prefix}: route.steps must not be empty")
        retail = record.get("retail")
        if not isinstance(retail, dict) or not isinstance(retail.get("observations"), list):
            errors.append(f"{prefix}: retail.observations must be an array")
        comparison = record.get("comparison")
        if not isinstance(comparison, dict):
            errors.append(f"{prefix}: comparison must be an object")
            continue
        status = comparison.get("status")
        if status not in RUNTIME_COMPARISON_STATUSES:
            errors.append(f"{prefix}: invalid runtime comparison status")
        if status in {"matched", "mismatched"} and not isinstance(record.get("target"), dict):
            errors.append(f"{prefix}: {status} comparison requires a target observation")
        if record.get("review_state") not in REVIEW_STATES:
            errors.append(f"{prefix}: invalid review_state")
    return errors


def validate_resources(path: Path) -> list[str]:
    root_fields = ("parser_roots", "dispatcher_roots", "consumer_roots")
    required = {
        "id",
        "data_set",
        "canonical_id",
        "kind",
        "container",
        "member",
        "digest",
        "dispatch_values",
        *root_fields,
        "reachability",
        "evidence_ids",
        "status",
        "source_task",
        "timestamp",
    }
    errors = validate_jsonl(path, required)
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(record, dict):
            continue
        prefix = f"{path.name}:{line_number}"
        if record.get("status") not in RESOURCE_STATUSES:
            errors.append(f"{prefix}: invalid resource status")
        if not isinstance(record.get("canonical_id"), str) or not record["canonical_id"]:
            errors.append(f"{prefix}: canonical_id is required")
        digest = record.get("digest")
        if digest is not None and (
            not isinstance(digest, str) or not SHA256_PATTERN.fullmatch(digest)
        ):
            errors.append(f"{prefix}: digest must be null or sha256:<64 lowercase hex>")
        reachability = record.get("reachability")
        if not isinstance(reachability, dict) or reachability.get(
            "status"
        ) not in REACHABILITY_STATUSES:
            errors.append(f"{prefix}: invalid resource reachability")
        roots: list[object] = []
        for field in root_fields:
            value = record.get(field)
            if not isinstance(value, list):
                errors.append(f"{prefix}: {field} must be an array")
            else:
                roots.extend(value)
        if record.get("status") == "traced" and not roots:
            errors.append(f"{prefix}: traced resource requires a program root")
    return errors


def validate_mappings(path: Path) -> list[str]:
    required = {
        "id",
        "behavior_id",
        "target",
        "retail_contract",
        "strategy",
        "service_substitutions",
        "retained_engine_semantics",
        "validation",
        "evidence_ids",
        "confidence",
        "status",
        "source_task",
        "timestamp",
    }
    errors = validate_jsonl(path, required)
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(record, dict):
            continue
        prefix = f"{path.name}:{line_number}"
        target = record.get("target")
        if not isinstance(target, dict) or target.get("kind") not in TARGET_KINDS:
            errors.append(f"{prefix}: invalid mapping target")
        elif not isinstance(target.get("paths"), list) or not isinstance(
            target.get("symbols"), list
        ):
            errors.append(f"{prefix}: target paths and symbols must be arrays")
        if record.get("strategy") not in MAPPING_STRATEGIES:
            errors.append(f"{prefix}: invalid mapping strategy")
        if record.get("status") not in MAPPING_STATUSES:
            errors.append(f"{prefix}: invalid mapping status")
        if record.get("confidence") not in CONFIDENCE_LEVELS:
            errors.append(f"{prefix}: invalid confidence {record.get('confidence')!r}")
        validation = record.get("validation")
        if not isinstance(validation, dict):
            errors.append(f"{prefix}: validation must be an object")
    return errors


def validate(root: Path) -> list[str]:
    errors: list[str] = []
    missing = REQUIRED_FILES - {path.name for path in root.iterdir()}
    if missing:
        errors.append(f"missing files: {', '.join(sorted(missing))}")
        return errors

    project = load_json(root / "project.json")
    progress = load_json(root / "progress.json")
    tasks_doc = load_json(root / "tasks.json")
    for name, document in (
        ("project.json", project),
        ("progress.json", progress),
        ("tasks.json", tasks_doc),
    ):
        if document.get("schema_version") not in SUPPORTED_SCHEMA_VERSIONS:
            errors.append(f"{name}: unsupported schema_version")

    ghidra = project.get("ghidra")
    if not isinstance(ghidra, dict) or not ghidra.get("project") or not ghidra.get(
        "program"
    ):
        errors.append("project.json: ghidra.project and ghidra.program are required")

    if project.get("schema_version") == 2:
        if project.get("profile") not in CAMPAIGN_PROFILES:
            errors.append("project.json: invalid or missing campaign profile")
        target = project.get("target")
        if project.get("profile") == "symbol-recovery" and target is not None:
            errors.append("project.json: symbol-recovery target must be null")
        if project.get("profile") == "reimplementation" and (
            not isinstance(target, dict) or target.get("kind") not in TARGET_KINDS
        ):
            errors.append("project.json: reimplementation target is required")
        errors.extend(validate_derived_programs(root, project))
        if not (root / "artifacts").is_dir():
            errors.append("missing directory: artifacts")
        fidelity = progress.get("analysis_fidelity")
        if not isinstance(fidelity, dict):
            errors.append("progress.json: analysis_fidelity must be an object")
        elif fidelity.get("status") not in FIDELITY_STATUSES:
            errors.append("progress.json: invalid analysis_fidelity status")
        behaviors_path = root / "behaviors.jsonl"
        if not behaviors_path.is_file():
            errors.append("missing file: behaviors.jsonl")
        else:
            errors.extend(validate_behaviors(behaviors_path))
        coverage_path = root / "coverage.jsonl"
        if not coverage_path.is_file():
            errors.append("missing file: coverage.jsonl")
        else:
            errors.extend(validate_coverage(coverage_path))
        runtime_path = root / "runtime.jsonl"
        if not runtime_path.is_file():
            errors.append("missing file: runtime.jsonl")
        else:
            errors.extend(validate_runtime(runtime_path))
        if not (root / "traces").is_dir():
            errors.append("missing directory: traces")
        resources_path = root / "resources.jsonl"
        if not resources_path.is_file():
            errors.append("missing file: resources.jsonl")
        else:
            errors.extend(validate_resources(resources_path))
        mappings_path = root / "mappings.jsonl"
        if not mappings_path.is_file():
            errors.append("missing file: mappings.jsonl")
        else:
            errors.extend(validate_mappings(mappings_path))

    tasks = tasks_doc.get("tasks")
    if not isinstance(tasks, list):
        errors.append("tasks.json: tasks must be an array")
        tasks = []
    task_ids: set[str] = set()
    for index, task in enumerate(tasks):
        prefix = f"tasks.json:tasks[{index}]"
        if not isinstance(task, dict):
            errors.append(f"{prefix}: expected object")
            continue
        task_id = task.get("id")
        if not isinstance(task_id, str) or not task_id:
            errors.append(f"{prefix}: id is required")
        elif task_id in task_ids:
            errors.append(f"{prefix}: duplicate id {task_id}")
        else:
            task_ids.add(task_id)
        if task.get("status") not in TASK_STATUSES:
            errors.append(f"{prefix}: invalid status {task.get('status')!r}")
        if task.get("authority") not in AUTHORITIES:
            errors.append(f"{prefix}: invalid authority {task.get('authority')!r}")

    for index, task in enumerate(tasks):
        if not isinstance(task, dict):
            continue
        for dependency in task.get("depends_on", []):
            if dependency not in task_ids:
                errors.append(
                    f"tasks.json:tasks[{index}]: unknown dependency {dependency}"
                )

    lease = progress.get("active_mutation_lease")
    if lease is not None and (
        not isinstance(lease, dict) or not lease.get("lease_owner")
    ):
        errors.append("progress.json: active mutation lease needs lease_owner")

    errors.extend(
        validate_jsonl(
            root / "evidence.jsonl", {"id", "category", "addresses", "claim"}
        )
    )
    errors.extend(
        validate_jsonl(
            root / "renames.jsonl",
            {
                "id",
                "batch_id",
                "kind",
                "address",
                "old_name",
                "new_name",
                "confidence",
                "evidence_ids",
                "state",
            },
        )
    )
    if not (root / "ARCHITECTURE.md").read_text(encoding="utf-8").strip():
        errors.append("ARCHITECTURE.md: file is empty")
    return errors


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: validate_project.py <state-dir>", file=sys.stderr)
        return 2
    root = Path(sys.argv[1]).expanduser().resolve()
    if not root.is_dir():
        print(f"error: not a directory: {root}", file=sys.stderr)
        return 2
    try:
        errors = validate(root)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"valid campaign: {root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
