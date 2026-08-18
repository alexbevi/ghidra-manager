#!/usr/bin/env python3
"""Validate durable state for a Ghidra decompilation campaign."""

from __future__ import annotations

import json
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
        if document.get("schema_version") != 1:
            errors.append(f"{name}: unsupported schema_version")

    ghidra = project.get("ghidra")
    if not isinstance(ghidra, dict) or not ghidra.get("project") or not ghidra.get(
        "program"
    ):
        errors.append("project.json: ghidra.project and ghidra.program are required")

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
