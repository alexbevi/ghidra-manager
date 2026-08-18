#!/usr/bin/env python3
"""Render a deterministic Markdown summary of a decompilation campaign."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import Any

from validate_project import load_json, validate


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("state_dir", type=Path)
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if not path.is_file():
        return records
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        value = json.loads(line)
        if isinstance(value, dict):
            records.append(value)
    return records


def count_by(
    records: list[dict[str, Any]],
    getter: Callable[[dict[str, Any]], object],
) -> Counter[str]:
    return Counter(str(value) for record in records if (value := getter(record)) is not None)


def render_counts(counts: Counter[str]) -> list[str]:
    if not counts:
        return ["- None recorded."]
    return [f"- `{key}`: {counts[key]}" for key in sorted(counts)]


def current_coverage(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    current: dict[str, dict[str, Any]] = {}
    for record in records:
        behavior_id = record.get("behavior_id")
        if not isinstance(behavior_id, str):
            continue
        if record.get("review_state") == "superseded":
            current.pop(behavior_id, None)
        elif record.get("review_state") == "reviewed":
            current[behavior_id] = record
    return [current[key] for key in sorted(current)]


def nested_status(record: dict[str, Any], field: str) -> object:
    value = record.get(field)
    return value.get("status") if isinstance(value, dict) else None


def count_nested(records: list[dict[str, Any]], field: str) -> Counter[str]:
    def get_status(record: dict[str, Any]) -> object:
        return nested_status(record, field)

    return count_by(records, get_status)


def render(root: Path) -> str:
    project = load_json(root / "project.json")
    progress = load_json(root / "progress.json")
    tasks_doc = load_json(root / "tasks.json")
    behaviors = read_jsonl(root / "behaviors.jsonl")
    coverage = current_coverage(read_jsonl(root / "coverage.jsonl"))
    runtime = read_jsonl(root / "runtime.jsonl")
    resources = read_jsonl(root / "resources.jsonl")
    mappings = read_jsonl(root / "mappings.jsonl")

    ghidra = project.get("ghidra", {})
    target = project.get("target")
    fidelity = progress.get("analysis_fidelity", {})
    tasks = tasks_doc.get("tasks", [])
    lines = [
        f"# Campaign Report: {ghidra.get('program', 'unknown')}",
        "",
        "## Identity",
        "",
        f"- Campaign: `{project.get('campaign_slug', 'unknown')}`",
        f"- Profile: `{project.get('profile', 'legacy')}`",
        f"- Ghidra project: `{ghidra.get('project', 'unknown')}`",
        f"- Program path: `{ghidra.get('program_path', 'unknown')}`",
        f"- Binary digest: `{ghidra.get('digest') or 'unknown'}`",
    ]
    if isinstance(target, dict):
        lines.extend(
            [
                f"- Target: `{target.get('kind', 'unknown')}`",
                f"- Target revision: `{target.get('revision') or 'unrecorded'}`",
            ]
        )
    lines.extend(
        [
            "",
            "## Analysis fidelity",
            "",
            f"- Status: `{fidelity.get('status', 'legacy')}`",
            f"- Semantic program: `{fidelity.get('semantic_program') or 'unrecorded'}`",
            f"- Derived programs: {len(project.get('derived_programs', []))}",
            "",
            "## Behavior inventory",
            "",
            *render_counts(count_by(behaviors, lambda record: record.get("status"))),
            "",
            "## Shipped-data reachability",
            "",
            *render_counts(
                count_by(
                    coverage,
                    lambda record: nested_status(record, "shipped_data_reachability"),
                )
            ),
        ]
    )
    for title, field in (
        ("Reusable interpreter", "reusable_interpreter"),
        ("Implementation", "implementation"),
        ("Semantic parity", "semantic_parity"),
    ):
        lines.extend(
            [
                "",
                f"## {title}",
                "",
                *render_counts(count_nested(coverage, field)),
            ]
        )

    gaps = [
        record
        for record in coverage
        if nested_status(record, "shipped_data_reachability") == "reachable"
        and nested_status(record, "implementation") in {"missing", "partial", "unknown"}
    ]
    lines.extend(["", "## Reachable implementation gaps", ""])
    if gaps:
        for record in gaps:
            status = nested_status(record, "implementation")
            lines.append(f"- `{record.get('behavior_id')}`: `{status}`")
    else:
        lines.append("- None recorded.")

    lines.extend(
        [
            "",
            "## Runtime comparisons",
            "",
            *render_counts(
                count_by(runtime, lambda record: nested_status(record, "comparison"))
            ),
            "",
            "## Resource graph",
            "",
            *render_counts(
                count_by(resources, lambda record: nested_status(record, "reachability"))
            ),
            "",
            "## Target mappings",
            "",
            *render_counts(count_by(mappings, lambda record: record.get("status"))),
            "",
            "## Task state",
            "",
            *render_counts(
                count_by(
                    [task for task in tasks if isinstance(task, dict)],
                    lambda record: record.get("status"),
                )
            ),
            "",
        ]
    )
    return "\n".join(lines)


def write_atomic(path: Path, content: str) -> None:
    path = path.expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(content, encoding="utf-8")
    temporary.replace(path)


def main() -> int:
    args = parse_args()
    root = args.state_dir.expanduser().resolve()
    if not root.is_dir():
        print(f"error: not a directory: {root}", file=sys.stderr)
        return 2
    try:
        errors = validate(root)
        if errors:
            for error in errors:
                print(f"error: {error}", file=sys.stderr)
            return 1
        report = render(root)
        if args.output is None:
            print(report, end="")
        else:
            write_atomic(args.output, report)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
