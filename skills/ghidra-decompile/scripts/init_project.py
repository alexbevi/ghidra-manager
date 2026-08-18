#!/usr/bin/env python3
"""Initialize durable state for a Ghidra decompilation campaign."""

from __future__ import annotations

import argparse
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug or "program"


def write_json(path: Path, value: dict[str, Any]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Initialize a Ghidra decompilation campaign directory."
    )
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--project", required=True)
    parser.add_argument("--program", required=True)
    parser.add_argument("--program-path", default="")
    parser.add_argument(
        "--profile",
        choices=("symbol-recovery", "reimplementation"),
        default="symbol-recovery",
    )
    parser.add_argument("--goal", default="")
    parser.add_argument("--slug")
    parser.add_argument("--max-workers", type=int, default=3)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    output = args.output.expanduser().resolve()
    if output.exists() and any(output.iterdir()):
        raise SystemExit(f"refusing to overwrite non-empty campaign: {output}")
    if args.max_workers < 1:
        raise SystemExit("--max-workers must be at least 1")

    output.mkdir(parents=True, exist_ok=True)
    timestamp = utc_now()
    slug = args.slug or slugify(args.program)
    project = {
        "schema_version": 2,
        "campaign_slug": slug,
        "created_at": timestamp,
        "goal_objective": args.goal,
        "profile": args.profile,
        "ghidra": {
            "project": args.project,
            "program": args.program,
            "program_path": args.program_path,
            "format": None,
            "language": None,
            "compiler": None,
            "image_base": None,
            "address_spaces": [],
            "digest": None,
        },
        "entry_points": [],
        "derived_programs": [],
    }
    progress = {
        "schema_version": 2,
        "status": "active",
        "phase": "analysis-fidelity",
        "analysis_fidelity": {
            "status": "pending",
            "semantic_program": None,
            "container_coverage": None,
            "relocations_and_overlays": None,
            "compiler_abi": None,
            "address_aliasing": None,
            "limitations": [],
            "verified_at": None,
        },
        "baseline": {},
        "current": {},
        "active_mutation_lease": None,
        "blockers": [],
        "last_verified_at": None,
        "updated_at": timestamp,
    }
    seed_tasks = [
        {
            "id": "recon-identity",
            "kind": "reconnaissance",
            "title": "Verify program identity and analysis state",
            "scope": {"program": args.program},
            "authority": "read-only",
            "status": "pending",
            "depends_on": [],
        },
        {
            "id": "assess-analysis-fidelity",
            "kind": "analysis-fidelity",
            "title": "Prove loader, container, address, and ABI fidelity",
            "scope": {"program": args.program},
            "authority": "read-only",
            "status": "pending",
            "depends_on": ["recon-identity"],
        },
        {
            "id": "index-entry-graph",
            "kind": "graph-index",
            "title": "Index entry points and direct call graph",
            "scope": {"roots": "entry-points"},
            "authority": "read-only",
            "status": "pending",
            "depends_on": ["assess-analysis-fidelity"],
        },
        {
            "id": "index-string-xrefs",
            "kind": "string-index",
            "title": "Cluster strings and trace cross-references",
            "scope": {"strings": "all"},
            "authority": "read-only",
            "status": "pending",
            "depends_on": ["assess-analysis-fidelity"],
        },
        {
            "id": "index-indirect-targets",
            "kind": "indirect-index",
            "title": "Find function-pointer, jump-table, and callback targets",
            "scope": {"targets": "indirect"},
            "authority": "read-only",
            "status": "pending",
            "depends_on": ["assess-analysis-fidelity"],
        },
    ]
    if args.profile == "reimplementation":
        seed_tasks.append(
            {
                "id": "index-resource-graph",
                "kind": "resource-index",
                "title": "Trace shipped resources through parsers and consumers",
                "scope": {"resources": "goal-relevant"},
                "authority": "read-only",
                "status": "pending",
                "depends_on": ["assess-analysis-fidelity"],
            }
        )
        seed_tasks.append(
            {
                "id": "model-behavior-slices",
                "kind": "behavior-recovery",
                "title": "Model bounded observable behavior contracts",
                "scope": {"behaviors": "goal-relevant"},
                "authority": "read-only",
                "status": "pending",
                "depends_on": [
                    "index-entry-graph",
                    "index-string-xrefs",
                    "index-indirect-targets",
                    "index-resource-graph",
                ],
            }
        )
        seed_tasks.append(
            {
                "id": "capture-runtime-evidence",
                "kind": "runtime-validation",
                "title": "Capture and compare goal-relevant runtime behavior",
                "scope": {"behaviors": "goal-relevant"},
                "authority": "read-only",
                "status": "pending",
                "depends_on": ["model-behavior-slices"],
            }
        )
    tasks = {
        "schema_version": 2,
        "queue_target": 6,
        "max_workers": args.max_workers,
        "tasks": seed_tasks,
        "updated_at": timestamp,
    }

    write_json(output / "project.json", project)
    write_json(output / "progress.json", progress)
    write_json(output / "tasks.json", tasks)
    (output / "artifacts").mkdir()
    (output / "traces").mkdir()
    (output / "evidence.jsonl").touch()
    (output / "renames.jsonl").touch()
    (output / "behaviors.jsonl").touch()
    (output / "coverage.jsonl").touch()
    (output / "runtime.jsonl").touch()
    (output / "resources.jsonl").touch()
    (output / "ARCHITECTURE.md").write_text(
        f"""# {args.program} Architecture

## Program identity

- Campaign: `{slug}`
- Ghidra project: `{args.project}`
- Program: `{args.program}`
- Program path: `{args.program_path or "unknown"}`

## Entry path

Pending reconnaissance.

## Analysis fidelity

Pending container, loader, address, and ABI audit.

## Subsystems

Pending evidence.

## Dispatch and indirect calls

Pending evidence.

## Data model

Pending evidence.

## Behavior inventory

No behavior slices recorded.

## Coverage and parity

No reviewed coverage records.

## Runtime validation

No runtime observations recorded.

## Resource entry graph

No resource records traced.

## Cross-version references

None recorded.

## Open questions

- Confirm binary identity and analysis baseline.

## Verification

No verified batches yet.
""",
        encoding="utf-8",
    )
    print(f"initialized campaign: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
