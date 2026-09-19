"""Immutable, evidence-linked change plans. Validation performs no Ghidra writes."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from ghidra_manager.campaign.budget import locked, require_admission
from ghidra_manager.campaign.inventory import fingerprint, latest, read
from ghidra_manager.errors import ManagerError
from ghidra_manager.storage import atomic_json


def target(snapshot: dict[str, Any], change: dict[str, Any]) -> dict[str, Any]:
    if change["kind"] == "function":
        matches = [f for f in snapshot["functions"] if f["address"] == change["address"]]
    elif change["kind"] == "global":
        matches = [
            s
            for s in snapshot["symbols"]
            if s["id"] == change.get("symbol_id")
            and s["address"] == change["address"]
            and s["kind"] == "Label"
            and s["namespace"] == "Global"
        ]
    else:
        raise ManagerError(f"Unsupported change kind: {change['kind']}")
    if len(matches) != 1:
        raise ManagerError("Change must resolve to exactly one persistent target")
    return dict(matches[0])


def create(root: Path, proposal: dict[str, Any]) -> dict[str, Any]:
    require_admission(root)
    with locked(root):
        snapshot = latest(root)
        if set(proposal) != {"author", "changes"} or not proposal["author"]:
            raise ManagerError("Proposal requires only author and changes")
        if not isinstance(proposal["changes"], list) or not proposal["changes"]:
            raise ManagerError("Proposal changes must be a nonempty list")
        evidence = {
            json.loads(line)["id"]
            for line in (root / "evidence.jsonl").read_text().splitlines()
            if line.strip()
        }
        changes = []
        touched: set[str] = set()
        new_names: set[tuple[str, str]] = set()
        for change in proposal["changes"]:
            allowed = {"kind", "address", "old_name", "new_name", "evidence_ids", "symbol_id"}
            if set(change) - allowed or not {
                "kind",
                "address",
                "old_name",
                "new_name",
                "evidence_ids",
            } <= set(change):
                raise ManagerError(
                    "Unexpected or missing rename fields; type and flow edits forbidden"
                )
            item = target(snapshot, change)
            if item["name"] != change["old_name"]:
                raise ManagerError("Stale prior name")
            if change["new_name"] == change["old_name"] or not re.fullmatch(
                r"[A-Za-z_][A-Za-z0-9_]*", change["new_name"]
            ):
                raise ManagerError("Require a different, unqualified identifier")
            if not change["evidence_ids"] or not set(change["evidence_ids"]) <= evidence:
                raise ManagerError("Every rename requires existing evidence identifiers")
            key = fingerprint(
                {
                    "kind": change["kind"],
                    "address": change["address"],
                    "symbol_id": change.get("symbol_id"),
                }
            )
            if key in touched:
                raise ManagerError("Duplicate target in proposal")
            namespace = item.get("namespace", "Global")
            name_key = (namespace, change["new_name"])
            if name_key in new_names or any(
                s["name"] == change["new_name"] and s.get("namespace", "Global") == namespace
                for s in snapshot["symbols"]
            ):
                raise ManagerError("Name collision in target namespace")
            new_names.add(name_key)
            touched.add(key)
            changes.append({**change, "expected": fingerprint(item)})
        plan = {
            "schema_version": 1,
            "author": proposal["author"],
            "queue": "naming",
            "snapshot": fingerprint(snapshot),
            "identity": snapshot["identity"],
            "changes": changes,
        }
        plan_id = fingerprint(plan)
        path = root / "artifacts" / "plans" / (plan_id + ".json")
        path.parent.mkdir(parents=True, exist_ok=True)
        atomic_json(path, {"id": plan_id, **plan})
        return {"id": plan_id, "artifact": str(path), "changes": len(changes)}


def load_plan(path: Path) -> dict[str, Any]:
    plan = read(path)
    if plan.get("schema_version") != 1 or plan.get("id") != fingerprint(
        {k: v for k, v in plan.items() if k != "id"}
    ):
        raise ManagerError("Invalid or edited retained plan")
    return plan
