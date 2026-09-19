"""Declarative layout plans, deliberately separate from naming."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from ghidra_manager.campaign.budget import locked, require_admission
from ghidra_manager.campaign.inventory import fingerprint, latest
from ghidra_manager.errors import ManagerError
from ghidra_manager.storage import atomic_json


def create(root: Path, proposal: dict[str, Any]) -> dict[str, Any]:
    require_admission(root)
    with locked(root):
        snapshot = latest(root)
        if set(proposal) != {"queue", "author", "changes"} or not proposal["author"]:
            raise ManagerError("Typed proposals require queue, author and changes")
        if proposal["queue"] != "types" or not proposal["changes"]:
            raise ManagerError("Require a nonempty types proposal")
        evidence = {
            json.loads(line)["id"]
            for line in (root / "evidence.jsonl").read_text().splitlines()
            if line.strip()
        }
        paths = {t["path"] for t in snapshot["types"]}
        touched: set[str] = set()
        for change in proposal["changes"]:
            if not change.get("evidence_ids") or not set(change["evidence_ids"]) <= evidence:
                raise ManagerError("Every type change requires existing evidence")
            kind = change.get("kind")
            if kind == "structure":
                if set(change) != {"kind", "path", "length", "fields", "evidence_ids"}:
                    raise ManagerError("Unexpected structure fields")
                path, length = change["path"], change["length"]
                if not re.fullmatch(r"(?:/[A-Za-z_][A-Za-z0-9_]*)+", path) or path in paths:
                    raise ManagerError("Require a new unambiguous structure path")
                if type(length) is not int or not 0 < length <= 65536:
                    raise ManagerError("Invalid structure extent")
                occupied: set[int] = set()
                names: set[str] = set()
                for field in change["fields"]:
                    if set(field) != {"offset", "length", "type", "name"}:
                        raise ManagerError("Unexpected field properties")
                    start, size = field["offset"], field["length"]
                    if (
                        type(start) is not int
                        or type(size) is not int
                        or start < 0
                        or size <= 0
                        or start + size > length
                        or not re.fullmatch(r"[A-Za-z_]\w*", field["name"])
                        or field["name"] in names
                    ):
                        raise ManagerError("Invalid field extent or name")
                    extent = set(range(start, start + size))
                    if extent & occupied:
                        raise ManagerError("Overlapping structure fields")
                    occupied |= extent
                    names.add(field["name"])
                paths.add(path)
                key = path
            elif kind == "data_type":
                if set(change) != {"kind", "address", "type", "length", "evidence_ids"}:
                    raise ManagerError("Unexpected data-type properties")
                if type(change["length"]) is not int or not 0 < change["length"] <= 65536:
                    raise ManagerError("Invalid data extent")
                key = change["address"]
            else:
                raise ManagerError(f"Unsupported type operation: {kind}")
            if key in touched:
                raise ManagerError("Duplicate type target")
            touched.add(key)
        plan = {
            "schema_version": 1,
            "author": proposal["author"],
            "queue": "types",
            "snapshot": fingerprint(snapshot),
            "identity": snapshot["identity"],
            "changes": proposal["changes"],
        }
        plan_id = fingerprint(plan)
        path = root / "artifacts" / "plans" / (plan_id + ".json")
        path.parent.mkdir(parents=True, exist_ok=True)
        atomic_json(path, {"id": plan_id, **plan})
        return {"id": plan_id, "artifact": str(path), "changes": len(plan["changes"])}


def readback(plan: dict[str, Any], before: dict[str, Any], after: dict[str, Any]) -> None:
    # All existing machine instructions and function boundaries must survive layout changes.
    old = {f["address"]: f for f in before["functions"]}
    new = {f["address"]: f for f in after["functions"]}
    if old.keys() != new.keys():
        raise ManagerError("Type change altered function ownership")
    for address in old:
        for key in ["byte_hash", "body", "flows"]:
            if old[address].get(key) != new[address].get(key):
                raise ManagerError("Type change altered code or control flow")
    types = {t["path"]: t for t in after["types"]}
    for change in plan["changes"]:
        if change["kind"] == "structure":
            result = types.get(change["path"], {})
            if result.get("length") != change["length"] or result.get("fields") != change["fields"]:
                raise ManagerError("Structure readback differs from reviewed layout")
        elif change["kind"] == "data_type":
            items = [d for d in after.get("data", []) if d["address"] == change["address"]]
            if (
                len(items) != 1
                or items[0]["type"] != change["type"]
                or items[0]["length"] != change["length"]
            ):
                raise ManagerError("Data-type readback failed")
