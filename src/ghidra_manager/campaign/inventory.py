"""Retained, canonical snapshots and exact target identity checks."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from ghidra_manager.campaign.budget import locked
from ghidra_manager.campaign.transport import Client
from ghidra_manager.errors import ManagerError
from ghidra_manager.storage import atomic_json


def fingerprint(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def read(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ManagerError(f"Expected object: {path}")
    return value


def check_identity(root: Path, snapshot: dict[str, Any]) -> None:
    expected = read(root / "project.json")["ghidra"]
    actual = snapshot["identity"]
    if expected["project"] not in {actual["project"], actual["project_path"]}:
        raise ManagerError("Ghidra project identity mismatch")
    for key in ["program_path", "digest", "language", "compiler", "format", "image_base"]:
        if expected.get(key) and expected[key] != actual.get(key):
            raise ManagerError(f"Ghidra identity mismatch: {key}")
    if not actual.get("digest") or not actual["program_path"].startswith("/"):
        raise ManagerError("Incomplete Ghidra identity")


def validate_snapshot(value: dict[str, Any]) -> None:
    if value.get("complete") is not True or value.get("schema_version") != 1:
        raise ManagerError("Incomplete or unsupported snapshot")
    for key in ["functions", "symbols", "types", "strings"]:
        if not isinstance(value.get(key), list):
            raise ManagerError(f"Missing snapshot inventory: {key}")
    addresses = [f["address"] for f in value["functions"]]
    if len(set(addresses)) != len(addresses):
        raise ManagerError("Duplicate function addresses in inventory")


def scan(root: Path, client: Client) -> dict[str, Any]:
    with locked(root):
        value = client.script("CampaignInventory", {})
        validate_snapshot(value)
        check_identity(root, value)
        if (root / "snapshot.json").exists() and latest(root)["identity"] != value["identity"]:
            raise ManagerError("Snapshot identity changed; explicit campaign migration required")
        for key, field in [
            ("functions", "address"),
            ("symbols", "id"),
            ("types", "path"),
            ("strings", "address"),
        ]:
            value[key].sort(key=lambda row: row[field])
        snapshot_id = fingerprint(value)
        directory = root / "artifacts" / "snapshots"
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / (snapshot_id + ".json")
        if not path.exists():
            atomic_json(path, value)
        atomic_json(root / "snapshot.json", {"schema_version": 1, "id": snapshot_id})
        return {
            "snapshot": snapshot_id,
            "artifact": str(path),
            "complete": True,
            "functions": len(value["functions"]),
            "symbols": len(value["symbols"]),
        }


def latest(root: Path) -> dict[str, Any]:
    snapshot_id = read(root / "snapshot.json")["id"]
    if (
        not isinstance(snapshot_id, str)
        or len(snapshot_id) != 64
        or any(c not in "0123456789abcdef" for c in snapshot_id)
    ):
        raise ManagerError("Invalid snapshot identifier")
    value = read(root / "artifacts" / "snapshots" / (snapshot_id + ".json"))
    validate_snapshot(value)
    if fingerprint(value) != snapshot_id:
        raise ManagerError("Snapshot content fingerprint mismatch")
    check_identity(root, value)
    return value
