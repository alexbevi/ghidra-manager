"""Native capture runs locally and exposes only differences for semantic review."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ghidra_manager.campaign.inventory import fingerprint, read
from ghidra_manager.campaign.transport import Client
from ghidra_manager.errors import ManagerError
from ghidra_manager.storage import atomic_json


def capture(root: Path, client: Client, plan_id: str, phase: str, snapshot: dict[str, Any]) -> None:
    directory = root / "artifacts" / "batches" / plan_id / phase
    directory.mkdir(parents=True, exist_ok=True)
    for previous in directory.glob("*.json"):
        previous.unlink()
    addresses = sorted(f["address"] for f in snapshot["functions"] if not f.get("thunk"))
    for index in range(0, len(addresses), 8):
        group = addresses[index : index + 8]
        result = client.script("CampaignEvidence", {"addresses": group})
        if sorted(f["address"] for f in result.get("functions", [])) != group:
            raise ManagerError("Incomplete native audit")
        for function in result["functions"]:
            atomic_json(directory / (fingerprint(function["address"]) + ".json"), function)


def delta(root: Path, plan_id: str) -> dict[str, Any]:
    directory = root / "artifacts" / "batches" / plan_id
    old = {read(p)["address"]: read(p) for p in (directory / "before-native").glob("*.json")}
    new = {read(p)["address"]: read(p) for p in (directory / "after-native").glob("*.json")}
    changed = []
    for address in sorted(old.keys() | new.keys()):
        a = old.get(address, {}).get("decompilation", "")
        b = new.get(address, {}).get("decompilation", "")
        if a != b:
            changed.append(
                {
                    "address": address,
                    "old_warnings": [line for line in a.splitlines() if "WARNING" in line],
                    "new_warnings": [line for line in b.splitlines() if "WARNING" in line],
                }
            )
    result = {"before_count": len(old), "after_count": len(new), "changed": changed}
    atomic_json(directory / "native-delta.json", result)
    return result
