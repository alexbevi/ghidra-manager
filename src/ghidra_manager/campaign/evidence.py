"""Cache evidence against semantic dependencies and emit bounded model input."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ghidra_manager.campaign import metrics
from ghidra_manager.campaign.budget import locked, require_admission
from ghidra_manager.campaign.inventory import fingerprint, latest, normalize, read, scan
from ghidra_manager.campaign.transport import Client
from ghidra_manager.errors import ManagerError
from ghidra_manager.storage import atomic_json


def dependency_key(snapshot: dict[str, Any], address: str) -> str:
    functions = {f["address"]: f for f in snapshot["functions"]}
    if address not in functions:
        raise ManagerError(f"Unknown function: {address}")
    function = functions[address]
    callees = [functions.get(a, {"address": a}) for a in sorted(function["callees"])]
    references = set(function.get("references", []))
    callers = sorted(f["address"] for f in functions.values() if address in f["callees"])
    return fingerprint(
        {
            "packet_version": 2,
            "memory": snapshot.get("memory"),
            "data": snapshot.get("data"),
            "collector_version": snapshot["collector_version"],
            "identity": snapshot["identity"],
            "configuration": snapshot["configuration"],
            "function": function,
            "callees": callees,
            "callers": callers,
            "types": snapshot["types"],
            "symbols": [s for s in snapshot["symbols"] if s["address"] in references],
            "strings": [s for s in snapshot["strings"] if s["address"] in references],
        }
    )


def packet(
    root: Path, client: Client, addresses: list[str], max_bytes: int = 32768
) -> dict[str, Any]:
    require_admission(root)
    if (
        not addresses
        or len(addresses) > 64
        or len(set(addresses)) != len(addresses)
        or max_bytes < 1024
    ):
        raise ManagerError(
            "Require 1 to 64 unique addresses and a packet limit of at least 1024 bytes"
        )
    scan(root, client)
    with locked(root):
        snapshot = latest(root)
        directory = root / "artifacts" / "evidence-cache"
        directory.mkdir(parents=True, exist_ok=True)
        keys = {a: dependency_key(snapshot, a) for a in addresses}
        missing = [a for a, key in keys.items() if not (directory / (key + ".json")).exists()]
        if missing:
            rows = []
            for index in range(0, len(missing), 8):
                captured = client.script(
                    "CampaignEvidence", {"addresses": missing[index : index + 8]}
                )
                rows.extend(captured.get("functions", []))
            if sorted(r["address"] for r in rows) != sorted(missing):
                raise ManagerError("Evidence collector omitted or duplicated a function")
            # Reconcile possible UI edits during collection before publishing cache entries.
            after = client.script("CampaignInventory", {})
            normalize(after)
            if any(dependency_key(after, a) != keys[a] for a in addresses):
                raise ManagerError(
                    "Evidence changed during capture; retry after the program settles"
                )
            for row in rows:
                atomic_json(directory / (keys[row["address"]] + ".json"), row)
        functions = {f["address"]: f for f in snapshot["functions"]}
        content: dict[str, Any] = {
            "schema_version": 1,
            "snapshot": fingerprint(snapshot),
            "functions": [],
            "omitted": [],
        }
        for address in sorted(addresses):
            row = read(directory / (keys[address] + ".json"))
            candidate = {"facts": functions[address], "evidence_key": keys[address], **row}
            content["functions"].append(candidate)
            if len(json.dumps(content, sort_keys=True).encode()) > max_bytes - 512:
                content["functions"].pop()
                content["omitted"].append(address)
        content["complete"] = not content["omitted"]
        if len(json.dumps(content, sort_keys=True).encode()) > max_bytes:
            raise ManagerError("Address list exceeds packet budget; request fewer functions")
        path = root / "artifacts" / "packets" / (fingerprint(content) + ".json")
        path.parent.mkdir(parents=True, exist_ok=True)
        # Compact serialization keeps the actual file within the advertised byte ceiling.
        if not path.exists():
            path.write_text(json.dumps(content, sort_keys=True), encoding="utf-8")
        metrics.record(
            root,
            packet_requests=1,
            cache_hits=len(addresses) - len(missing),
            cache_misses=len(missing),
            packet_bytes=path.stat().st_size,
            evidence_functions_captured=len(missing),
        )
        return {
            "artifact": str(path),
            "complete": content["complete"],
            "included": len(content["functions"]),
            "omitted": content["omitted"],
            "cache_hits": len(addresses) - len(missing),
            "captured": len(missing),
            "bytes": path.stat().st_size,
        }
