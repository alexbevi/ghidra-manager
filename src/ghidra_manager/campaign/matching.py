"""Reference matches are review candidates, never automatic ABI transfers."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from ghidra_manager.campaign.inventory import fingerprint, validate_snapshot
from ghidra_manager.errors import ManagerError


def candidates(
    target: dict[str, Any], reference: dict[str, Any], provenance: str
) -> dict[str, Any]:
    for snapshot in (target, reference):
        validate_snapshot(snapshot)
    if not provenance.strip():
        raise ManagerError("Reference provenance is required")
    for key in ["language", "compiler"]:
        if target["identity"].get(key) != reference["identity"].get(key):
            raise ManagerError(f"Incompatible reference {key}")
    index: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
    for function in reference["functions"]:
        if function.get("shape_hash") and not function["name"].startswith(("FUN_", "thunk_FUN_")):
            index[(function["shape_hash"], function["instruction_count"])].append(function)
    results = []
    for function in target["functions"]:
        match_key = (function.get("shape_hash", ""), function.get("instruction_count", 0))
        matches = index.get(match_key, [])
        if not matches:
            continue
        results.append(
            {
                "address": function["address"],
                "ambiguous": len(matches) != 1,
                "candidates": [
                    {
                        "reference_address": f["address"],
                        "name": f["name"],
                        "exact_code_bytes": bool(function.get("code_hash"))
                        and function["code_hash"] == f.get("code_hash"),
                        "reference_abi": f.get("abi"),
                        "requires_semantic_review": True,
                    }
                    for f in sorted(matches, key=lambda f: f["address"])
                ],
            }
        )
    return {
        "reference_snapshot": fingerprint(reference),
        "reference_identity": reference["identity"],
        "provenance": provenance,
        "matches": results,
        "installed_fid_databases": target.get("fid_databases", []),
        "note": "Shape hashes ignore operands; even unique/exact-byte candidates are not ABI proof",
    }
