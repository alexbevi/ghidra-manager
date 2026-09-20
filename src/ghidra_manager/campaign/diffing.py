"""Classify metadata deltas before deciding what needs native review."""

from __future__ import annotations

from typing import Any

from ghidra_manager.campaign.inventory import validate_snapshot
from ghidra_manager.errors import ManagerError


def compare(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    for value in (old, new):
        validate_snapshot(value)
    if old["identity"] != new["identity"]:
        raise ManagerError("Cannot compare snapshots of different program identities")
    before = {f["address"]: f for f in old["functions"]}
    after = {f["address"]: f for f in new["functions"]}
    changes = []
    review: set[str] = set()
    reasons = []
    if old["configuration"] != new["configuration"]:
        reasons.append("program configuration changed")
    if old["types"] != new["types"]:
        reasons.append("shared types changed; consumer coverage is conservative")
    for address in sorted(before.keys() | after.keys()):
        a, b = before.get(address), after.get(address)
        if a == b:
            continue
        fields = sorted(
            k for k in (a or {}).keys() | (b or {}).keys() if (a or {}).get(k) != (b or {}).get(k)
        )
        meaningful = set(fields)
        if a is not None and b is not None and "abi" in a and a["abi"] == b.get("abi"):
            meaningful.discard("signature")
        if a is None or b is None:
            kind = "added" if a is None else "removed"
        elif meaningful <= {"name", "source", "comment"}:
            kind = "decoration"
        elif meaningful <= {"variables", "name", "source", "comment"} and [
            {k: v for k, v in item.items() if k != "name"} for item in a["variables"]
        ] == [{k: v for k, v in item.items() if k != "name"} for item in b["variables"]]:
            kind = "variable-name"
        else:
            kind = "semantic-metadata"
        changes.append({"address": address, "kind": kind, "fields": fields})
        if kind not in {"decoration", "variable-name"}:
            review.add(address)
            review.update(f["address"] for f in new["functions"] if address in f["callees"])
            if any(
                flow.get("computed", False) or "COMPUTED" in str(flow.get("targets", []))
                for f in new["functions"]
                for flow in f.get("flows", [])
            ):
                reasons.append("indirect consumer coverage is incomplete")
    if reasons:
        review = set(after)
    return {
        "changed": changes,
        "native_review": sorted(review & after.keys()),
        "full_audit": bool(reasons),
        "reasons": sorted(set(reasons)),
        "unchanged_functions": len(before.keys() & after.keys())
        - sum(c["address"] in before and c["address"] in after for c in changes),
    }
