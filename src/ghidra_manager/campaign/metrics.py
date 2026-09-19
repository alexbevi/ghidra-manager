"""Local work counters. These do not estimate model tokens or account quotas."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ghidra_manager.campaign import budget, queue
from ghidra_manager.campaign.inventory import read
from ghidra_manager.storage import atomic_json


def record(root: Path, **counts: int) -> None:
    """Caller holds the campaign lock; count completed local work only."""
    path = root / "metrics.json"
    value: dict[str, Any] = read(path) if path.exists() else {"schema_version": 1, "counters": {}}
    for key, count in counts.items():
        value["counters"][key] = value["counters"].get(key, 0) + count
    atomic_json(path, value)


def report(root: Path) -> dict[str, Any]:
    usage = budget.summary(budget.load(root))
    path = root / "metrics.json"
    counters = read(path)["counters"] if path.exists() else {}
    tasks = queue.load(root)["tasks"]
    receipts = list((root / "artifacts" / "batches").glob("*/receipt.json"))
    accepted = 0
    for path in receipts:
        batch = read(path)
        if batch["status"] == "saved":
            accepted += len(read(Path(batch["plan_path"]))["changes"])
    measured = usage["campaign_measured_tokens"]
    return {
        "budget": usage,
        "local_work": counters,
        "saved_batches": len(receipts),
        "accepted_changes": accepted,
        "accepted_changes_per_1000_reported_tokens": accepted * 1000 / measured
        if measured
        else None,
        "failed_attempts": sum(h["action"] == "fail" for t in tasks for h in t["history"]),
        "deferred_tasks": sum(t["status"] == "deferred" for t in tasks),
        "batch_status": read(root / "batch.json")["status"]
        if (root / "batch.json").exists()
        else None,
        "limits": "Counters cover completed instrumented work only; ratios use reported token "
        "deltas across sessions and do not prove causation, full agent coverage, or weekly savings",
    }
