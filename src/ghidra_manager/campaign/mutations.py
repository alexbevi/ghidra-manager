"""Single-writer mutation orchestration with durable ambiguous-request state."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ghidra_manager.campaign import layouts, native, repairs
from ghidra_manager.campaign.budget import locked, require_admission, timestamp
from ghidra_manager.campaign.diffing import compare
from ghidra_manager.campaign.inventory import check_identity, fingerprint, latest, read
from ghidra_manager.campaign.plans import load_plan, target
from ghidra_manager.campaign.transport import Client
from ghidra_manager.errors import ManagerError
from ghidra_manager.storage import atomic_json


def readback(plan: dict[str, Any], before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    if before.get("memory") != after.get("memory"):
        raise ManagerError("Mutation changed program memory")
    if plan["queue"] in {"types", "repair"}:
        (layouts if plan["queue"] == "types" else repairs).readback(plan, before, after)
        return {
            "complete": True,
            "plan": plan["id"],
            "after_snapshot": fingerprint(after),
            "delta": compare(before, after),
            "verified_at": timestamp(),
        }
    delta = compare(before, after)
    allowed_functions = {c["address"] for c in plan["changes"] if c["kind"] != "global"}
    if any(c["address"] not in allowed_functions for c in delta["changed"]):
        raise ManagerError("Unplanned function metadata changed")
    if any(c["kind"] not in {"decoration", "variable-name"} for c in delta["changed"]):
        raise ManagerError("Rename changed semantic metadata")
    if before["types"] != after["types"] or before["configuration"] != after["configuration"]:
        raise ManagerError("Rename changed types or program configuration")
    for change in plan["changes"]:
        if target(after, change)["name"] != change["new_name"]:
            raise ManagerError("Exact rename readback failed")
    return {
        "complete": True,
        "plan": plan["id"],
        "after_snapshot": fingerprint(after),
        "delta": delta,
        "verified_at": timestamp(),
    }


def apply(
    root: Path, client: Client, plan_path: Path, trial_review: dict[str, Any] | None = None
) -> dict[str, Any]:
    require_admission(root)
    plan = load_plan(plan_path)
    if plan["queue"] not in {"naming", "types", "repair"}:
        raise ManagerError("Unsupported mutation queue")
    with locked(root):
        from ghidra_manager.campaign.repairs import require_clear

        require_clear(root)
        if plan["queue"] == "repair":
            repairs.approve_trial(root, plan, trial_review)
        progress = read(root / "progress.json")
        if progress.get("active_mutation_lease"):
            raise ManagerError("An existing campaign mutation lease requires reconciliation")
        batch_path = root / "batch.json"
        if batch_path.exists() and read(batch_path)["status"] not in {"saved", "unapplied"}:
            raise ManagerError("Reconcile or finalize the existing batch before applying another")
        before = client.script("CampaignInventory", {})
        check_identity(root, before)
        retained = latest(root)
        # Collector ordering is canonicalized by scan; normalize live arrays identically.
        normalize(before)
        if fingerprint(before) != plan["snapshot"] or fingerprint(retained) != plan["snapshot"]:
            raise ManagerError("Stale plan snapshot; rescan and review a new proposal")
        for change in plan["changes"]:
            if (
                plan["queue"] == "naming"
                and fingerprint(target(before, change)) != change["expected"]
            ):
                raise ManagerError("Stale target fingerprint")
        if plan["queue"] != "naming":
            native.capture(root, client, plan["id"], "before-native", before)
        batch = {
            "schema_version": 1,
            "plan": plan["id"],
            "plan_path": str(plan_path.resolve()),
            "status": "in-flight",
            "started_at": timestamp(),
        }
        atomic_json(batch_path, batch)
        # An exception leaves in-flight state; never automatically retry an uncertain write.
        response = client.script(
            {"naming": "CampaignRename", "types": "CampaignTypes", "repair": "CampaignRepair"}[
                plan["queue"]
            ],
            {
                "plan": plan,
                "before": before,
                "mode": "apply",
                "directory": str((root / "artifacts" / "batches" / plan["id"]).resolve()),
            },
        )
        if response.get("transaction") != plan["id"] or response.get("committed") is not True:
            raise ManagerError("Mutation outcome ambiguous; run reconcile")
        after = client.script("CampaignInventory", {})
        normalize(after)
        verification = readback(plan, before, after)
        if plan["queue"] != "naming":
            native.capture(root, client, plan["id"], "after-native", after)
            verification["native_delta"] = native.delta(root, plan["id"])
            if plan["queue"] == "repair":
                repairs.native_tables(root, plan)
                repairs.stable(client, after)
        directory = root / "artifacts" / "batches" / plan["id"]
        directory.mkdir(parents=True, exist_ok=True)
        atomic_json(directory / "after.json", after)
        atomic_json(directory / "verification.json", verification)
        batch["status"] = "needs-review"
        atomic_json(batch_path, batch)
        return {
            "plan": plan["id"],
            "status": "needs-review",
            "saved": False,
            "verification": str(directory / "verification.json"),
        }


def normalize(snapshot: dict[str, Any]) -> None:
    for key, field in [
        ("functions", "address"),
        ("symbols", "id"),
        ("types", "path"),
        ("strings", "address"),
    ]:
        snapshot[key].sort(key=lambda row: row[field])


def reconcile(root: Path, client: Client) -> dict[str, Any]:
    with locked(root):
        batch = read(root / "batch.json")
        plan = load_plan(Path(batch["plan_path"]))
        live = client.script("CampaignInventory", {})
        normalize(live)
        check_identity(root, live)
        journal = live.get("transactions", {})
        if journal.get(plan["id"]) == "applied":
            before = read(root / "artifacts" / "snapshots" / (plan["snapshot"] + ".json"))
            verification = readback(plan, before, live)
            if plan["queue"] != "naming":
                native.capture(root, client, plan["id"], "after-native", live)
                verification["native_delta"] = native.delta(root, plan["id"])
                if plan["queue"] == "repair":
                    repairs.native_tables(root, plan)
                    repairs.stable(client, live)
            directory = root / "artifacts" / "batches" / plan["id"]
            directory.mkdir(parents=True, exist_ok=True)
            atomic_json(directory / "after.json", live)
            atomic_json(directory / "verification.json", verification)
            batch["status"] = "needs-review"
        else:
            # A timed-out script may still be queued: absence of a receipt is not proof it stopped.
            batch["status"] = "unresolved"
        atomic_json(root / "batch.json", batch)
        return {"plan": plan["id"], "status": batch["status"], "saved": False}
