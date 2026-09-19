"""Independent review and explicit save gate for an already applied batch."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ghidra_manager.campaign import native
from ghidra_manager.campaign.budget import locked, timestamp
from ghidra_manager.campaign.inventory import check_identity, fingerprint, read
from ghidra_manager.campaign.mutations import normalize, readback, reconcile
from ghidra_manager.campaign.plans import load_plan
from ghidra_manager.campaign.transport import Client
from ghidra_manager.errors import ManagerError
from ghidra_manager.storage import atomic_json


def verify(root: Path, client: Client) -> dict[str, Any]:
    result = reconcile(root, client)
    if result["status"] != "needs-review":
        raise ManagerError("Batch outcome remains unresolved")
    report = read(root / "artifacts" / "batches" / result["plan"] / "verification.json")
    return {**result, "after_snapshot": report["after_snapshot"]}


def finalize(root: Path, client: Client, review: dict[str, Any]) -> dict[str, Any]:
    with locked(root):
        batch = read(root / "batch.json")
        if batch["status"] not in {"needs-review", "save-uncertain", "saved"}:
            raise ManagerError("Verify the applied batch before finalizing")
        plan = load_plan(Path(batch["plan_path"]))
        directory = root / "artifacts" / "batches" / plan["id"]
        verification = read(directory / "verification.json")
        if (
            review.get("plan") != plan["id"]
            or review.get("after_snapshot") != verification["after_snapshot"]
            or review.get("verdict") != "pass"
            or not review.get("notes")
            or not isinstance(review.get("reviewer"), str)
            or not review["reviewer"].strip()
            or review["reviewer"].strip().casefold() == plan["author"].strip().casefold()
        ):
            raise ManagerError("Require an independent passing review bound to this exact batch")
        required = {e for c in plan["changes"] for e in c["evidence_ids"]}
        if not required <= set(review.get("evidence_ids", [])):
            raise ManagerError("Review must address every change's evidence")
        if plan["queue"] != "naming":
            if verification.get("native_delta", {}).get("artifacts_hash") != native.manifest(
                root, plan["id"]
            ):
                raise ManagerError("Native evidence changed after verification")
            changed = {
                c["address"] for c in verification.get("native_delta", {}).get("changed", [])
            }
            if "native_delta" not in verification or not changed <= set(
                review.get("reviewed_native_functions", [])
            ):
                raise ManagerError("Review must explicitly cover every changed native function")
        live = client.script("CampaignInventory", {})
        normalize(live)
        check_identity(root, live)
        if fingerprint(live) != verification["after_snapshot"]:
            raise ManagerError("Program changed after review; verify and review the new state")
        before = read(root / "artifacts" / "snapshots" / (plan["snapshot"] + ".json"))
        readback(plan, before, live)
        atomic_json(directory / "review.json", review)
        batch["status"] = "save-uncertain"
        atomic_json(root / "batch.json", batch)
        client.request("/save_program")
        saved = client.script("CampaignSaveState", {})
        if saved.get("changed") is not False or saved.get("program") != client.program:
            raise ManagerError("Save not confirmed; batch remains save-uncertain")
        saved_snapshot = client.script("CampaignInventory", {})
        normalize(saved_snapshot)
        if fingerprint(saved_snapshot) != verification["after_snapshot"]:
            raise ManagerError("Program changed during save; saved checkpoint remains unverified")
        batch["status"] = "saved"
        batch["saved_at"] = timestamp()
        atomic_json(root / "batch.json", batch)
        # Publish the verified current baseline only after confirmed save.
        snapshot_id = fingerprint(live)
        atomic_json(root / "artifacts" / "snapshots" / (snapshot_id + ".json"), live)
        atomic_json(root / "snapshot.json", {"schema_version": 1, "id": snapshot_id})
        progress = read(root / "progress.json")
        progress["save_state"] = "saved after independent campaign verification"
        progress["last_verified_at"] = timestamp()
        progress["current"].update(
            internal_functions=len(live["functions"]),
            unnamed_functions=sum(f["name"].startswith("FUN_") for f in live["functions"]),
        )
        atomic_json(root / "progress.json", progress)
        existing = {
            json.loads(line)["id"]
            for line in (root / "renames.jsonl").read_text().splitlines()
            if line.strip()
        }
        with (root / "renames.jsonl").open("a", encoding="utf-8") as stream:
            for index, change in enumerate(plan["changes"]):
                if plan["queue"] != "naming":
                    continue
                record_id = f"rn-{plan['id']}-{index}"
                if record_id not in existing:
                    stream.write(
                        json.dumps(
                            {
                                "id": record_id,
                                "batch_id": plan["id"],
                                "kind": change["kind"],
                                "address": change["address"],
                                "old_name": change["old_name"],
                                "new_name": change["new_name"],
                                "confidence": "high",
                                "evidence_ids": change["evidence_ids"],
                                "state": "verified",
                                "agent": plan["author"],
                                "verified_by": review["reviewer"],
                                "timestamp": batch["saved_at"],
                            }
                        )
                        + "\n"
                    )
        atomic_json(directory / "receipt.json", batch)
        return {"plan": plan["id"], "status": "saved", "reviewer": review["reviewer"]}
