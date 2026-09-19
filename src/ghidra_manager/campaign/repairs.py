"""Evidence-bound flow repairs and rollback-only native trials."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from ghidra_manager.campaign import native
from ghidra_manager.campaign.budget import locked, require_admission
from ghidra_manager.campaign.inventory import check_identity, fingerprint, latest, read
from ghidra_manager.campaign.plans import load_plan
from ghidra_manager.campaign.transport import Client
from ghidra_manager.errors import ManagerError
from ghidra_manager.storage import atomic_json


def create(root: Path, proposal: dict[str, Any]) -> dict[str, Any]:
    require_admission(root)
    with locked(root):
        snapshot = latest(root)
        if set(proposal) != {"queue", "author", "changes"} or not proposal["author"]:
            raise ManagerError("Repair proposal requires queue, author and changes")
        if not proposal["changes"] or len(proposal["changes"]) > 100:
            raise ManagerError("Repair batch must contain 1 to 100 operations")
        evidence = {
            json.loads(line)["id"]
            for line in (root / "evidence.jsonl").read_text().splitlines()
            if line.strip()
        }
        functions = {f["address"]: f for f in snapshot["functions"]}
        keys = set()
        for change in proposal["changes"]:
            kind = change.get("kind")
            common = {"kind", "address", "evidence_ids"}
            fields = {
                "body": {"ranges", "old_body"},
                "remove_function": {"old_body", "old_name"},
                "flow_override": {"bytes", "old_override", "override"},
                "jump_table": {"bytes", "function", "targets"},
                "analyzer_option": {"old_value", "value"},
            }
            if kind not in fields or set(change) != common | fields[kind]:
                raise ManagerError("Unsupported repair operation or fields")
            if not change["evidence_ids"] or not set(change["evidence_ids"]) <= evidence:
                raise ManagerError("Every repair requires existing evidence")
            key = (kind, change["address"])
            if key in keys:
                raise ManagerError("Duplicate repair target")
            keys.add(key)
            if kind in {"body", "remove_function"}:
                f = functions.get(change["address"], {})
                if not f or f.get("body") != change["old_body"]:
                    raise ManagerError("Stale function body")
                if kind == "remove_function" and f["name"] != change["old_name"]:
                    raise ManagerError("Stale removed function name")
                if kind == "body" and (
                    not change["ranges"] or any(len(pair) != 2 for pair in change["ranges"])
                ):
                    raise ManagerError("Body requires explicit inclusive address ranges")
            if kind in {"flow_override", "jump_table"}:
                if not re.fullmatch(r"(?:[0-9a-f]{2}){1,16}", change["bytes"]):
                    raise ManagerError("Require exact instruction bytes")
                if kind == "flow_override" and change["override"] not in {"NONE", "BRANCH"}:
                    raise ManagerError("Only NONE and BRANCH flow overrides are supported")
                if kind == "jump_table" and (
                    change["function"] not in functions
                    or not change["targets"]
                    or len(change["targets"]) != len(set(change["targets"]))
                    or len(change["targets"]) > 256
                ):
                    raise ManagerError("Require an existing owner and unique bounded targets")
            if kind == "analyzer_option" and (
                change["address"] != "Shared Return Calls.Assume Contiguous Functions Only"
                or type(change["old_value"]) is not bool
                or type(change["value"]) is not bool
            ):
                raise ManagerError("Only the reviewed shared-return boolean is supported")
        plan = {
            "schema_version": 1,
            "queue": "repair",
            "author": proposal["author"],
            "identity": snapshot["identity"],
            "snapshot": fingerprint(snapshot),
            "changes": proposal["changes"],
        }
        plan_id = fingerprint(plan)
        path = root / "artifacts" / "plans" / (plan_id + ".json")
        path.parent.mkdir(parents=True, exist_ok=True)
        atomic_json(path, {"id": plan_id, **plan})
        return {"id": plan_id, "artifact": str(path), "changes": len(plan["changes"])}


def require_clear(root: Path) -> None:
    if (root / "trial-state.json").exists():
        raise ManagerError("An uncertain trial requires trial-reconcile before any mutation")
    if read(root / "progress.json").get("active_mutation_lease"):
        raise ManagerError("Existing mutation lease requires reconciliation")
    if (root / "batch.json").exists() and read(root / "batch.json")["status"] not in {
        "saved",
        "unapplied",
    }:
        raise ManagerError("The existing batch requires reconciliation or finalization")


def trial(root: Path, client: Client, plan_path: Path) -> dict[str, Any]:
    from ghidra_manager.campaign.mutations import normalize

    require_admission(root)
    plan = load_plan(plan_path)
    if plan["queue"] != "repair":
        raise ManagerError("Trial requires a repair plan")
    with locked(root):
        require_clear(root)
        before = client.script("CampaignInventory", {})
        normalize(before)
        check_identity(root, before)
        if fingerprint(before) != plan["snapshot"]:
            raise ManagerError("Stale trial plan")
        native.capture(root, client, plan["id"], "before-native", before)
        directory = root / "artifacts" / "batches" / plan["id"]
        trial_path = directory / "trial.json"
        for stale in [trial_path, directory / "trial-finished.json"]:
            stale.unlink(missing_ok=True)
        atomic_json(root / "trial-state.json", {"plan_path": str(plan_path.resolve())})
        result = client.script(
            "CampaignRepair", {"plan": plan, "mode": "trial", "directory": str(directory.resolve())}
        )
        after = client.script("CampaignInventory", {})
        normalize(after)
        if fingerprint(after) != plan["snapshot"] or result.get("rolled_back") is not True:
            raise ManagerError("Trial rollback not proven; mutation remains blocked")
        candidate = read(directory / "trial-snapshot.json")
        normalize(candidate)
        readback(plan, before, candidate)
        native_tables(root, plan)
        report = {
            "plan": plan["id"],
            "rolled_back": True,
            "candidate_snapshot": fingerprint(candidate),
            "native_delta": native.delta(root, plan["id"]),
        }
        report["id"] = fingerprint(report)
        atomic_json(trial_path, report)
        (root / "trial-state.json").unlink()
        return {
            "plan": plan["id"],
            "trial": report["id"],
            "artifact": str(trial_path),
            "rolled_back": True,
            "saved": False,
        }


def reconcile_trial(root: Path, client: Client) -> dict[str, Any]:
    """A completion receipt plus restored snapshot proves the queued script has finished."""
    from ghidra_manager.campaign.mutations import normalize

    with locked(root):
        state = read(root / "trial-state.json")
        plan = load_plan(Path(state["plan_path"]))
        receipt = root / "artifacts" / "batches" / plan["id"] / "trial-finished.json"
        if not receipt.exists() or read(receipt) != {"plan": plan["id"], "finished": True}:
            raise ManagerError("Trial completion is unknown; do not retry")
        live = client.script("CampaignInventory", {})
        normalize(live)
        if fingerprint(live) != plan["snapshot"]:
            raise ManagerError("Trial state is not restored; manual investigation required")
        (root / "trial-state.json").unlink()
        return {"rolled_back": True, "reviewable": False, "retry_requires_new_trial": True}


def readback(plan: dict[str, Any], before: dict[str, Any], after: dict[str, Any]) -> None:
    if not before.get("memory") or before["memory"] != after.get("memory"):
        raise ManagerError("Repair must preserve all memory bytes")
    if before["types"] != after["types"] or before["data"] != after["data"]:
        raise ManagerError("Repair altered types or data")
    removed = {c["address"] for c in plan["changes"] if c["kind"] == "remove_function"}
    old = {f["address"]: f for f in before["functions"]}
    new = {f["address"]: f for f in after["functions"]}
    if new.keys() != old.keys() - removed:
        raise ManagerError("Unexpected function creation or removal")
    bodies = {c["address"]: c["ranges"] for c in plan["changes"] if c["kind"] == "body"}
    flows = {c["address"]: c["override"] for c in plan["changes"] if c["kind"] == "flow_override"}
    tables = {c["address"]: c["targets"] for c in plan["changes"] if c["kind"] == "jump_table"}
    for address, function in new.items():
        for key in ["name", "abi", "variables", "namespace", "thunk"]:
            if old[address].get(key) != function.get(key):
                raise ManagerError("Repair changed names or ABI")
        if function.get("body_ranges") != bodies.get(address, old[address].get("body_ranges")):
            raise ManagerError("Function ownership differs from proposal")
        for flow in function["flows"]:
            at = flow["address"]
            if at in flows and flow["override"] != flows[at]:
                raise ManagerError("Flow override did not stick")
            if at in tables and set(flow["targets"]) != {
                target + ":COMPUTED_JUMP" for target in tables[at]
            }:
                raise ManagerError("Computed listing references differ from proposal")
    observed = {flow["address"] for f in new.values() for flow in f["flows"]}
    if not flows.keys() | tables.keys() <= observed:
        raise ManagerError("Repaired instructions disappeared")
    expected_options = json.loads(json.dumps(before["configuration"]))
    for change in plan["changes"]:
        if change["kind"] == "analyzer_option":
            expected_options["Analysis"][change["address"]] = str(change["value"]).lower()
    if expected_options != after["configuration"]:
        raise ManagerError("Unplanned analyzer settings changed")


def native_tables(root: Path, plan: dict[str, Any]) -> None:
    directory = root / "artifacts" / "batches" / plan["id"] / "after-native"
    functions = {read(p)["address"]: read(p) for p in directory.glob("*.json")}
    for change in plan["changes"]:
        if change["kind"] != "jump_table":
            continue
        tables = functions.get(change["function"], {}).get("jump_tables", [])
        matching = [t for t in tables if t["address"] == change["address"]]
        if len(matching) != 1 or set(matching[0]["targets"]) != set(change["targets"]):
            raise ManagerError("Native jump-table targets differ from proposal")
