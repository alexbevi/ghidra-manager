"""Evidence-bound flow repairs and rollback-only native trials."""

from __future__ import annotations

import json
import re
from pathlib import Path
from shutil import copy2
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
        kinds = {c.get("kind") for c in proposal["changes"]}
        if "create_function" in kinds and kinds != {"create_function"}:
            raise ManagerError("Function creation requires a separate repair batch")
        keys = set()
        for change in proposal["changes"]:
            kind = change.get("kind")
            common = {"kind", "address", "evidence_ids"}
            fields = {
                "body": {"ranges", "old_body"},
                "create_function": {"ranges", "instruction_hash"},
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
            if kind == "create_function":
                validate_creation(change, functions)
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


def validate_creation(change: dict[str, Any], functions: dict[str, Any]) -> None:
    """Validate canonical flat-address ranges; live checks prove instruction ownership."""
    address = change["address"]
    ranges = change["ranges"]
    if address in functions:
        raise ManagerError("Created function already exists")
    if not isinstance(address, str) or not re.fullmatch(r"[0-9a-f]{8,16}", address):
        raise ManagerError("Creation requires a canonical flat hexadecimal address")
    if not isinstance(change["instruction_hash"], str) or not re.fullmatch(
        r"[0-9a-f]{64}", change["instruction_hash"]
    ):
        raise ManagerError("Creation requires an exact instruction hash")
    if not isinstance(ranges, list) or not 1 <= len(ranges) <= 256:
        raise ManagerError("Creation requires 1 to 256 inclusive ranges")
    previous = -2
    contains_entry = False
    for pair in ranges:
        if (
            not isinstance(pair, list)
            or len(pair) != 2
            or any(
                not isinstance(value, str)
                or not re.fullmatch(r"[0-9a-f]{" + str(len(address)) + r"}", value)
                for value in pair
            )
        ):
            raise ManagerError("Creation ranges require canonical address pairs")
        start, end = (int(value, 16) for value in pair)
        if start > end or start <= previous + 1:
            raise ManagerError("Creation ranges must be sorted, disjoint and nonadjacent")
        contains_entry |= start <= int(address, 16) <= end
        previous = end
    if not contains_entry:
        raise ManagerError("Creation body excludes entrypoint")


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
        after_native = directory / "after-native"
        after_native.mkdir(exist_ok=True)
        for previous in after_native.glob("*.json"):
            previous.unlink()
        native_fingerprints = {}
        for artifact in (directory / "trial-native").glob("*.json"):
            copy2(artifact, after_native / artifact.name)
            native_fingerprints[artifact.name] = fingerprint(read(artifact))
        native_tables(root, plan)
        report = {
            "native_fingerprints": native_fingerprints,
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
    created = {c["address"]: c for c in plan["changes"] if c["kind"] == "create_function"}
    old = {f["address"]: f for f in before["functions"]}
    new = {f["address"]: f for f in after["functions"]}
    if new.keys() != (old.keys() - removed) | created.keys():
        raise ManagerError("Unexpected function creation or removal")
    bodies = {c["address"]: c["ranges"] for c in plan["changes"] if c["kind"] == "body"}
    flows = {c["address"]: c["override"] for c in plan["changes"] if c["kind"] == "flow_override"}
    tables = {c["address"]: c["targets"] for c in plan["changes"] if c["kind"] == "jump_table"}
    for address, function in new.items():
        if address in created:
            change = created[address]
            if (
                function.get("body_ranges") != change["ranges"]
                or function.get("byte_hash") != change["instruction_hash"]
                or function.get("source") != "DEFAULT"
                or not function.get("name", "").startswith("FUN_")
                or function.get("thunk") is not False
                or function.get("external") is not False
            ):
                raise ManagerError(
                    "Created function differs from reviewed extent or default identity"
                )
            continue
        if created:
            for key in old[address].keys() | function.keys():
                if key != "callees" and old[address].get(key) != function.get(key):
                    raise ManagerError("Creation changed existing function metadata")
            old_callees = set(old[address].get("callees", []))
            new_callees = set(function.get("callees", []))
            if not old_callees <= new_callees or not new_callees - old_callees <= created.keys():
                raise ManagerError("Creation changed unrelated callees")
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
            expected_options["Analyzers"][change["address"]] = str(change["value"]).lower()
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


def approve_trial(root: Path, plan: dict[str, Any], review: dict[str, Any] | None) -> None:
    directory = root / "artifacts" / "batches" / plan["id"]
    report = read(directory / "trial.json")
    if report.get("id") != fingerprint({k: v for k, v in report.items() if k != "id"}):
        raise ManagerError("Trial report changed")
    candidate = read(directory / "trial-snapshot.json")
    from ghidra_manager.campaign.mutations import normalize

    normalize(candidate)
    if fingerprint(candidate) != report["candidate_snapshot"]:
        raise ManagerError("Trial candidate changed")
    for name, digest in report.get("native_fingerprints", {}).items():
        if (
            Path(name).name != name
            or fingerprint(read(directory / "trial-native" / name)) != digest
        ):
            raise ManagerError("Trial native evidence changed")
    if not report.get("native_fingerprints"):
        raise ManagerError("Trial has no retained native evidence")
    if (
        report.get("plan") != plan["id"]
        or not review
        or review.get("plan") != plan["id"]
        or review.get("trial") != report["id"]
        or report.get("rolled_back") is not True
        or review.get("verdict") != "pass"
        or not review.get("notes")
        or not isinstance(review.get("reviewer"), str)
        or not review["reviewer"].strip()
        or review["reviewer"].strip().casefold() == plan["author"].strip().casefold()
    ):
        raise ManagerError("Require independent passing review of the exact rolled-back trial")
    evidence = {e for c in plan["changes"] for e in c["evidence_ids"]}
    changed = {c["address"] for c in report["native_delta"]["changed"]}
    if not evidence <= set(review.get("evidence_ids", [])) or not changed <= set(
        review.get("reviewed_native_functions", [])
    ):
        raise ManagerError("Trial review must cover all evidence and changed native functions")
    atomic_json(directory / "trial-review.json", review)


def stable(client: Client, expected: dict[str, Any]) -> None:
    from ghidra_manager.campaign.mutations import normalize

    client.idle()
    live = client.script("CampaignInventory", {})
    normalize(live)
    if fingerprint(live) != fingerprint(expected):
        raise ManagerError("Analysis changed the repair after native capture; do not save")
