from copy import deepcopy
from pathlib import Path

import pytest

from ghidra_manager.campaign.inventory import fingerprint, read, scan
from ghidra_manager.campaign.plans import create
from ghidra_manager.campaign.repairs import reconcile_trial, trial
from ghidra_manager.campaign.transport import Client
from ghidra_manager.errors import ManagerError
from ghidra_manager.storage import atomic_json
from tests.test_campaign_plans import planning_fixture


def setup(tmp_path, monkeypatch):
    root, snapshot, _ = planning_fixture(tmp_path, monkeypatch)
    snapshot["functions"][0]["body"] = "[[00401000, 00401000]]"
    scan(root, Client(8089, "/fixture.exe"))
    proposal = {
        "author": "analyst",
        "queue": "repair",
        "changes": [
            {
                "kind": "flow_override",
                "address": "00401000",
                "bytes": "c3",
                "old_override": "NONE",
                "override": "BRANCH",
                "evidence_ids": ["ev-test"],
            }
        ],
    }
    return root, snapshot, proposal


def test_repair_requires_raw_bytes_and_existing_evidence(tmp_path, monkeypatch):
    root, _, proposal = setup(tmp_path, monkeypatch)
    assert create(root, proposal)["changes"] == 1
    proposal["changes"][0]["bytes"] = "*"
    with pytest.raises(ManagerError, match="exact instruction bytes"):
        create(root, proposal)


def test_trial_timeout_blocks_new_mutations_and_never_retries(tmp_path, monkeypatch):
    root, snapshot, proposal = setup(tmp_path, monkeypatch)
    plan = create(root, proposal)
    writes = []

    def script(self, name, args):
        if name == "CampaignEvidence":
            return {"functions": [{"address": "00401000", "decompilation": "void f() {}"}]}
        if name == "CampaignRepair":
            writes.append(name)
            raise ManagerError("timeout")
        return deepcopy(snapshot)

    monkeypatch.setattr(Client, "script", script)
    client = Client(8089, "/fixture.exe")
    with pytest.raises(ManagerError, match="timeout"):
        trial(root, client, Path(plan["artifact"]))
    with pytest.raises(ManagerError, match="uncertain trial"):
        trial(root, client, Path(plan["artifact"]))
    with pytest.raises(ManagerError, match="completion is unknown"):
        reconcile_trial(root, client)
    assert len(writes) == 1
    directory = root / "artifacts" / "batches" / plan["id"]
    atomic_json(directory / "trial-finished.json", {"plan": plan["id"], "finished": True})
    assert reconcile_trial(root, client)["rolled_back"] is True
    assert fingerprint(snapshot) == read(Path(plan["artifact"]))["snapshot"]


def test_durable_repair_requires_exact_independent_trial_review(tmp_path, monkeypatch):
    from ghidra_manager.campaign.repairs import approve_trial

    root, snapshot, proposal = setup(tmp_path, monkeypatch)
    result = create(root, proposal)
    plan = read(Path(result["artifact"]))
    directory = root / "artifacts" / "batches" / plan["id"]
    directory.mkdir(parents=True)
    atomic_json(directory / "trial-snapshot.json", snapshot)
    report = {
        "plan": plan["id"],
        "rolled_back": True,
        "candidate_snapshot": fingerprint(snapshot),
        "native_delta": {"changed": [{"address": "00401000"}]},
    }
    (directory / "trial-native").mkdir()
    atomic_json(directory / "trial-native" / "function.json", {"address": "00401000"})
    report["native_fingerprints"] = {"function.json": fingerprint({"address": "00401000"})}
    report["id"] = fingerprint(report)
    atomic_json(directory / "trial.json", report)
    review = {
        "plan": plan["id"],
        "trial": report["id"],
        "reviewer": "reviewer",
        "verdict": "pass",
        "notes": "Checked raw p-code and every incoming edge",
        "evidence_ids": ["ev-test"],
        "reviewed_native_functions": ["00401000"],
    }
    approve_trial(root, plan, review)
    with pytest.raises(ManagerError, match="independent"):
        approve_trial(root, plan, {**review, "reviewer": "analyst"})
    with pytest.raises(ManagerError, match="all evidence"):
        approve_trial(root, plan, {**review, "reviewed_native_functions": []})
    atomic_json(directory / "trial-snapshot.json", {**snapshot, "edited": True})
    with pytest.raises(ManagerError, match="candidate changed"):
        approve_trial(root, plan, review)


def test_stability_rejects_analyzer_interference(tmp_path, monkeypatch):
    from ghidra_manager.campaign.repairs import stable

    _, snapshot, _ = setup(tmp_path, monkeypatch)
    monkeypatch.setattr(Client, "idle", lambda self: None)
    client = Client(8089, "/fixture.exe")
    stable(client, deepcopy(snapshot))
    prior = deepcopy(snapshot)
    snapshot["functions"].append({"address": "00401001", "name": "false_shared_tail"})
    with pytest.raises(ManagerError, match="Analysis changed"):
        stable(client, prior)
