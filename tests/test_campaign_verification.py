from copy import deepcopy
from pathlib import Path

import pytest

from ghidra_manager.campaign.mutations import apply
from ghidra_manager.campaign.plans import create
from ghidra_manager.campaign.transport import Client
from ghidra_manager.campaign.verification import finalize, verify
from ghidra_manager.errors import ManagerError
from tests.test_campaign_plans import planning_fixture


def test_independent_review_and_save_confirmation(tmp_path, monkeypatch):
    root, snapshot, proposal = planning_fixture(tmp_path, monkeypatch)
    plan = create(root, proposal)
    saves = []

    def script(self, name, args):
        if name == "CampaignRename":
            snapshot["functions"][0]["name"] = "parse_header"
            snapshot["transactions"] = {plan["id"]: "applied"}
            return {"complete": True, "transaction": plan["id"], "committed": True}
        if name == "CampaignSaveState":
            return {"complete": True, "changed": False, "program": "/fixture.exe"}
        return deepcopy(snapshot)

    monkeypatch.setattr(Client, "script", script)
    monkeypatch.setattr(Client, "request", lambda *args: saves.append(args))
    client = Client(8089, "/fixture.exe")
    apply(root, client, Path(plan["artifact"]))
    result = verify(root, client)
    review = {
        "plan": plan["id"],
        "after_snapshot": result["after_snapshot"],
        "reviewer": "analyst",
        "verdict": "pass",
        "evidence_ids": ["ev-test"],
        "notes": "Header reads are supported by the fixture instructions.",
    }
    with pytest.raises(ManagerError, match="independent"):
        finalize(root, client, review)
    assert not saves
    review["reviewer"] = "reviewer"
    assert finalize(root, client, review)["status"] == "saved"
    assert len(saves) == 1
    assert '"state": "verified"' in (root / "renames.jsonl").read_text()


def test_nonpassing_review_never_saves(tmp_path, monkeypatch):
    # Existing state guards fail closed even before attempting a live connection.
    root, _, _ = planning_fixture(tmp_path, monkeypatch)
    with pytest.raises(FileNotFoundError):
        finalize(root, Client(8089, "/fixture.exe"), {"verdict": "fail"})


def test_save_race_does_not_publish_verified_receipt(tmp_path, monkeypatch):
    from ghidra_manager.campaign.inventory import read

    root, snapshot, proposal = planning_fixture(tmp_path, monkeypatch)
    plan = create(root, proposal)

    def script(self, name, args):
        if name == "CampaignRename":
            snapshot["functions"][0]["name"] = "parse_header"
            snapshot["transactions"] = {plan["id"]: "applied"}
            return {"committed": True, "transaction": plan["id"]}
        if name == "CampaignSaveState":
            return {"changed": False, "program": self.program}
        return deepcopy(snapshot)

    def save(self, endpoint):
        assert endpoint == "/save_program"
        snapshot["functions"][0]["name"] = "concurrent_ui_edit"

    monkeypatch.setattr(Client, "script", script)
    monkeypatch.setattr(Client, "request", save)
    client = Client(8089, "/fixture.exe")
    apply(root, client, Path(plan["artifact"]))
    verified = verify(root, client)
    review = {
        "plan": plan["id"],
        "after_snapshot": verified["after_snapshot"],
        "reviewer": "reviewer",
        "verdict": "pass",
        "evidence_ids": ["ev-test"],
        "notes": "Reviewed the actual function.",
    }
    with pytest.raises(ManagerError, match="changed during save"):
        finalize(root, client, review)
    assert read(root / "batch.json")["status"] == "save-uncertain"
    assert not (root / "artifacts" / "batches" / plan["id"] / "receipt.json").exists()
    assert (root / "renames.jsonl").read_text() == ""
