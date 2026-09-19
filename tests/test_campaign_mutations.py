from copy import deepcopy
from pathlib import Path

import pytest

from ghidra_manager.campaign.inventory import read
from ghidra_manager.campaign.mutations import apply, reconcile
from ghidra_manager.campaign.plans import create
from ghidra_manager.campaign.transport import Client
from ghidra_manager.errors import ManagerError
from tests.test_campaign_plans import planning_fixture


def test_apply_readback_and_duplicate_admission(tmp_path, monkeypatch):
    root, snapshot, proposal = planning_fixture(tmp_path, monkeypatch)
    plan = create(root, proposal)

    def script(self, name, args):
        if name == "CampaignRename":
            snapshot["functions"][0]["name"] = "parse_header"
            snapshot["transactions"] = {plan["id"]: "applied"}
            return {"complete": True, "transaction": plan["id"], "committed": True}
        return deepcopy(snapshot)

    monkeypatch.setattr(Client, "script", script)
    client = Client(8089, "/fixture.exe")
    result = apply(root, client, Path(plan["artifact"]))
    assert result["status"] == "needs-review"
    assert result["saved"] is False
    with pytest.raises(ManagerError, match="existing batch"):
        apply(root, client, Path(plan["artifact"]))
    assert reconcile(root, client)["status"] == "needs-review"


def test_timeout_never_automatically_retries(tmp_path, monkeypatch):
    root, snapshot, proposal = planning_fixture(tmp_path, monkeypatch)
    plan = create(root, proposal)
    writes = []

    def script(self, name, args):
        if name == "CampaignRename":
            writes.append(name)
            raise ManagerError("timeout")
        return deepcopy(snapshot)

    monkeypatch.setattr(Client, "script", script)
    client = Client(8089, "/fixture.exe")
    with pytest.raises(ManagerError, match="timeout"):
        apply(root, client, Path(plan["artifact"]))
    assert read(root / "batch.json")["status"] == "in-flight"
    assert reconcile(root, client)["status"] == "unresolved"
    assert len(writes) == 1
