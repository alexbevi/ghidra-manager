import json
from copy import deepcopy
from pathlib import Path

import pytest

from ghidra_manager.campaign.budget import operate
from ghidra_manager.campaign.inventory import scan
from ghidra_manager.campaign.plans import create, load_plan
from ghidra_manager.campaign.transport import Client
from ghidra_manager.errors import ManagerError
from tests.test_campaign_budget import record
from tests.test_campaign_cli import initialize
from tests.test_campaign_inventory import fixture_snapshot


def planning_fixture(tmp_path, monkeypatch):
    root = tmp_path / "state"
    initialize(root)
    operate(root, "start")
    record(root, 0, "baseline")
    (root / "evidence.jsonl").write_text(json.dumps({"id": "ev-test"}) + "\n")
    snapshot = fixture_snapshot()
    snapshot["functions"] = [
        {
            "address": "00401000",
            "name": "FUN_00401000",
            "callees": [],
            "variables": [],
            "namespace": "Global",
        }
    ]
    monkeypatch.setattr(Client, "script", lambda *a: deepcopy(snapshot))
    scan(root, Client(8089, "/fixture.exe"))
    proposal = {
        "author": "analyst",
        "changes": [
            {
                "kind": "function",
                "address": "00401000",
                "old_name": "FUN_00401000",
                "new_name": "parse_header",
                "evidence_ids": ["ev-test"],
            }
        ],
    }
    return root, snapshot, proposal


def test_plan_binds_evidence_and_rejects_edits(tmp_path, monkeypatch):
    root, _, proposal = planning_fixture(tmp_path, monkeypatch)
    result = create(root, proposal)
    path = Path(result["artifact"])
    assert load_plan(path)["author"] == "analyst"
    value = json.loads(path.read_text())
    value["changes"][0]["new_name"] = "edited"
    path.write_text(json.dumps(value))
    with pytest.raises(ManagerError, match="edited"):
        load_plan(path)


@pytest.mark.parametrize(
    "field,value",
    [("old_name", "stale"), ("new_name", "invalid name"), ("evidence_ids", []), ("type", "int")],
)
def test_rejects_unsupported_or_stale_proposals(tmp_path, monkeypatch, field, value):
    root, _, proposal = planning_fixture(tmp_path, monkeypatch)
    proposal["changes"][0][field] = value
    with pytest.raises(ManagerError):
        create(root, proposal)
    assert not (root / "artifacts" / "plans").exists()
