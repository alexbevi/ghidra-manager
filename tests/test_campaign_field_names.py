from copy import deepcopy
from pathlib import Path

import pytest

from ghidra_manager.campaign.field_names import expected_types
from ghidra_manager.campaign.inventory import scan
from ghidra_manager.campaign.mutations import readback
from ghidra_manager.campaign.plans import create, load_plan
from ghidra_manager.campaign.transport import Client
from ghidra_manager.errors import ManagerError
from tests.test_campaign_plans import planning_fixture


def field_fixture(tmp_path, monkeypatch):
    root, snapshot, proposal = planning_fixture(tmp_path, monkeypatch)
    snapshot["types"] = [
        {
            "path": "/Fixture/Image",
            "length": 8,
            "fields": [
                {"offset": 0, "length": 4, "type": "/uint", "name": "unknown"},
                {"offset": 4, "length": 4, "type": "/uint", "name": "width"},
            ],
            "definition": "/Fixture/Image\npack(disabled)\nStructure Image {\n"
            '   0   uint   4   unknown   "unknown remains in comment"\n'
            '   4   uint   4   width   ""\n}\nLength: 8 Alignment: 1\n',
        }
    ]
    scan(root, Client(8089, "/fixture.exe"))
    proposal["changes"] = [
        {
            "kind": "field",
            "address": "/Fixture/Image",
            "offset": 0,
            "old_name": "unknown",
            "new_name": "colorKey",
            "evidence_ids": ["ev-test"],
        }
    ]
    return root, snapshot, proposal


def test_field_name_readback_preserves_layout_and_comment(tmp_path, monkeypatch):
    root, before, proposal = field_fixture(tmp_path, monkeypatch)
    plan = load_plan(Path(create(root, proposal)["artifact"]))
    after = deepcopy(before)
    after["types"] = expected_types(plan, before)
    after["transactions"] = {plan["id"]: "applied"}
    result = readback(plan, before, after)
    assert not result["delta"]["full_audit"]
    assert result["delta"]["native_review"] == []
    assert "unknown remains in comment" in after["types"][0]["definition"]
    assert after["types"][0]["fields"][0]["name"] == "colorKey"
    changed = deepcopy(after)
    changed["transactions"]["unrelated"] = "applied"
    with pytest.raises(ManagerError, match="unrelated program metadata"):
        readback(plan, before, changed)
    for section, key, value in [
        ("types", "length", 9),
        ("functions", "name", "unplanned"),
    ]:
        changed = deepcopy(after)
        changed[section][0][key] = value
        with pytest.raises(ManagerError):
            readback(plan, before, changed)
    for key, value in [("offset", 1), ("length", 2), ("type", "/ushort")]:
        changed = deepcopy(after)
        changed["types"][0]["fields"][0][key] = value
        with pytest.raises(ManagerError):
            readback(plan, before, changed)


@pytest.mark.parametrize(
    "key,value",
    [
        ("offset", 1),
        ("offset", True),
        ("offset", -1),
        ("address", "/Absent"),
        ("old_name", "stale"),
        ("new_name", "width"),
        ("new_name", "bad name"),
        ("type", "/byte"),
        ("length", 1),
    ],
)
def test_field_plan_rejects_invalid_targets(tmp_path, monkeypatch, key, value):
    root, _, proposal = field_fixture(tmp_path, monkeypatch)
    proposal["changes"][0][key] = value
    with pytest.raises(ManagerError):
        create(root, proposal)


def test_duplicate_field_and_mixed_batch_rejected(tmp_path, monkeypatch):
    root, _, proposal = field_fixture(tmp_path, monkeypatch)
    proposal["changes"].append(dict(proposal["changes"][0], new_name="another"))
    with pytest.raises(ManagerError, match="Duplicate target"):
        create(root, proposal)
    proposal["changes"][1]["kind"] = "function"
    with pytest.raises(ManagerError, match="separate naming batch"):
        create(root, proposal)
