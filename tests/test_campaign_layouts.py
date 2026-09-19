import pytest

from ghidra_manager.campaign.layouts import create, readback
from ghidra_manager.errors import ManagerError
from tests.test_campaign_plans import planning_fixture


def proposal():
    return {
        "author": "analyst",
        "queue": "types",
        "changes": [
            {
                "kind": "structure",
                "path": "/Fixture/Header",
                "length": 4,
                "fields": [{"offset": 0, "length": 4, "type": "/uint", "name": "size"}],
                "evidence_ids": ["ev-test"],
            }
        ],
    }


def test_layout_plan_rejects_overlaps_and_existing_types(tmp_path, monkeypatch):
    root, _, _ = planning_fixture(tmp_path, monkeypatch)
    assert create(root, proposal())["changes"] == 1
    invalid = proposal()
    invalid["changes"][0]["fields"].append(
        {"offset": 2, "length": 2, "type": "/ushort", "name": "other"}
    )
    with pytest.raises(ManagerError, match="Overlapping"):
        create(root, invalid)


def test_layout_readback_rejects_code_damage():
    before = {"functions": [{"address": "a", "byte_hash": "before"}]}
    after = {"functions": [{"address": "a", "byte_hash": "after"}], "types": []}
    with pytest.raises(ManagerError, match="code"):
        readback(proposal(), before, after)
