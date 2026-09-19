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


def test_unchanged_verification_reuses_native_audit(tmp_path, monkeypatch):
    from copy import deepcopy
    from pathlib import Path

    from ghidra_manager.campaign.inventory import read
    from ghidra_manager.campaign.mutations import apply, reconcile
    from ghidra_manager.campaign.transport import Client

    root, snapshot, _ = planning_fixture(tmp_path, monkeypatch)
    result = create(root, proposal())
    captures = []

    def script(self, name, args):
        if name == "CampaignTypes":
            snapshot["types"] = [
                {
                    "path": "/Fixture/Header",
                    "length": 4,
                    "fields": proposal()["changes"][0]["fields"],
                }
            ]
            snapshot["transactions"] = {result["id"]: "applied"}
            return {"committed": True, "transaction": result["id"]}
        if name == "CampaignEvidence":
            captures.append(name)
            return {"functions": [{"address": "00401000", "decompilation": "void f() {}"}]}
        return deepcopy(snapshot)

    monkeypatch.setattr(Client, "script", script)
    client = Client(8089, "/fixture.exe")
    apply(root, client, Path(result["artifact"]))
    assert len(captures) == 2
    reconcile(root, client)
    assert len(captures) == 2
    artifact = next((root / "artifacts" / "batches" / result["id"] / "after-native").glob("*.json"))
    artifact.write_text('{"address":"00401000","decompilation":"tampered"}')
    reconcile(root, client)
    assert len(captures) == 3
    assert read(artifact)["decompilation"] == "void f() {}"


def test_layout_rejects_unplanned_existing_type_changes():
    before = {"functions": [], "types": [{"path": "/Existing", "length": 4}]}
    after = {"functions": [], "types": [{"path": "/Existing", "length": 8}]}
    with pytest.raises(ManagerError, match="existing type changed"):
        readback(proposal(), before, after)
