from copy import deepcopy

from ghidra_manager.campaign.budget import operate
from ghidra_manager.campaign.evidence import packet
from ghidra_manager.campaign.transport import Client
from tests.test_campaign_budget import record
from tests.test_campaign_cli import initialize
from tests.test_campaign_inventory import fixture_snapshot


def test_cache_reuse_dependency_invalidation_and_packet_bound(tmp_path, monkeypatch):
    root = tmp_path / "state"
    initialize(root)
    operate(root, "start")
    record(root, 0, "baseline")
    snapshot = fixture_snapshot()
    snapshot["functions"] = [
        {
            "address": "00401000",
            "name": "test",
            "callees": [],
            "references": [],
            "signature": "void test()",
        }
    ]
    captures = []

    def script(self, name, args):
        if name == "CampaignInventory":
            return deepcopy(snapshot)
        captures.append(args)
        return {
            "complete": True,
            "functions": [
                {
                    "address": "00401000",
                    "decompilation": "void test() {}",
                    "instructions": [],
                    "callers": [],
                }
            ],
        }

    monkeypatch.setattr(Client, "script", script)
    client = Client(8089, "/fixture.exe")
    first = packet(root, client, ["00401000"])
    second = packet(root, client, ["00401000"])
    assert first["artifact"] == second["artifact"]
    assert second["cache_hits"] == 1
    assert len(captures) == 1
    snapshot["configuration"]["changed"] = True
    assert packet(root, client, ["00401000"])["captured"] == 1
    snapshot["functions"][0]["signature"] = "x" * 5000
    bounded = packet(root, client, ["00401000"], 1024)
    assert bounded["omitted"] == ["00401000"]
    assert bounded["bytes"] <= 1024
