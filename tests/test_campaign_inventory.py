from copy import deepcopy

import pytest

from ghidra_manager.campaign.inventory import latest, scan
from ghidra_manager.campaign.transport import Client
from ghidra_manager.errors import ManagerError
from tests.test_campaign_cli import initialize


def fixture_snapshot():
    return {
        "schema_version": 1,
        "complete": True,
        "collector_version": 1,
        "identity": {
            "project": "fixture",
            "project_path": "/fixture.gpr",
            "program_path": "/fixture.exe",
            "digest": "abc",
            "language": "x86",
            "compiler": "windows",
            "format": "PE",
            "image_base": "00400000",
        },
        "configuration": {},
        "functions": [],
        "symbols": [],
        "types": [],
        "strings": [],
    }


def test_scan_is_idempotent_and_rejects_identity_drift(tmp_path, monkeypatch):
    initialize(tmp_path / "state")
    root = tmp_path / "state"
    value = fixture_snapshot()
    monkeypatch.setattr(Client, "script", lambda *a: deepcopy(value))
    client = Client(8089, "/fixture.exe")
    first = scan(root, client)
    assert scan(root, client) == first
    assert latest(root) == value
    value["identity"]["digest"] = "changed"
    with pytest.raises(ManagerError, match="identity changed"):
        scan(root, client)
    assert latest(root)["identity"]["digest"] == "abc"


def test_partial_scan_does_not_publish(tmp_path, monkeypatch):
    initialize(tmp_path / "state")
    value = fixture_snapshot()
    value["complete"] = False
    monkeypatch.setattr(Client, "script", lambda *a: value)
    with pytest.raises(ManagerError, match="Incomplete"):
        scan(tmp_path / "state", Client(8089, "/fixture.exe"))
    assert not (tmp_path / "state" / "snapshot.json").exists()


def test_script_rejects_inner_failure_and_missing_marker(monkeypatch):
    monkeypatch.setattr(Client, "idle", lambda _: None)
    monkeypatch.setattr(Client, "request", lambda *a: {"success": True, "console_output": "error"})
    with pytest.raises(ManagerError, match="complete result"):
        Client(8089, "/fixture.exe").script("CampaignInventory", {})


def test_collector_uses_result_file_not_large_console_output(monkeypatch):
    import base64
    import json
    from pathlib import Path

    monkeypatch.setattr(Client, "idle", lambda _: None)

    def request(self, endpoint, body):
        assert endpoint == "/run_ghidra_script"
        assert body["timeout_seconds"] == 60
        arguments = json.loads(base64.b64decode(body["args"]))
        Path(arguments["output"]).write_text(json.dumps({"complete": True, "large": "x" * 100000}))
        return {"success": True, "console_output": "CAMPAIGN_RESULT:complete"}

    monkeypatch.setattr(Client, "request", request)
    result = Client(8089, "/fixture.exe").script("CampaignInventory", {})
    assert len(result["large"]) == 100000
