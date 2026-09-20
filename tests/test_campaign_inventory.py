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


def test_callee_order_is_stable_but_edge_and_parameter_changes_are_visible(tmp_path, monkeypatch):
    from ghidra_manager.campaign.inventory import fingerprint, normalize

    root = tmp_path / "state"
    initialize(root)
    value = fixture_snapshot()
    value["functions"] = [
        {
            "address": "00401000",
            "callees": ["00403000", "00402000"],
            "abi": {"parameters": ["EAX", "EDX"]},
        }
    ]
    monkeypatch.setattr(Client, "script", lambda *a: deepcopy(value))
    client = Client(8089, "/fixture.exe")
    first = scan(root, client)
    value["functions"][0]["callees"].reverse()
    assert scan(root, client) == first
    normalize(value)
    assert fingerprint(value) == first["snapshot"]
    value["functions"][0]["callees"].append("00404000")
    assert scan(root, client)["snapshot"] != first["snapshot"]
    previous = fingerprint(value)
    value["functions"][0]["abi"]["parameters"].reverse()
    normalize(value)
    assert fingerprint(value) != previous


def test_repair_gets_full_audit_timeout_and_transport_does_not_retry(monkeypatch):
    import base64
    import json
    from pathlib import Path

    monkeypatch.setattr(Client, "idle", lambda _: None)
    requests = []

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self):
            return b'{"console_output":"CAMPAIGN_RESULT:complete"}'

    def urlopen(request, *, timeout):
        body = json.loads(request.data)
        requests.append(timeout)
        assert body["timeout_seconds"] == 1800
        arguments = json.loads(base64.b64decode(body["args"]))
        Path(arguments["output"]).write_text('{"complete":true}')
        return Response()

    monkeypatch.setattr("urllib.request.urlopen", urlopen)
    client = Client(8089, "/fixture.exe")
    assert client.script("CampaignRepair", {}) == {"complete": True}
    assert requests == [1860]

    def timeout(request, *, timeout):
        requests.append(timeout)
        raise TimeoutError("still running")

    monkeypatch.setattr("urllib.request.urlopen", timeout)
    with pytest.raises(ManagerError, match="reconcile before retrying"):
        client.script("CampaignRepair", {})
    assert requests == [1860, 1860]


@pytest.mark.parametrize("outcome", ["success", "failure", "timeout"])
def test_scheduled_repair_polls_retained_result_without_resubmission(
    tmp_path, monkeypatch, outcome
):
    import base64
    import json

    monkeypatch.setattr(Client, "idle", lambda _: None)
    submissions = []
    output_paths = []

    def request(self, endpoint, body):
        submissions.append(endpoint)
        arguments = json.loads(base64.b64decode(body["args"]))
        from pathlib import Path

        output_paths.append(Path(arguments["output"]))
        assert output_paths[-1].parent == tmp_path
        return {"console_output": "CAMPAIGN_RESULT:scheduled"}

    def sleep(_):
        if outcome != "timeout":
            output_paths[0].write_text(json.dumps({"complete": outcome == "success"}))

    ticks = iter([0, 0, 1801])
    monkeypatch.setattr(Client, "request", request)
    monkeypatch.setattr("ghidra_manager.campaign.transport.time.sleep", sleep)
    monkeypatch.setattr("ghidra_manager.campaign.transport.time.monotonic", lambda: next(ticks))
    client = Client(8089, "/fixture.exe")
    if outcome == "success":
        assert client.script("CampaignRepair", {"directory": str(tmp_path)}) == {"complete": True}
    else:
        with pytest.raises(ManagerError, match="reconcile before retrying"):
            client.script("CampaignRepair", {"directory": str(tmp_path)})
    assert submissions == ["/run_ghidra_script"]
    if outcome != "timeout":
        assert output_paths[0].is_file()
