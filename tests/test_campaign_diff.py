from copy import deepcopy

from ghidra_manager.campaign.diffing import compare
from tests.test_campaign_inventory import fixture_snapshot


def test_name_only_does_not_request_decompilation():
    old = fixture_snapshot()
    old["functions"] = [{"address": "a", "name": "FUN_a", "callees": []}]
    new = deepcopy(old)
    new["functions"][0]["name"] = "read_header"
    assert compare(old, new)["native_review"] == []
    assert compare(old, new)["changed"][0]["kind"] == "decoration"


def test_abi_change_includes_callers_and_type_change_requests_full_audit():
    old = fixture_snapshot()
    old["functions"] = [
        {"address": "a", "signature": "void()", "callees": []},
        {"address": "b", "callees": ["a"]},
        {"address": "c", "callees": []},
    ]
    new = deepcopy(old)
    new["functions"][0]["signature"] = "int()"
    assert compare(old, new)["native_review"] == ["a", "b"]
    new["types"] = [{"path": "/Changed", "length": 4}]
    assert compare(old, new)["native_review"] == ["a", "b", "c"]
