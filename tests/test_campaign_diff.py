from copy import deepcopy

import pytest

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


@pytest.mark.parametrize("semantic_field", [None, "storage", "type", "parameter"])
def test_combined_function_and_local_names_preserve_semantic_checks(semantic_field):
    old = fixture_snapshot()
    old["functions"] = [
        {
            "address": "a",
            "name": "FUN_a",
            "source": "DEFAULT",
            "callees": [],
            "signature": "undefined FUN_a(void)",
            "abi": {"convention": "unknown"},
            "variables": [
                {
                    "name": "local_14",
                    "storage": "Stack[-0x14]:4",
                    "type": "/undefined4",
                    "parameter": False,
                }
            ],
        }
    ]
    new = deepcopy(old)
    function = new["functions"][0]
    function.update(
        name="load_buffer", source="USER_DEFINED", signature="undefined load_buffer(void)"
    )
    function["variables"][0]["name"] = "extra_capacity_bytes"
    if semantic_field:
        function["variables"][0][semantic_field] = {
            "storage": "Stack[-0x18]:4",
            "type": "/int",
            "parameter": True,
        }[semantic_field]
    delta = compare(old, new)
    assert delta["changed"][0]["kind"] == (
        "semantic-metadata" if semantic_field else "variable-name"
    )
    assert delta["native_review"] == (["a"] if semantic_field else [])
