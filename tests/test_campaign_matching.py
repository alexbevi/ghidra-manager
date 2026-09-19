from copy import deepcopy

import pytest

from ghidra_manager.campaign.matching import candidates
from ghidra_manager.errors import ManagerError
from tests.test_campaign_inventory import fixture_snapshot


def test_ambiguous_matches_remain_candidates_and_abi_is_not_applied():
    target = fixture_snapshot()
    target["functions"] = [
        {
            "address": "a",
            "name": "FUN_a",
            "shape_hash": "shape",
            "code_hash": "bytes",
            "instruction_count": 2,
        }
    ]
    reference = deepcopy(target)
    reference["functions"] = [
        {**target["functions"][0], "name": "one"},
        {**target["functions"][0], "address": "b", "name": "two"},
    ]
    result = candidates(target, reference, "Reviewed compiler reference")
    assert result["matches"][0]["ambiguous"]
    assert result["matches"][0]["candidates"][0]["requires_semantic_review"]
    assert target["functions"][0]["name"] == "FUN_a"
    reference["identity"]["compiler"] = "incompatible"
    with pytest.raises(ManagerError, match="compiler"):
        candidates(target, reference, "reference")
