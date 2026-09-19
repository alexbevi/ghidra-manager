import pytest

from ghidra_manager.campaign.abi import matches_storage, validate
from ghidra_manager.errors import ManagerError
from tests.test_campaign_inventory import fixture_snapshot


def test_explicit_register_and_stack_storage():
    assert matches_storage("EAX:4", {"register": "EAX"})
    assert matches_storage("Stack[0x4]:4", {"stack": 4})
    assert not matches_storage("EDX:4", {"register": "EAX"})
    assert matches_storage("<VOID>", None)


def test_compiler_models_reject_external_declarations():
    with pytest.raises(ManagerError, match="declarations"):
        validate(
            {
                "kind": "compiler_model",
                "name": "bad",
                "xml": '<!DOCTYPE x><prototype name="bad"/>',
                "evidence_ids": ["e"],
            },
            fixture_snapshot(),
        )
    assert (
        validate(
            {
                "kind": "compiler_model",
                "name": "good",
                "xml": '<prototype name="good"/>',
                "evidence_ids": ["e"],
            },
            fixture_snapshot(),
        )
        == "model:good"
    )
