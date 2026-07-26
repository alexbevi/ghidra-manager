import json
from pathlib import Path

import pytest

from ghidra_manager.coverage.model import (
    LEDGER_SCHEMA,
    SCHEMA_VERSION,
    Address,
    canonical_bytes,
    require_schema,
    validate_ledger,
)
from ghidra_manager.errors import ManagerError


def test_address_preserves_spaces_overlays_and_segments() -> None:
    overlay = Address.parse(".image::00001234", known_spaces={"ram", ".image"})
    segmented = Address.parse("1234:00ab")

    assert overlay.key == ".image:00001234"
    assert overlay.to_json()["space"] == ".image"
    assert segmented.key == "ram:1234:000000ab"
    assert segmented.to_json()["segment"] == "0x1234"
    assert Address.parse("ram:0x12", known_spaces={"ram"}).key == "ram:00000012"


def test_address_rejects_ambiguous_unknown_space() -> None:
    with pytest.raises(ManagerError, match="Unknown Ghidra address space"):
        Address.parse("other:1000", known_spaces={"ram"})


def test_canonical_json_is_stable() -> None:
    left = canonical_bytes({"z": [2, 1], "a": "value"})
    right = canonical_bytes(json.loads(left))

    assert left == right
    assert left.endswith(b"\n")


def test_ledger_validation_detects_duplicates_and_invalid_states(tmp_path: Path) -> None:
    ledger = {
        "schema": LEDGER_SCHEMA,
        "version": SCHEMA_VERSION,
        "profile_id": "demo",
        "records": [
            {
                "id": "unit:1",
                "scope": {"state": "in_scope"},
                "status": "complete",
                "verification": {"state": "static_verified"},
            },
            {
                "id": "unit:1",
                "scope": {"state": "invalid"},
                "status": "done",
                "verification": {"state": "maybe"},
            },
        ],
    }

    errors = validate_ledger(ledger)

    assert "duplicate ledger record id: unit:1" in errors
    assert any("invalid coverage status" in error for error in errors)


def test_future_schema_version_is_rejected() -> None:
    with pytest.raises(ManagerError, match="Unsupported"):
        require_schema(
            {"schema": LEDGER_SCHEMA, "version": SCHEMA_VERSION + 1},
            LEDGER_SCHEMA,
        )
