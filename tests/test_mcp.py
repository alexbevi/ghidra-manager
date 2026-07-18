import pytest

from ghidra_manager.errors import ManagerError
from ghidra_manager.mcp import DEFAULT_PORT, discover_instances, validate_base_port


def test_discovery_accepts_wrapped_and_direct_records() -> None:
    records: dict[int, object] = {
        DEFAULT_PORT + 2: {
            "data": {
                "pid": 42,
                "project": "second\nproject",
                "programs": [
                    {"name": "OPEN.EXE", "open": True},
                    {"name": "CLOSED.EXE", "open": False},
                ],
            }
        },
        DEFAULT_PORT: {"pid": 7, "project": "first"},
        DEFAULT_PORT + 1: {"pid": "invalid"},
    }

    instances = discover_instances(DEFAULT_PORT, fetch=records.get)

    assert [(item.port, item.pid, item.project) for item in instances] == [
        (DEFAULT_PORT, 7, "first"),
        (DEFAULT_PORT + 2, 42, "second project"),
    ]
    assert instances[1].programs == ("OPEN.EXE",)


@pytest.mark.parametrize("value", [0, -1, 65521])
def test_invalid_base_port(value: int) -> None:
    with pytest.raises(ManagerError):
        validate_base_port(value)
