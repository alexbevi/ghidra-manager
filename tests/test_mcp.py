import pytest

from ghidra_manager.errors import ManagerError
from ghidra_manager.mcp import (
    DEFAULT_PORT,
    discover_instances,
    probe_analysis,
    probe_server,
    validate_base_port,
)


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


def test_server_and_analysis_probes() -> None:
    responses: dict[str, object] = {
        "/get_version": {
            "plugin_version": "5.14.2",
            "ghidra_version": "12.1.2",
            "java_version": "21.0.11",
            "endpoint_count": 206,
        },
        "/analysis_status": {
            "name": "DEMO.EXE",
            "analyzing": False,
            "analyzed": True,
            "function_count": 123,
        },
    }

    def fetch(_port, path, _params):  # type: ignore[no-untyped-def]
        return responses[path]

    server = probe_server(DEFAULT_PORT, fetch=fetch)
    analysis = probe_analysis(DEFAULT_PORT, "DEMO.EXE", fetch=fetch)

    assert server is not None and server.endpoint_count == 206
    assert analysis is not None and analysis.function_count == 123
