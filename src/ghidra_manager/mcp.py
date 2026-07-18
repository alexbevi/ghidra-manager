"""GhidraMCP instance discovery."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any

from ghidra_manager.errors import ManagerError

DEFAULT_PORT = 8089
PORT_RANGE = 16
Fetch = Callable[[int], object | None]
EndpointFetch = Callable[[int, str, Mapping[str, str] | None], object | None]


@dataclass(frozen=True, slots=True, order=True)
class Instance:
    port: int
    pid: int
    project: str
    programs: tuple[str, ...] = ()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"


@dataclass(frozen=True, slots=True)
class ServerInfo:
    plugin_version: str
    ghidra_version: str
    java_version: str
    endpoint_count: int


@dataclass(frozen=True, slots=True)
class AnalysisStatus:
    program: str
    analyzing: bool
    analyzed: bool
    function_count: int


def validate_base_port(value: int) -> int:
    if value <= 0 or value > 65535 - PORT_RANGE + 1:
        raise ManagerError("Base port leaves no room for the 16-port fallback range")
    return value


def _fetch_instance(port: int) -> object | None:
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/mcp/instance_info",
        headers={"Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=1) as response:
            value: object = json.load(response)
            return value
    except (OSError, TimeoutError, ValueError, urllib.error.URLError):
        return None


def _fetch_endpoint(
    port: int, path: str, params: Mapping[str, str] | None = None
) -> object | None:
    query = f"?{urllib.parse.urlencode(params)}" if params else ""
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}{query}",
        headers={"Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=2) as response:
            value: object = json.load(response)
            return value
    except (OSError, TimeoutError, ValueError, urllib.error.URLError):
        return None


def _parse_instance(port: int, value: object | None) -> Instance | None:
    if not isinstance(value, dict):
        return None
    record: Any = value.get("data", value)
    if not isinstance(record, dict) or not isinstance(record.get("pid"), int):
        return None
    project = (
        str(record.get("project") or "unknown")
        .replace("\t", " ")
        .replace("\r", " ")
        .replace("\n", " ")
    )
    raw_programs = record.get("programs")
    programs = (
        tuple(
            str(item["name"])
            for item in raw_programs
            if isinstance(item, dict)
            and item.get("name")
            and item.get("open", True) is True
        )
        if isinstance(raw_programs, list)
        else ()
    )
    return Instance(port=port, pid=record["pid"], project=project, programs=programs)


def discover_instances(
    base_port: int = DEFAULT_PORT, *, fetch: Fetch = _fetch_instance
) -> list[Instance]:
    """Probe GhidraMCP's configured fallback range and return valid instances."""
    validate_base_port(base_port)
    ports = range(base_port, base_port + PORT_RANGE)
    with ThreadPoolExecutor(max_workers=PORT_RANGE) as executor:
        values = executor.map(fetch, ports)
    return sorted(
        instance
        for port, value in zip(ports, values, strict=True)
        if (instance := _parse_instance(port, value)) is not None
    )


def probe_server(port: int, *, fetch: EndpointFetch = _fetch_endpoint) -> ServerInfo | None:
    value = fetch(port, "/get_version", None)
    if not isinstance(value, dict):
        return None
    try:
        return ServerInfo(
            plugin_version=str(value["plugin_version"]),
            ghidra_version=str(value["ghidra_version"]),
            java_version=str(value["java_version"]),
            endpoint_count=int(value["endpoint_count"]),
        )
    except (KeyError, TypeError, ValueError):
        return None


def probe_analysis(
    port: int,
    program: str,
    *,
    fetch: EndpointFetch = _fetch_endpoint,
) -> AnalysisStatus | None:
    value = fetch(port, "/analysis_status", {"program": program})
    if not isinstance(value, dict):
        return None
    try:
        return AnalysisStatus(
            program=str(value["name"]),
            analyzing=bool(value["analyzing"]),
            analyzed=bool(value["analyzed"]),
            function_count=int(value["function_count"]),
        )
    except (KeyError, TypeError, ValueError):
        return None
