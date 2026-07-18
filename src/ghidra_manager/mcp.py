"""GhidraMCP instance discovery."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any

from ghidra_manager.errors import ManagerError

DEFAULT_PORT = 8089
PORT_RANGE = 16
Fetch = Callable[[int], object | None]


@dataclass(frozen=True, slots=True, order=True)
class Instance:
    port: int
    pid: int
    project: str
    programs: tuple[str, ...] = ()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"


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
