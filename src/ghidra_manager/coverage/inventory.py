"""Read-only Ghidra inventory snapshots."""

from __future__ import annotations

import hashlib
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from ghidra_manager.coverage.model import (
    SCHEMA_VERSION,
    SNAPSHOT_SCHEMA,
    Address,
    with_content_id,
)
from ghidra_manager.errors import ManagerError

EndpointFetch = Callable[[int, str, Mapping[str, str] | None], object | None]
CALL_GRAPH_LIMIT = 100_000


def fetch_endpoint(
    port: int, path: str, params: Mapping[str, str] | None = None
) -> object | None:
    query = f"?{urllib.parse.urlencode(params)}" if params else ""
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}{query}",
        headers={"Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            response_text: str = response.read().decode("utf-8", errors="replace")
            try:
                value: object = json.loads(response_text)
                return value
            except json.JSONDecodeError:
                return response_text
    except (OSError, TimeoutError, ValueError, urllib.error.URLError):
        return None


def _unwrap(value: object | None) -> object | None:
    if isinstance(value, dict) and set(value) == {"data"}:
        return value.get("data")
    if isinstance(value, dict) and set(value) >= {"success", "data"}:
        return value.get("data")
    return value


def _required_dict(
    fetch: EndpointFetch,
    port: int,
    path: str,
    params: Mapping[str, str],
) -> dict[str, Any]:
    value = _unwrap(fetch(port, path, params))
    if not isinstance(value, dict):
        raise ManagerError(f"GhidraMCP did not provide required coverage data from {path}")
    return value


def _optional(fetch: EndpointFetch, port: int, path: str, params: Mapping[str, str]) -> object:
    return _unwrap(fetch(port, path, params))


def _binary_fingerprint(info: dict[str, Any], metadata: dict[str, Any]) -> str:
    for key in ("sha256", "executable_sha256", "binary_sha256"):
        value = metadata.get(key) or info.get(key)
        if isinstance(value, str) and value:
            return value if value.startswith("sha256:") else f"sha256:{value}"
    executable = info.get("executable_path") or metadata.get("executable_path")
    if isinstance(executable, str) and Path(executable).is_file():
        digest = hashlib.sha256()
        with Path(executable).open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
        return f"sha256:{digest.hexdigest()}"
    raise ManagerError("Coverage snapshot requires a stable binary SHA-256 fingerprint")


def _functions(
    fetch: EndpointFetch,
    port: int,
    params: Mapping[str, str],
    known_spaces: set[str],
    program_id: str,
) -> list[dict[str, object]]:
    functions: list[dict[str, object]] = []
    offset = 0
    limit = 1000
    while True:
        page_params = dict(params)
        page_params.update({"offset": str(offset), "limit": str(limit), "filter": ""})
        page = _required_dict(fetch, port, "/get_bulk_function_hashes", page_params)
        raw = page.get("functions", page.get("items", page.get("results")))
        if not isinstance(raw, list):
            raise ManagerError("GhidraMCP function inventory has no functions array")
        for item in raw:
            if not isinstance(item, dict):
                continue
            raw_address = item.get("address") or item.get("entry")
            if not isinstance(raw_address, str):
                raise ManagerError("GhidraMCP returned a function without an entry address")
            address = Address.parse(raw_address, known_spaces=known_spaces)
            functions.append(
                {
                    "id": f"fn:{program_id}:{address.key}",
                    "address": address.to_json(),
                    "name": str(item.get("name") or ""),
                    "namespace": item.get("namespace"),
                    "instruction_count": item.get("instruction_count"),
                    "body_size": item.get("body_size"),
                    "body_ranges": item.get("body_ranges", []),
                    "thunk": item.get("thunk"),
                    "external": item.get("external"),
                    "tags": sorted(item.get("tags", []))
                    if isinstance(item.get("tags"), list)
                    else [],
                    "normalized_hash": item.get("hash"),
                }
            )
        total = page.get("total", page.get("total_count", page.get("total_matching")))
        offset += len(raw)
        if not raw or (isinstance(total, int) and offset >= total) or len(raw) < limit:
            break
    return sorted(functions, key=lambda item: str(item["id"]))


def _entry_points(
    value: object,
    *,
    known_spaces: set[str],
) -> list[dict[str, object]]:
    raw_items: object = value
    if isinstance(value, dict):
        raw_items = value.get("entry_points", value.get("entries", []))
    if isinstance(raw_items, str):
        parsed: list[dict[str, object]] = []
        pattern = re.compile(r"^(?P<name>.*?)\s+@\s+(?P<address>\S+)\s+\[(?P<kind>[^\]]+)\]")
        for line in raw_items.splitlines():
            match = pattern.match(line.strip())
            if match:
                parsed.append(
                    {
                        "kind": match.group("kind"),
                        "name": match.group("name"),
                        "address": Address.parse(
                            match.group("address"), known_spaces=known_spaces
                        ).to_json(),
                    }
                )
        return parsed
    result: list[dict[str, object]] = []
    if isinstance(raw_items, list):
        for item in raw_items:
            if isinstance(item, str):
                result.append(
                    {
                        "kind": "entry",
                        "address": Address.parse(
                            item, known_spaces=known_spaces
                        ).to_json(),
                    }
                )
            elif isinstance(item, dict) and isinstance(item.get("address"), str):
                result.append(
                    {
                        "kind": str(item.get("kind") or item.get("type") or "entry"),
                        "name": item.get("name"),
                        "address": Address.parse(
                            item["address"], known_spaces=known_spaces
                        ).to_json(),
                    }
                )
    return sorted(result, key=lambda item: json.dumps(item, sort_keys=True))


def _call_graph(
    value: object,
    *,
    known_spaces: set[str],
    functions: list[dict[str, object]],
) -> list[dict[str, object]]:
    function_ids: dict[str, str] = {}
    for function in functions:
        address = function.get("address")
        if isinstance(address, dict) and isinstance(address.get("display"), str):
            parsed = Address.parse(
                address["display"],
                default_space=str(address.get("space", "ram")),
                known_spaces=known_spaces,
            )
            function_ids[parsed.key] = str(function["id"])
    raw_edges: object = value.get("edges", []) if isinstance(value, dict) else value
    if isinstance(raw_edges, list):
        return sorted(
            [item for item in raw_edges if isinstance(item, dict)],
            key=lambda item: json.dumps(item, sort_keys=True),
        )
    if not isinstance(raw_edges, str):
        return []
    pattern = re.compile(
        r"^(?P<caller>.+)@(?P<caller_address>\S+)\s+->\s+"
        r"(?P<callee>.+)@(?P<callee_address>\S+)$"
    )
    result: list[dict[str, object]] = []
    for line in raw_edges.splitlines():
        match = pattern.match(line.strip())
        if not match:
            continue
        caller_address = Address.parse(
            match.group("caller_address"), known_spaces=known_spaces
        )
        callee_address = Address.parse(
            match.group("callee_address"), known_spaces=known_spaces
        )
        result.append(
            {
                "kind": "direct_static",
                "caller": function_ids.get(caller_address.key),
                "callee": function_ids.get(callee_address.key),
                "caller_name": match.group("caller"),
                "callee_name": match.group("callee"),
                "caller_address": caller_address.to_json(),
                "callee_address": callee_address.to_json(),
            }
        )
    return sorted(
        result,
        key=lambda item: (
            str(item["caller_address"]),
            str(item["callee_address"]),
        ),
    )


def build_snapshot(
    *,
    project: str,
    program: str,
    port: int,
    fetch: EndpointFetch = fetch_endpoint,
    roots: list[dict[str, object]] | None = None,
    declared_edges: list[dict[str, object]] | None = None,
) -> dict[str, Any]:
    params = {"program": program}
    info = _required_dict(fetch, port, "/get_current_program_info", params)
    metadata_value = _optional(fetch, port, "/get_metadata", params)
    metadata = metadata_value if isinstance(metadata_value, dict) else {}
    spaces_value = _optional(fetch, port, "/get_address_spaces", params)
    spaces = (
        spaces_value.get("address_spaces", spaces_value.get("spaces", []))
        if isinstance(spaces_value, dict)
        else spaces_value
    )
    if not isinstance(spaces, list) or not spaces:
        spaces = [{"name": "ram", "kind": "memory"}]
        spaces_available = False
    else:
        spaces_available = True
    normalized_spaces = sorted(
        [item for item in spaces if isinstance(item, dict) and isinstance(item.get("name"), str)],
        key=lambda item: str(item["name"]),
    )
    known_spaces = {str(item["name"]) for item in normalized_spaces}
    binary_sha256 = _binary_fingerprint(info, metadata)
    layout_source = {
        "image_base": info.get("image_base") or metadata.get("image_base"),
        "address_spaces": normalized_spaces,
        "blocks": info.get("memory_blocks") or metadata.get("memory_blocks"),
    }
    layout_digest = hashlib.sha256(
        json.dumps(layout_source, sort_keys=True).encode()
    ).hexdigest()
    layout_hash = f"sha256:{layout_digest}"
    program_seed = {
        "binary_sha256": binary_sha256,
        "language": info.get("language") or metadata.get("language"),
        "compiler": info.get("compiler") or metadata.get("compiler"),
        "memory_map_fingerprint": layout_hash,
    }
    program_id = hashlib.sha256(json.dumps(program_seed, sort_keys=True).encode()).hexdigest()[:24]
    functions = _functions(fetch, port, params, known_spaces, program_id)
    entry_value = _optional(fetch, port, "/get_entry_points", params)
    entries = _entry_points(entry_value, known_spaces=known_spaces)
    graph_params = dict(params)
    graph_params["limit"] = str(CALL_GRAPH_LIMIT)
    graph = _optional(fetch, port, "/get_full_call_graph", graph_params)
    graph_available = graph is not None
    call_graph = (
        _call_graph(graph, known_spaces=known_spaces, functions=functions)
        if graph_available
        else []
    )
    snapshot: dict[str, Any] = {
        "schema": SNAPSHOT_SCHEMA,
        "version": SCHEMA_VERSION,
        "program": {
            "id": program_id,
            "project": project,
            "program_path": program,
            "binary_sha256": binary_sha256,
            "format": info.get("format") or metadata.get("format"),
            "language": info.get("language") or metadata.get("language"),
            "compiler": info.get("compiler") or metadata.get("compiler"),
            "image_base": info.get("image_base") or metadata.get("image_base"),
            "address_spaces": normalized_spaces,
            "memory_map_fingerprint": layout_hash,
        },
        "availability": {
            "address_spaces": spaces_available,
            "entry_points": entry_value is not None,
            "call_graph": graph_available,
            "call_graph_complete": graph_available
            and len(call_graph) < CALL_GRAPH_LIMIT,
            "namespace": any(item.get("namespace") is not None for item in functions),
            "body_ranges": any(bool(item.get("body_ranges")) for item in functions),
            "thunk": any(item.get("thunk") is not None for item in functions),
            "external": any(item.get("external") is not None for item in functions),
        },
        "entry_points": sorted(entries, key=lambda item: json.dumps(item, sort_keys=True)),
        "functions": functions,
        "call_graph": call_graph,
        "declared_roots": sorted(roots or [], key=lambda item: json.dumps(item, sort_keys=True)),
        "declared_edges": sorted(
            declared_edges or [], key=lambda item: json.dumps(item, sort_keys=True)
        ),
    }
    return with_content_id(snapshot, "snapshot_id")
