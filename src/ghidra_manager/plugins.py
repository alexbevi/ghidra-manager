"""Curated Ghidra plugin registry."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from importlib.resources import files
from pathlib import PurePosixPath
from typing import Any

from ghidra_manager.errors import ManagerError


@dataclass(frozen=True, slots=True)
class PluginDefinition:
    plugin_id: str
    name: str
    description: str
    repository: str
    extension_name: str
    extension_root: str
    build_task: str
    artifact_pattern: str
    runtime_files: tuple[tuple[str, str], ...] = ()

    def as_dict(self, *, selected: bool) -> dict[str, object]:
        value = asdict(self)
        value["id"] = value.pop("plugin_id")
        value["runtime_files"] = dict(self.runtime_files)
        value["selected"] = selected
        return value

    def runtime_file(self, name: str) -> str | None:
        return dict(self.runtime_files).get(name)


def _string(raw: dict[str, Any], key: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ManagerError(f"Plugin registry field must be a non-empty string: {key}")
    return value


def _relative_path(value: str, field: str) -> str:
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts:
        raise ManagerError(f"Plugin registry field must be a safe relative path: {field}")
    return value


def parse_registry(raw: object) -> tuple[PluginDefinition, ...]:
    if not isinstance(raw, dict) or raw.get("schema_version") != 1:
        raise ManagerError("Unsupported plugin registry schema")
    entries = raw.get("plugins")
    if not isinstance(entries, list):
        raise ManagerError("Plugin registry has no plugin list")
    plugins: list[PluginDefinition] = []
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ManagerError("Plugin registry entry must be an object")
        plugin_id = _string(entry, "id")
        if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", plugin_id):
            raise ManagerError(f"Invalid plugin ID: {plugin_id}")
        if plugin_id in seen:
            raise ManagerError(f"Duplicate plugin ID: {plugin_id}")
        repository = _string(entry, "repository")
        if not re.fullmatch(r"[^/\s]+/[^/\s]+", repository):
            raise ManagerError(f"Invalid plugin repository: {repository}")
        runtime_raw = entry.get("runtime_files", {})
        if not isinstance(runtime_raw, dict):
            raise ManagerError(f"Invalid runtime files for plugin: {plugin_id}")
        runtime_files = tuple(
            sorted(
                (
                    key if isinstance(key, str) and key else "",
                    _relative_path(
                        _string({"value": value}, "value"), f"runtime_files.{key}"
                    ),
                )
                for key, value in runtime_raw.items()
            )
        )
        if any(not key for key, _ in runtime_files):
            raise ManagerError(f"Invalid runtime file name for plugin: {plugin_id}")
        plugins.append(
            PluginDefinition(
                plugin_id=plugin_id,
                name=_string(entry, "name"),
                description=_string(entry, "description"),
                repository=repository,
                extension_name=_string(entry, "extension_name"),
                extension_root=_relative_path(
                    _string(entry, "extension_root"), "extension_root"
                ),
                build_task=_string(entry, "build_task"),
                artifact_pattern=_relative_path(
                    _string(entry, "artifact_pattern"), "artifact_pattern"
                ),
                runtime_files=runtime_files,
            )
        )
        seen.add(plugin_id)
    return tuple(plugins)


def load_registry() -> tuple[PluginDefinition, ...]:
    try:
        registry = files("ghidra_manager").joinpath("plugin_registry.json")
        raw: object = json.loads(registry.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ManagerError(f"Unable to load plugin registry: {exc}") from exc
    return parse_registry(raw)


def plugin_definition(plugin_id: str) -> PluginDefinition:
    for plugin in load_registry():
        if plugin.plugin_id == plugin_id:
            return plugin
    available = ", ".join(plugin.plugin_id for plugin in load_registry())
    raise ManagerError(f"Unknown plugin '{plugin_id}'. Available plugins: {available}")
