"""Curated Ghidra plugin registry."""

from __future__ import annotations

import json
import re
import zipfile
from dataclasses import asdict, dataclass
from importlib.resources import files
from pathlib import Path, PurePosixPath
from typing import Any

from ghidra_manager.errors import ManagerError
from ghidra_manager.models import ReleaseAsset, ResolvedPluginSource
from ghidra_manager.releases import ReleaseClient
from ghidra_manager.storage import parse_properties


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
    runtime_asset_patterns: tuple[tuple[str, str], ...] = ()

    def as_dict(self, *, selected: bool) -> dict[str, object]:
        value = asdict(self)
        value["id"] = value.pop("plugin_id")
        value["runtime_files"] = dict(self.runtime_files)
        value["runtime_assets"] = dict(value.pop("runtime_asset_patterns"))
        value["selected"] = selected
        return value

    def runtime_file(self, name: str) -> str | None:
        return dict(self.runtime_files).get(name)

    def runtime_asset_pattern(self, name: str) -> str | None:
        return dict(self.runtime_asset_patterns).get(name)


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
                    _relative_path(_string({"value": value}, "value"), f"runtime_files.{key}"),
                )
                for key, value in runtime_raw.items()
            )
        )
        if any(not key for key, _ in runtime_files):
            raise ManagerError(f"Invalid runtime file name for plugin: {plugin_id}")
        runtime_assets_raw = entry.get("runtime_assets", {})
        if not isinstance(runtime_assets_raw, dict):
            raise ManagerError(f"Invalid runtime assets for plugin: {plugin_id}")
        runtime_asset_patterns = tuple(
            sorted(
                (
                    key if isinstance(key, str) and key else "",
                    _string({"value": value}, "value"),
                )
                for key, value in runtime_assets_raw.items()
            )
        )
        if any(not key for key, _ in runtime_asset_patterns):
            raise ManagerError(f"Invalid runtime asset name for plugin: {plugin_id}")
        for _, pattern in runtime_asset_patterns:
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ManagerError(
                    f"Invalid runtime asset pattern for plugin: {plugin_id}: {pattern}"
                ) from exc
        build_task = _string(entry, "build_task")
        if not re.fullmatch(r"[A-Za-z0-9:_-]+", build_task):
            raise ManagerError(f"Invalid plugin build task: {build_task}")
        plugins.append(
            PluginDefinition(
                plugin_id=plugin_id,
                name=_string(entry, "name"),
                description=_string(entry, "description"),
                repository=repository,
                extension_name=_string(entry, "extension_name"),
                extension_root=_relative_path(_string(entry, "extension_root"), "extension_root"),
                build_task=build_task,
                artifact_pattern=_relative_path(
                    _string(entry, "artifact_pattern"), "artifact_pattern"
                ),
                runtime_files=runtime_files,
                runtime_asset_patterns=runtime_asset_patterns,
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


def resolve_plugin_source(
    client: ReleaseClient, definition: PluginDefinition
) -> ResolvedPluginSource:
    release = client.get_json(f"repos/{definition.repository}/releases/latest")
    if not isinstance(release, dict):
        raise ManagerError(f"GitHub returned invalid release metadata for {definition.plugin_id}")
    tag = release.get("tag_name")
    if not isinstance(tag, str) or not tag:
        raise ManagerError(f"Latest {definition.plugin_id} release has no tag")
    runtime_assets = _resolve_runtime_assets(release, definition)
    reference = client.get_json(f"repos/{definition.repository}/git/ref/tags/{tag}")
    if not isinstance(reference, dict) or not isinstance(reference.get("object"), dict):
        raise ManagerError(f"Unable to resolve release tag for {definition.plugin_id}: {tag}")
    target = reference["object"]
    for _ in range(5):
        target_type = target.get("type")
        sha = target.get("sha")
        if not isinstance(sha, str):
            break
        if target_type == "commit":
            if not re.fullmatch(r"[0-9a-fA-F]{40}", sha):
                break
            return ResolvedPluginSource(
                plugin_id=definition.plugin_id,
                version=tag.removeprefix("v"),
                tag=tag,
                commit=sha.lower(),
                archive_url=(f"https://api.github.com/repos/{definition.repository}/zipball/{sha}"),
                runtime_assets=runtime_assets,
            )
        if target_type != "tag":
            break
        annotated = client.get_json(f"repos/{definition.repository}/git/tags/{sha}")
        if not isinstance(annotated, dict) or not isinstance(annotated.get("object"), dict):
            break
        target = annotated["object"]
    raise ManagerError(f"Release tag does not resolve to one commit: {definition.plugin_id} {tag}")


def _resolve_runtime_assets(
    release: dict[str, object],
    definition: PluginDefinition,
) -> tuple[tuple[str, ReleaseAsset], ...]:
    raw_assets = release.get("assets", [])
    if not isinstance(raw_assets, list):
        raise ManagerError(f"Latest {definition.plugin_id} release has an invalid asset list")
    resolved: list[tuple[str, ReleaseAsset]] = []
    for runtime_name, pattern in definition.runtime_asset_patterns:
        matches = [
            raw
            for raw in raw_assets
            if isinstance(raw, dict)
            and isinstance(raw.get("name"), str)
            and re.fullmatch(pattern, raw["name"])
        ]
        if not matches:
            continue
        if len(matches) != 1:
            raise ManagerError(
                f"Expected one {definition.plugin_id} runtime asset matching: {pattern}"
            )
        match = matches[0]
        name = match["name"]
        url = match.get("browser_download_url")
        digest = match.get("digest")
        if (
            not isinstance(name, str)
            or Path(name).name != name
            or not isinstance(url, str)
            or not isinstance(digest, str)
            or re.fullmatch(r"sha256:[0-9a-fA-F]{64}", digest) is None
        ):
            raise ManagerError(
                f"Runtime asset is missing GitHub SHA-256 metadata: {definition.plugin_id} {name}"
            )
        resolved.append((runtime_name, ReleaseAsset(name=name, url=url, digest=digest)))
    return tuple(resolved)


def plugin_extension_properties(archive: Path, definition: PluginDefinition) -> dict[str, str]:
    member = f"{definition.extension_root}/extension.properties"
    try:
        with zipfile.ZipFile(archive) as bundle:
            text = bundle.read(member).decode("utf-8")
    except (OSError, KeyError, UnicodeError, zipfile.BadZipFile) as exc:
        raise ManagerError(
            f"Invalid {definition.plugin_id} extension archive: expected {member}"
        ) from exc
    return parse_properties(text)


def validate_plugin_archive(
    archive: Path,
    definition: PluginDefinition,
    *,
    ghidra_version: str,
    plugin_version: str,
) -> None:
    properties = plugin_extension_properties(archive, definition)
    if properties.get("name") != definition.extension_name:
        raise ManagerError(f"Unexpected extension name for plugin: {definition.plugin_id}")
    if properties.get("version") != ghidra_version:
        raise ManagerError(
            f"Plugin {definition.plugin_id} does not declare Ghidra {ghidra_version}"
        )
    if definition.plugin_id == "mcp":
        match = re.search(r"Plugin version ([0-9.]+)\.", properties.get("description", ""))
        if match is None or match.group(1) != plugin_version:
            raise ManagerError("MCP source tag and extension metadata do not match")
