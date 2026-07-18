"""Typed manager state and release metadata."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

DoctorLevel = Literal["ok", "warning", "error"]


@dataclass(frozen=True, slots=True)
class DoctorCheck:
    name: str
    level: DoctorLevel
    detail: str


@dataclass(frozen=True, slots=True)
class PluginMetadata:
    plugin_id: str
    version: str
    tag: str
    commit: str
    extension_name: str
    extension_root: str
    artifact: str
    digest: str
    runtime_files: tuple[tuple[str, str], ...] = ()

    def runtime_file(self, name: str) -> str | None:
        return dict(self.runtime_files).get(name)


@dataclass(frozen=True, slots=True)
class PairMetadata:
    pair_id: str
    ghidra_version: str
    ghidra_tag: str
    plugins: tuple[PluginMetadata, ...] = ()

    def plugin(self, plugin_id: str) -> PluginMetadata | None:
        return next((plugin for plugin in self.plugins if plugin.plugin_id == plugin_id), None)


@dataclass(frozen=True, slots=True)
class ManagerState:
    current: str | None = None
    previous: str | None = None
    schema_version: int = 2


@dataclass(frozen=True, slots=True)
class ReleaseAsset:
    name: str
    url: str
    digest: str


@dataclass(frozen=True, slots=True)
class ResolvedGhidra:
    version: str
    tag: str
    asset: ReleaseAsset


@dataclass(frozen=True, slots=True)
class ResolvedPluginSource:
    plugin_id: str
    version: str
    tag: str
    commit: str
    archive_url: str


@dataclass(frozen=True, slots=True)
class ResolvedPair:
    ghidra_version: str
    ghidra_latest_version: str
    ghidra_tag: str
    ghidra_asset: ReleaseAsset
    mcp_version: str
    mcp_tag: str
    mcp_extension: ReleaseAsset
    mcp_bridge: ReleaseAsset
    mcp_requirements: ReleaseAsset

    @property
    def pair_id(self) -> str:
        return f"ghidra-{self.ghidra_version}__mcp-{self.mcp_version}"
