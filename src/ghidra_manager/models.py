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
class PairMetadata:
    pair_id: str
    ghidra_version: str
    mcp_version: str
    ghidra_tag: str
    mcp_tag: str


@dataclass(frozen=True, slots=True)
class ManagerState:
    current: str | None = None
    previous: str | None = None
    schema_version: int = 1


@dataclass(frozen=True, slots=True)
class ReleaseAsset:
    name: str
    url: str
    digest: str


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
