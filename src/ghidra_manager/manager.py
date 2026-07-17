"""High-level manager operations."""

from __future__ import annotations

import re
from dataclasses import dataclass

from ghidra_manager.config import ManagerPaths
from ghidra_manager.github import GitHubClient
from ghidra_manager.models import ResolvedPair
from ghidra_manager.releases import ReleaseClient, resolve_pair
from ghidra_manager.storage import StateStore, read_properties


@dataclass(slots=True)
class Manager:
    paths: ManagerPaths
    client: ReleaseClient

    @classmethod
    def discover(cls) -> Manager:
        return cls(ManagerPaths.discover(), GitHubClient())

    def resolved_pair(self) -> ResolvedPair:
        return resolve_pair(self.client)

    def status_lines(self) -> list[str]:
        store = StateStore(self.paths)
        state = store.load()
        lines: list[str] = []
        if state.current:
            current = store.pair(state.current)
            installed = self._installed_mcp_version(current.ghidra_version) or "missing"
            lines.extend(
                [
                    f"Active Ghidra:      {current.ghidra_version}",
                    f"Active GhidraMCP:   {current.mcp_version}",
                    f"Installed extension: {installed}",
                ]
            )
        else:
            lines.append("Active pair:        not installed")
        if state.previous:
            previous = store.pair(state.previous)
            lines.append(
                f"Previous pair:      Ghidra {previous.ghidra_version} "
                f"with GhidraMCP {previous.mcp_version}"
            )
        else:
            lines.append("Previous pair:      none")
        resolved = self.resolved_pair()
        lines.extend(
            [
                f"Upstream Ghidra:    {resolved.ghidra_latest_version}",
                f"Compatible Ghidra:  {resolved.ghidra_version}",
                f"Upstream GhidraMCP: {resolved.mcp_version}",
            ]
        )
        if resolved.ghidra_latest_version != resolved.ghidra_version:
            lines.append(
                f"Update held: GhidraMCP {resolved.mcp_version} declares "
                f"Ghidra {resolved.ghidra_version}."
            )
        return lines

    def _installed_mcp_version(self, ghidra_version: str) -> str | None:
        properties = (
            self.paths.ghidra
            / ghidra_version
            / "Ghidra"
            / "Extensions"
            / "GhidraMCP"
            / "extension.properties"
        )
        if not properties.is_file():
            return None
        description = read_properties(properties).get("description", "")
        match = re.search(r"Plugin version ([0-9.]+)\.", description)
        return match.group(1) if match else None
