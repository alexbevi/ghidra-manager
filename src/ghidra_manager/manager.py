"""High-level manager operations."""

from __future__ import annotations

import json
import re
import shutil
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from ghidra_manager.config import ManagerPaths
from ghidra_manager.errors import ManagerError
from ghidra_manager.github import GitHubClient
from ghidra_manager.models import ManagerState, PairMetadata, ReleaseAsset, ResolvedPair
from ghidra_manager.processes import managed_ghidra_running
from ghidra_manager.releases import (
    ReleaseClient,
    extension_properties,
    resolve_pair,
    verify_digest,
)
from ghidra_manager.storage import (
    StateStore,
    atomic_json,
    read_properties,
    safe_extract,
)


@dataclass(slots=True)
class Manager:
    paths: ManagerPaths
    client: ReleaseClient
    process_check: Callable[[Path], bool] = managed_ghidra_running

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

    def sync(self, *, dry_run: bool = False) -> list[str]:
        lines = ["Resolving stable upstream releases..."]
        resolved = self.resolved_pair()
        lines.extend(self._remote_lines(resolved))
        store = StateStore(self.paths)
        state = store.load()
        if dry_run:
            if state.current == resolved.pair_id:
                lines.append("Dry run: the active pair is already current.")
            else:
                lines.append(
                    f"Dry run: would activate Ghidra {resolved.ghidra_version} "
                    f"with GhidraMCP {resolved.mcp_version}."
                )
            return lines
        if self._is_current(state, resolved):
            lines.append(
                f"Already current: Ghidra {resolved.ghidra_version} "
                f"with GhidraMCP {resolved.mcp_version}."
            )
            return lines
        if self.process_check(self.paths.ghidra):
            raise ManagerError("Close the managed Ghidra instance before syncing")
        self.paths.home.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="transaction-", dir=self.paths.home) as temporary:
            transaction = Path(temporary)
            self._stage_mcp(resolved, transaction)
            lines.extend(self._stage_ghidra(resolved, transaction))
            self._install_extension(
                resolved.ghidra_version,
                resolved.mcp_version,
                resolved.mcp_extension.name,
                transaction,
            )
            pair = PairMetadata(
                pair_id=resolved.pair_id,
                ghidra_version=resolved.ghidra_version,
                mcp_version=resolved.mcp_version,
                ghidra_tag=resolved.ghidra_tag,
                mcp_tag=resolved.mcp_tag,
            )
            store.save_pair(pair)
            previous = state.current if state.current != pair.pair_id else state.previous
            store.save(ManagerState(current=pair.pair_id, previous=previous))
        self._prune(store.load())
        lines.append(
            f"Active pair: Ghidra {resolved.ghidra_version} "
            f"with GhidraMCP {resolved.mcp_version}."
        )
        return lines

    def rollback(self) -> list[str]:
        store = StateStore(self.paths)
        state = store.load()
        if state.current is None:
            raise ManagerError("No active pair is installed")
        if state.previous is None:
            raise ManagerError("No previous pair is available for rollback")
        if self.process_check(self.paths.ghidra):
            raise ManagerError("Close the managed Ghidra instance before rolling back")
        current = store.pair(state.current)
        previous = store.pair(state.previous)
        ghidra_dir = self.paths.ghidra / previous.ghidra_version
        if not self._valid_ghidra(ghidra_dir, previous.ghidra_version):
            raise ManagerError("Previous Ghidra installation is missing or invalid")
        component = self._mcp_metadata(previous.mcp_version)
        extension_name = component.get("extension_asset")
        if not extension_name:
            raise ManagerError("Previous pair metadata is incomplete")
        archive = self.paths.mcp / previous.mcp_version / extension_name
        if not archive.is_file():
            raise ManagerError("Previous GhidraMCP extension archive is missing")
        with tempfile.TemporaryDirectory(prefix="rollback-", dir=self.paths.home) as temporary:
            self._install_extension(
                previous.ghidra_version,
                previous.mcp_version,
                extension_name,
                Path(temporary),
            )
            store.save(
                ManagerState(current=previous.pair_id, previous=current.pair_id)
            )
        self._prune(store.load())
        return [
            f"Rolled back to Ghidra {previous.ghidra_version} "
            f"with GhidraMCP {previous.mcp_version}."
        ]

    def _remote_lines(self, resolved: ResolvedPair) -> list[str]:
        lines = [
            f"Upstream Ghidra:    {resolved.ghidra_latest_version}",
            f"Compatible Ghidra:  {resolved.ghidra_version}",
            f"Upstream GhidraMCP: {resolved.mcp_version}",
        ]
        if resolved.ghidra_latest_version != resolved.ghidra_version:
            lines.append(
                f"Update held: GhidraMCP {resolved.mcp_version} declares "
                f"Ghidra {resolved.ghidra_version}."
            )
        return lines

    def _is_current(self, state: ManagerState, resolved: ResolvedPair) -> bool:
        mcp_dir = self.paths.mcp / resolved.mcp_version
        return (
            state.current == resolved.pair_id
            and self._valid_ghidra(
                self.paths.ghidra / resolved.ghidra_version, resolved.ghidra_version
            )
            and all(
                (mcp_dir / asset.name).is_file()
                for asset in (
                    resolved.mcp_extension,
                    resolved.mcp_bridge,
                    resolved.mcp_requirements,
                )
            )
            and self._installed_mcp_version(resolved.ghidra_version) == resolved.mcp_version
        )

    def _stage_mcp(self, resolved: ResolvedPair, transaction: Path) -> None:
        destination = self.paths.mcp / resolved.mcp_version
        assets = (
            resolved.mcp_extension,
            resolved.mcp_bridge,
            resolved.mcp_requirements,
        )
        if all((destination / asset.name).is_file() for asset in assets):
            return
        stage = transaction / "mcp-component"
        stage.mkdir()
        for asset in assets:
            self._download(asset, stage / asset.name)
        atomic_json(
            stage / "metadata.json",
            {
                "mcp_version": resolved.mcp_version,
                "mcp_tag": resolved.mcp_tag,
                "ghidra_version": resolved.ghidra_version,
                "extension_asset": resolved.mcp_extension.name,
                "bridge_asset": resolved.mcp_bridge.name,
                "requirements_asset": resolved.mcp_requirements.name,
            },
            mode=0o600,
        )
        self._replace_directory(stage, destination)

    def _stage_ghidra(self, resolved: ResolvedPair, transaction: Path) -> list[str]:
        destination = self.paths.ghidra / resolved.ghidra_version
        if self._valid_ghidra(destination, resolved.ghidra_version):
            return []
        archive = transaction / resolved.ghidra_asset.name
        self._download(resolved.ghidra_asset, archive)
        extract_dir = transaction / "ghidra-extract"
        safe_extract(archive, extract_dir)
        roots = [path for path in extract_dir.iterdir() if path.is_dir()]
        if len(roots) != 1 or not self._valid_ghidra(roots[0], resolved.ghidra_version):
            raise ManagerError("Extracted Ghidra installation failed validation")
        atomic_json(
            roots[0] / ".manager-metadata.json",
            {
                "ghidra_version": resolved.ghidra_version,
                "ghidra_tag": resolved.ghidra_tag,
                "asset": resolved.ghidra_asset.name,
                "digest": resolved.ghidra_asset.digest,
            },
            mode=0o600,
        )
        self._replace_directory(roots[0], destination)
        return [f"Downloading Ghidra {resolved.ghidra_version}..."]

    def _install_extension(
        self,
        ghidra_version: str,
        mcp_version: str,
        extension_name: str,
        transaction: Path,
    ) -> None:
        if self._installed_mcp_version(ghidra_version) == mcp_version:
            return
        ghidra_dir = self.paths.ghidra / ghidra_version
        archive = self.paths.mcp / mcp_version / extension_name
        properties = extension_properties(archive)
        if properties.get("version") != ghidra_version:
            raise ManagerError("Extension is incompatible with the staged Ghidra installation")
        unpacked = transaction / "extension-unpacked"
        safe_extract(archive, unpacked)
        source = unpacked / "GhidraMCP"
        if not source.is_dir():
            raise ManagerError("Extension archive has an unexpected layout")
        target = ghidra_dir / "Ghidra" / "Extensions" / "GhidraMCP"
        target.parent.mkdir(parents=True, exist_ok=True)
        backup = transaction / "extension-backup"
        if target.exists():
            target.replace(backup)
        try:
            source.replace(target)
        except Exception:
            shutil.rmtree(target, ignore_errors=True)
            if backup.exists():
                backup.replace(target)
            raise

    def _mcp_metadata(self, mcp_version: str) -> dict[str, str]:
        component = self.paths.mcp / mcp_version
        json_path = component / "metadata.json"
        if json_path.is_file():
            try:
                raw: object = json.loads(json_path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                raise ManagerError(f"Invalid MCP component metadata: {mcp_version}") from exc
            if not isinstance(raw, dict):
                raise ManagerError(f"Invalid MCP component metadata: {mcp_version}")
            return {str(key): str(value) for key, value in raw.items()}
        legacy = component / "metadata"
        return read_properties(legacy)

    def _download(self, asset: ReleaseAsset, destination: Path) -> None:
        self.client.download(asset.url, destination)
        verify_digest(destination, asset.digest)

    @staticmethod
    def _replace_directory(stage: Path, destination: Path) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            shutil.rmtree(destination)
        stage.replace(destination)

    @staticmethod
    def _valid_ghidra(path: Path, expected_version: str) -> bool:
        properties = path / "Ghidra" / "application.properties"
        launcher = path / "ghidraRun"
        if not properties.is_file() or not launcher.is_file():
            return False
        try:
            return read_properties(properties).get("application.version") == expected_version
        except ManagerError:
            return False

    def _prune(self, state: ManagerState) -> None:
        store = StateStore(self.paths)
        pairs = [store.pair(pair_id) for pair_id in (state.current, state.previous) if pair_id]
        keep_ghidra = {pair.ghidra_version for pair in pairs}
        keep_mcp = {pair.mcp_version for pair in pairs}
        keep_pairs = {pair.pair_id for pair in pairs}
        for root, keep in (
            (self.paths.ghidra, keep_ghidra),
            (self.paths.mcp, keep_mcp),
            (self.paths.pairs, keep_pairs),
        ):
            if not root.is_dir():
                continue
            for child in root.iterdir():
                if child.is_dir() and child.name not in keep:
                    shutil.rmtree(child)

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
