"""Versioned, symlink-free manager state with legacy migration."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import zipfile
from dataclasses import asdict
from pathlib import Path
from typing import Any

from ghidra_manager.config import ManagerPaths
from ghidra_manager.errors import ManagerError
from ghidra_manager.models import ManagerState, PairMetadata, PluginMetadata


def parse_properties(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "!")) or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def read_properties(path: Path) -> dict[str, str]:
    try:
        return parse_properties(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ManagerError(f"Unable to read metadata: {path}: {exc}") from exc


def atomic_json(path: Path, value: object, *, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        if mode is not None:
            temporary.chmod(mode)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def safe_extract(archive: Path, destination: Path) -> None:
    """Extract a ZIP without allowing traversal or archived symlinks."""
    destination.mkdir(parents=True, exist_ok=True)
    root = destination.resolve()
    try:
        with zipfile.ZipFile(archive) as bundle:
            for entry in bundle.infolist():
                target = (destination / entry.filename).resolve()
                if target != root and root not in target.parents:
                    raise ManagerError(f"Archive entry escapes destination: {entry.filename}")
                mode = entry.external_attr >> 16
                if stat.S_ISLNK(mode):
                    raise ManagerError(f"Archive contains unsupported symlink: {entry.filename}")
                if entry.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with bundle.open(entry) as source, target.open("wb") as output:
                    shutil.copyfileobj(source, output)
                permissions = stat.S_IMODE(mode)
                if permissions and os.name != "nt":
                    target.chmod(permissions)
    except (OSError, zipfile.BadZipFile) as exc:
        raise ManagerError(f"Unable to extract archive: {archive.name}: {exc}") from exc


class StateStore:
    def __init__(self, paths: ManagerPaths):
        self.paths = paths

    def load(self) -> ManagerState:
        if self.paths.state.is_file():
            return self._load_json_state()
        legacy = self._legacy_state()
        if legacy.current is not None or legacy.previous is not None:
            self.save(legacy)
        return legacy

    def save(self, state: ManagerState) -> None:
        atomic_json(self.paths.state, asdict(state), mode=0o600)
        if self.legacy_mode:
            self._save_legacy_link("current", state.current)
            self._save_legacy_link("previous", state.previous)

    def pair(self, pair_id: str) -> PairMetadata:
        pair_dir = self.paths.pairs / pair_id
        json_path = pair_dir / "metadata.json"
        if json_path.is_file():
            try:
                raw: object = json.loads(json_path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                raise ManagerError(f"Invalid pair metadata: {json_path}") from exc
            if not isinstance(raw, dict):
                raise ManagerError(f"Invalid pair metadata: {json_path}")
            return self._pair_from_mapping(pair_id, raw)
        legacy_path = pair_dir / "metadata"
        if legacy_path.is_file():
            return self._pair_from_mapping(pair_id, read_properties(legacy_path))
        raise ManagerError(f"Pair metadata is missing: {pair_id}")

    def save_pair(self, pair: PairMetadata) -> None:
        pair_dir = self.paths.pairs / pair.pair_id
        pair_dir.mkdir(parents=True, exist_ok=True)
        atomic_json(
            pair_dir / "metadata.json",
            {
                "schema_version": 2,
                "pair_id": pair.pair_id,
                "ghidra_version": pair.ghidra_version,
                "ghidra_tag": pair.ghidra_tag,
                "plugins": [asdict(plugin) for plugin in pair.plugins],
            },
            mode=0o600,
        )
        if self.legacy_mode:
            mcp = pair.plugin("mcp")
            (pair_dir / "metadata").write_text(
                f"ghidra_version={pair.ghidra_version}\n"
                f"ghidra_tag={pair.ghidra_tag}\n"
                f"mcp_version={mcp.version if mcp else ''}\n"
                f"mcp_tag={mcp.tag if mcp else ''}\n",
                encoding="utf-8",
            )
            self._replace_symlink(pair_dir / "ghidra", self.paths.ghidra / pair.ghidra_version)
            if mcp:
                component = (self.paths.home / mcp.artifact).parent
                self._replace_symlink(pair_dir / "ghidra-mcp", component)

    @property
    def legacy_mode(self) -> bool:
        return (self.paths.home.parent / "ghidra-manager.sh").is_file() and os.name != "nt"

    def _load_json_state(self) -> ManagerState:
        try:
            raw: Any = json.loads(self.paths.state.read_text(encoding="utf-8"))
            state = ManagerState(
                schema_version=int(raw["schema_version"]),
                current=raw.get("current"),
                previous=raw.get("previous"),
            )
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise ManagerError(f"Invalid manager state: {self.paths.state}") from exc
        if state.schema_version not in {1, 2}:
            raise ManagerError(f"Unsupported manager state schema: {state.schema_version}")
        for pair_id in (state.current, state.previous):
            if pair_id is not None:
                self.pair(pair_id)
        return state

    def _legacy_state(self) -> ManagerState:
        return ManagerState(
            current=self._legacy_link("current"),
            previous=self._legacy_link("previous"),
        )

    def _legacy_link(self, name: str) -> str | None:
        link = self.paths.home / name
        if not link.is_symlink():
            return None
        try:
            target = link.resolve(strict=True)
        except OSError as exc:
            raise ManagerError(f"Legacy {name} link is invalid: {link}") from exc
        pair_id = target.name
        self.pair(pair_id)
        return pair_id

    def _save_legacy_link(self, name: str, pair_id: str | None) -> None:
        path = self.paths.home / name
        if pair_id is None:
            path.unlink(missing_ok=True)
            return
        self._replace_symlink(path, self.paths.pairs / pair_id)

    @staticmethod
    def _replace_symlink(path: Path, target: Path) -> None:
        staged = path.with_name(f".{path.name}.{os.getpid()}.next")
        staged.unlink(missing_ok=True)
        staged.symlink_to(target, target_is_directory=True)
        os.replace(staged, path)

    def _pair_from_mapping(self, pair_id: str, raw: dict[str, Any]) -> PairMetadata:
        try:
            plugins_raw = raw.get("plugins")
            if isinstance(plugins_raw, list):
                plugins = tuple(
                    sorted(
                        (self._plugin_from_mapping(item) for item in plugins_raw),
                        key=lambda plugin: plugin.plugin_id,
                    )
                )
            else:
                plugins = (self._legacy_mcp(raw),)
            return PairMetadata(
                pair_id=pair_id,
                ghidra_version=str(raw["ghidra_version"]),
                ghidra_tag=str(raw["ghidra_tag"]),
                plugins=plugins,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ManagerError(f"Pair metadata is incomplete: {pair_id}") from exc

    @staticmethod
    def _plugin_from_mapping(raw: object) -> PluginMetadata:
        if not isinstance(raw, dict):
            raise TypeError("plugin metadata is not an object")
        runtime_raw = raw.get("runtime_files", [])
        if not isinstance(runtime_raw, list):
            raise TypeError("runtime files are invalid")
        return PluginMetadata(
            plugin_id=str(raw["plugin_id"]),
            version=str(raw["version"]),
            tag=str(raw["tag"]),
            commit=str(raw["commit"]),
            extension_name=str(raw["extension_name"]),
            extension_root=str(raw["extension_root"]),
            artifact=str(raw["artifact"]),
            digest=str(raw["digest"]),
            runtime_files=tuple((str(key), str(path)) for key, path in runtime_raw),
        )

    def _legacy_mcp(self, raw: dict[str, Any]) -> PluginMetadata:
        version = str(raw["mcp_version"])
        tag = str(raw["mcp_tag"])
        component = self.paths.mcp / version
        metadata_path = component / "metadata.json"
        if metadata_path.is_file():
            metadata_raw: object = json.loads(metadata_path.read_text(encoding="utf-8"))
            if not isinstance(metadata_raw, dict):
                raise TypeError("legacy MCP metadata is invalid")
            metadata = {str(key): str(value) for key, value in metadata_raw.items()}
        elif (component / "metadata").is_file():
            metadata = read_properties(component / "metadata")
        else:
            metadata = {"extension_asset": f"GhidraMCP-{version}.zip"}
        extension = metadata["extension_asset"]
        artifact_path = component / extension
        digest = (
            f"sha256:{hashlib.sha256(artifact_path.read_bytes()).hexdigest()}"
            if artifact_path.is_file()
            else ""
        )
        runtime_files = tuple(
            (name, str((component / metadata[key]).relative_to(self.paths.home)))
            for name, key in (("bridge", "bridge_asset"), ("requirements", "requirements_asset"))
            if metadata.get(key)
        )
        return PluginMetadata(
            plugin_id="mcp",
            version=version,
            tag=tag,
            commit=f"legacy-{tag}",
            extension_name="GhidraMCP",
            extension_root="GhidraMCP",
            artifact=str(artifact_path.relative_to(self.paths.home)),
            digest=digest,
            runtime_files=runtime_files,
        )
