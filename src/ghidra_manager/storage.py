"""Versioned, symlink-free manager state with legacy migration."""

from __future__ import annotations

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
from ghidra_manager.models import ManagerState, PairMetadata


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
        atomic_json(pair_dir / "metadata.json", asdict(pair), mode=0o600)
        if self.legacy_mode:
            (pair_dir / "metadata").write_text(
                f"ghidra_version={pair.ghidra_version}\n"
                f"mcp_version={pair.mcp_version}\n"
                f"ghidra_tag={pair.ghidra_tag}\n"
                f"mcp_tag={pair.mcp_tag}\n",
                encoding="utf-8",
            )
            self._replace_symlink(pair_dir / "ghidra", self.paths.ghidra / pair.ghidra_version)
            self._replace_symlink(pair_dir / "ghidra-mcp", self.paths.mcp / pair.mcp_version)

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
        if state.schema_version != 1:
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

    @staticmethod
    def _pair_from_mapping(pair_id: str, raw: dict[str, Any]) -> PairMetadata:
        try:
            return PairMetadata(
                pair_id=pair_id,
                ghidra_version=str(raw["ghidra_version"]),
                mcp_version=str(raw["mcp_version"]),
                ghidra_tag=str(raw["ghidra_tag"]),
                mcp_tag=str(raw["mcp_tag"]),
            )
        except KeyError as exc:
            raise ManagerError(f"Pair metadata is incomplete: {pair_id}") from exc
