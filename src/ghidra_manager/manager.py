"""High-level manager operations."""

from __future__ import annotations

import json
import re
import shutil
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from ghidra_manager import compare as compare_engine
from ghidra_manager.config import ManagerPaths
from ghidra_manager.errors import ManagerError
from ghidra_manager.github import GitHubClient
from ghidra_manager.mcp import DEFAULT_PORT, Instance, discover_instances
from ghidra_manager.models import ManagerState, PairMetadata, ReleaseAsset, ResolvedPair
from ghidra_manager.platforms import (
    find_java21,
    ghidra_settings_dir,
    run_bridge,
    run_ghidra,
    start_ghidra_instance,
)
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

COMPARE_PLAN_VERSION = 1
COMPARE_PLAN_RETENTION = 10


@dataclass(slots=True)
class Manager:
    paths: ManagerPaths
    client: ReleaseClient
    process_check: Callable[[Path], bool] = managed_ghidra_running
    instance_discovery: Callable[[int], list[Instance]] = discover_instances

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

    def projects(self, *, base_port: int = DEFAULT_PORT) -> list[str]:
        store = StateStore(self.paths)
        state = store.load()
        if state.current is None:
            raise ManagerError("No active pair. Run ghidra-manager sync first.")
        pair = store.pair(state.current)
        application = self.paths.ghidra / pair.ghidra_version / "Ghidra/application.properties"
        if not application.is_file():
            raise ManagerError("Active Ghidra application metadata is missing")
        release_name = read_properties(application).get("application.release.name")
        if not release_name:
            raise ManagerError("Active Ghidra release name is missing")
        settings_dir = ghidra_settings_dir(pair.ghidra_version, release_name)
        preferences = settings_dir / "preferences"
        if not preferences.is_file():
            raise ManagerError(
                f"No Ghidra project registry found at {preferences}. Launch Ghidra once first."
            )
        values = read_properties(preferences)
        recent = values.get("RecentProjects", "").split(";")
        last_opened = self._project_base(values.get("LastOpenedProject", ""))
        known = ([last_opened] if last_opened else []) + recent
        unique: list[str] = []
        for item in known:
            base = self._project_base(item)
            if base and base not in unique:
                unique.append(base)
        if not unique:
            return [f"Ghidra has no recorded projects in {preferences}."]
        active = {instance.project: instance for instance in self.instance_discovery(base_port)}
        lines = [f"Projects known to Ghidra {pair.ghidra_version}:"]
        for base in unique:
            base_path = Path(base)
            project_file = base_path.with_suffix(".gpr")
            repository = base_path.with_suffix(".rep")
            if project_file.is_file() and repository.is_dir():
                storage = "ready"
            elif project_file.is_file() or repository.is_dir():
                storage = "incomplete"
            else:
                storage = "missing"
            last_status = "last-opened" if base == last_opened else "recent"
            instance = active.get(base_path.name)
            active_status = (
                f"active MCP port {instance.port} (PID {instance.pid})"
                if instance
                else "inactive"
            )
            lines.append(
                f"{base_path.name} | {storage} | {last_status} | "
                f"{active_status} | {project_file}"
            )
        lines.append(f"{len(unique)} recorded projects from {preferences}")
        return lines

    def launch(self, arguments: list[str]) -> tuple[str, int]:
        store = StateStore(self.paths)
        state = store.load()
        if state.current is None:
            raise ManagerError("No active pair. Run ghidra-manager sync first.")
        pair = store.pair(state.current)
        java_home = find_java21()
        message = f"Launching Ghidra {pair.ghidra_version} with JDK 21..."
        return message, run_ghidra(
            self.paths.ghidra / pair.ghidra_version, arguments, java_home
        )

    def launch_multi(
        self,
        projects: list[str],
        *,
        count: int | None = None,
        timeout: int = 180,
        base_port: int = DEFAULT_PORT,
    ) -> list[str]:
        if timeout <= 0:
            raise ManagerError("Timeout must be a positive integer")
        if projects and count is not None:
            raise ManagerError("Use either --count or project paths, not both")
        normalized = [self._normalize_project(path) for path in projects]
        instance_count = len(normalized) if normalized else (count or 2)
        if instance_count < 2:
            raise ManagerError("launch-multi requires at least two instances")
        if instance_count > 16:
            raise ManagerError("Instance count exceeds GhidraMCP's 16-port fallback range")
        if len(set(normalized)) != len(normalized):
            raise ManagerError("Each Ghidra instance requires a different project")
        names = [path.stem for path in normalized]
        if len(set(names)) != len(names):
            raise ManagerError("Project names must be unique for GhidraMCP instance selection")
        store = StateStore(self.paths)
        state = store.load()
        if state.current is None:
            raise ManagerError("No active pair. Run ghidra-manager sync first.")
        pair = store.pair(state.current)
        baseline = self.instance_discovery(base_port)
        active_names = {instance.project for instance in baseline}
        duplicate_active = next((name for name in names if name in active_names), None)
        if duplicate_active:
            raise ManagerError(
                f"Project is already active in a GhidraMCP instance: {duplicate_active}"
            )
        if len(baseline) + instance_count > 16:
            raise ManagerError(
                f"Not enough ports remain in the {base_port}-{base_port + 15} fallback range"
            )
        java_home = find_java21()
        install = self.paths.ghidra / pair.ghidra_version
        stamp = time.strftime("%Y%m%d-%H%M%S")
        log_dir = self.paths.home / "launch-logs"
        lines = [f"Launching {instance_count} Ghidra instances with JDK 21..."]
        for index in range(instance_count):
            project = normalized[index] if normalized else None
            description = str(project) if project else "restore/select a distinct project"
            lines.append(f"  Instance {index + 1}: {description}")
            log_path = log_dir / f"{stamp}-{index + 1}.log"
            process = start_ghidra_instance(install, project, java_home, log_path)
            time.sleep(1)
            if process.poll() is not None:
                detail = log_path.read_text(encoding="utf-8", errors="replace")[:4000]
                raise ManagerError(
                    f"Ghidra instance exited during startup; see {log_path}\n{detail}"
                )
            lines.append(f"    launcher PID {process.pid} | log {log_path}")
        lines.append(
            f"Waiting up to {timeout} seconds for {instance_count} new GhidraMCP endpoints "
            f"on ports {base_port}-{base_port + 15}..."
        )
        baseline_pids = {instance.pid for instance in baseline}
        deadline = time.monotonic() + timeout
        new_instances: list[Instance] = []
        while time.monotonic() < deadline:
            scanned = self.instance_discovery(base_port)
            new_instances = [item for item in scanned if item.pid not in baseline_pids]
            if len(new_instances) >= instance_count:
                lines.append("GhidraMCP instances ready:")
                lines.extend(self._instance_lines(new_instances))
                return lines
            time.sleep(2)
        if new_instances:
            lines.append("New MCP endpoints detected before timeout:")
            lines.extend(self._instance_lines(new_instances))
        raise ManagerError(
            f"Detected {len(new_instances)} of {instance_count} new MCP endpoints. "
            "Open CodeBrowser in each new project, enable GhidraMCP, and run instances "
            "to inspect ports."
        )

    def bridge(self, arguments: list[str]) -> int:
        store = StateStore(self.paths)
        state = store.load()
        if state.current is None:
            raise ManagerError("No active pair. Run ghidra-manager sync first.")
        pair = store.pair(state.current)
        component = self._mcp_metadata(pair.mcp_version)
        bridge_name = component.get("bridge_asset")
        if not bridge_name:
            raise ManagerError("Active MCP component has no bridge asset metadata")
        bridge_path = self.paths.mcp / pair.mcp_version / bridge_name
        if not bridge_path.is_file():
            raise ManagerError("Active MCP bridge is missing. Run sync to repair it.")
        self.paths.python.mkdir(parents=True, exist_ok=True)
        self.paths.uv_cache.mkdir(parents=True, exist_ok=True)
        return run_bridge(
            bridge_path,
            arguments,
            self.paths.python,
            self.paths.uv_cache,
        )

    def compare(
        self, source_project: str, target_project: str, *, base_port: int = DEFAULT_PORT
    ) -> int:
        self._require_active_pair()
        if source_project == target_project:
            raise ManagerError("compare source and target projects must be different")
        instances = self.instance_discovery(base_port)
        source = self._resolve_instance(source_project, instances)
        target = self._resolve_instance(target_project, instances)
        if source.port == target.port:
            raise ManagerError("compare source and target resolved to the same MCP instance")
        return compare_engine.main(
            [
                "generate",
                str(self.paths.home),
                str(COMPARE_PLAN_VERSION),
                str(COMPARE_PLAN_RETENTION),
                source.project,
                str(source.port),
                str(source.pid),
                target.project,
                str(target.port),
                str(target.pid),
            ]
        )

    def compare_apply(self, plan: Path) -> int:
        self._require_active_pair()
        return compare_engine.main(
            [
                "apply",
                str(self.paths.home),
                str(COMPARE_PLAN_VERSION),
                str(COMPARE_PLAN_RETENTION),
                str(plan),
            ]
        )

    def _require_active_pair(self) -> PairMetadata:
        store = StateStore(self.paths)
        state = store.load()
        if state.current is None:
            raise ManagerError("No active pair. Run ghidra-manager sync first.")
        return store.pair(state.current)

    @staticmethod
    def _resolve_instance(project: str, instances: list[Instance]) -> Instance:
        matches = [item for item in instances if item.project == project]
        if not matches:
            raise ManagerError(f"No responding GhidraMCP instance has project name: {project}")
        if len(matches) != 1:
            raise ManagerError(f"Multiple responding instances have project name: {project}")
        return matches[0]

    @staticmethod
    def _normalize_project(value: str) -> Path:
        path = Path(value)
        if path.suffix != ".gpr":
            raise ManagerError(f"Ghidra project must use the .gpr extension: {value}")
        if not path.is_file():
            raise ManagerError(f"Ghidra project not found: {value}")
        return path.resolve()

    @staticmethod
    def _instance_lines(instances: list[Instance]) -> list[str]:
        return [
            f"MCP port {item.port} | PID {item.pid} | project {item.project} | {item.url}"
            for item in sorted(instances)
        ]

    @staticmethod
    def _project_base(value: str) -> str:
        result = value.removeprefix("ghidra:")
        return result.removesuffix(".gpr")

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
