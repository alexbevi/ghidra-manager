"""High-level manager operations."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from ghidra_manager import compare as compare_engine
from ghidra_manager.config import ManagerPaths
from ghidra_manager.errors import ManagerError
from ghidra_manager.github import GitHubClient
from ghidra_manager.instance_state import (
    InstanceReport,
)
from ghidra_manager.mcp import (
    DEFAULT_PORT,
    Instance,
    discover_instances,
    probe_analysis,
    probe_server,
)
from ghidra_manager.models import (
    DoctorCheck,
    DoctorLevel,
    ManagerState,
    PairMetadata,
    PluginMetadata,
    ReleaseAsset,
    ResolvedGhidra,
    ResolvedPair,
    ResolvedPluginSource,
)
from ghidra_manager.platforms import (
    find_java21,
    run_plugin_build,
)
from ghidra_manager.plugins import (
    PluginDefinition,
    load_registry,
    plugin_definition,
    resolve_plugin_source,
    validate_plugin_archive,
)
from ghidra_manager.processes import (
    managed_ghidra_running,
)
from ghidra_manager.releases import (
    ReleaseClient,
    file_digest,
    resolve_ghidra,
    resolve_pair,
    verify_digest,
)
from ghidra_manager.runtime import InstanceService
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

    def plugin_discovery(self) -> list[dict[str, object]]:
        """Return the bundled plugin catalog with active selection state."""
        store = StateStore(self.paths)
        state = store.load()
        selected = (
            {plugin.plugin_id for plugin in store.pair(state.current).plugins}
            if state.current
            else set()
        )
        return [plugin.as_dict(selected=plugin.plugin_id in selected) for plugin in load_registry()]

    def plugin_list(self) -> dict[str, object]:
        store = StateStore(self.paths)
        state = store.load()
        if state.current is None:
            return {"ghidra_version": None, "plugins": []}
        pair = store.pair(state.current)
        return {
            "ghidra_version": pair.ghidra_version,
            "plugins": [
                {
                    "id": plugin.plugin_id,
                    "version": plugin.version,
                    "tag": plugin.tag,
                    "commit": plugin.commit,
                    "extension_root": plugin.extension_root,
                }
                for plugin in pair.plugins
            ],
        }

    def status_lines(self) -> list[str]:
        store = StateStore(self.paths)
        state = store.load()
        lines: list[str] = []
        if state.current:
            current = store.pair(state.current)
            lines.append(f"Active Ghidra:      {current.ghidra_version}")
            if current.plugins:
                for plugin in current.plugins:
                    installed = (
                        "installed"
                        if self._installed_plugin_matches(current, plugin)
                        else "missing"
                    )
                    lines.append(
                        f"Active plugin:      {plugin.plugin_id} {plugin.version} ({installed})"
                    )
            else:
                lines.append("Active plugins:     none")
        else:
            lines.append("Active pair:        not installed")
        if state.previous:
            previous = store.pair(state.previous)
            plugin_ids = ", ".join(plugin.plugin_id for plugin in previous.plugins) or "none"
            lines.append(
                f"Previous pair:      Ghidra {previous.ghidra_version}; plugins {plugin_ids}"
            )
        else:
            lines.append("Previous pair:      none")
        resolved = resolve_ghidra(self.client)
        lines.append(f"Upstream Ghidra:    {resolved.version}")
        return lines

    def doctor(
        self,
        project: str | None = None,
        *,
        program: str | None = None,
        base_port: int = DEFAULT_PORT,
    ) -> list[DoctorCheck]:
        checks: list[DoctorCheck] = []
        store = StateStore(self.paths)
        try:
            state = store.load()
        except ManagerError as exc:
            return [DoctorCheck("active-pair", "error", str(exc))]
        if state.current is None:
            return [DoctorCheck("active-pair", "error", "not installed; run sync")]
        try:
            pair = store.pair(state.current)
        except ManagerError as exc:
            return [DoctorCheck("active-pair", "error", str(exc))]
        checks.append(
            DoctorCheck(
                "active-pair",
                "ok",
                f"Ghidra {pair.ghidra_version}; "
                f"plugins {', '.join(item.plugin_id for item in pair.plugins) or 'none'}",
            )
        )

        install = self.paths.ghidra / pair.ghidra_version
        if self._valid_ghidra(install, pair.ghidra_version):
            checks.append(DoctorCheck("installation", "ok", str(install)))
        else:
            checks.append(DoctorCheck("installation", "error", f"missing or invalid: {install}"))
        mcp = pair.plugin("mcp")
        if mcp is None:
            checks.append(
                DoctorCheck(
                    "extension",
                    "error",
                    "MCP plugin is not installed; run ghidra-manager plugins install mcp",
                )
            )
        else:
            try:
                installed_mcp = self._installed_mcp_version(pair.ghidra_version)
            except ManagerError as exc:
                installed_mcp = None
                extension_detail = str(exc)
            else:
                extension_detail = (
                    (
                        f"GhidraMCP {installed_mcp}"
                        if installed_mcp == mcp.version
                        else f"GhidraMCP {installed_mcp}; expected {mcp.version}"
                    )
                    if installed_mcp is not None
                    else "GhidraMCP extension is missing"
                )
            extension_level: DoctorLevel = "ok" if installed_mcp == mcp.version else "error"
            checks.append(DoctorCheck("extension", extension_level, extension_detail))

        try:
            java_home = find_java21()
        except ManagerError as exc:
            checks.append(DoctorCheck("jdk", "error", str(exc)))
        else:
            checks.append(DoctorCheck("jdk", "ok", f"JDK 21 at {java_home}"))

        resolved_project: Path | None = None
        if project:
            try:
                resolved_project = self._resolve_project(project)
            except ManagerError as exc:
                checks.append(DoctorCheck("project", "error", str(exc)))
            else:
                checks.append(DoctorCheck("project", "ok", str(resolved_project)))
        else:
            try:
                _, preferences, recorded, _ = self._project_registry()
            except ManagerError as exc:
                checks.append(DoctorCheck("projects", "warning", str(exc)))
            else:
                level: DoctorLevel = "ok" if recorded else "warning"
                checks.append(
                    DoctorCheck(
                        "projects",
                        level,
                        f"{len(recorded)} recorded projects in {preferences}",
                    )
                )

        if mcp is None:
            return checks

        try:
            instances = self.instance_discovery(base_port)
        except ManagerError as exc:
            checks.append(DoctorCheck("instances", "error", str(exc)))
            return checks
        selected: Instance | None = None
        if resolved_project:
            matches = [item for item in instances if item.project == resolved_project.stem]
            if len(matches) == 1:
                selected = matches[0]
                checks.append(
                    DoctorCheck(
                        "instance",
                        "ok",
                        f"PID {selected.pid} on {selected.url}",
                    )
                )
            elif matches:
                checks.append(
                    DoctorCheck(
                        "instance",
                        "error",
                        f"multiple MCP instances report project {resolved_project.stem}",
                    )
                )
            else:
                checks.append(
                    DoctorCheck(
                        "instance",
                        "error",
                        f"no MCP instance reports project {resolved_project.stem}",
                    )
                )
        else:
            level = "ok" if instances else "warning"
            checks.append(
                DoctorCheck(
                    "instances",
                    level,
                    f"{len(instances)} responding on ports {base_port}-{base_port + 15}",
                )
            )
            for instance in instances:
                self._doctor_server(
                    checks,
                    instance,
                    pair,
                    mcp,
                    name=f"mcp-server:{instance.port}",
                )

        if selected:
            self._doctor_instance(checks, selected, pair, mcp, program)
        elif program:
            checks.append(
                DoctorCheck(
                    "program", "error", "--program requires one responding project instance"
                )
            )
        return checks

    @staticmethod
    def _doctor_instance(
        checks: list[DoctorCheck],
        instance: Instance,
        pair: PairMetadata,
        mcp: PluginMetadata,
        program: str | None,
    ) -> None:
        Manager._doctor_server(checks, instance, pair, mcp)

        selected_program = program
        if program:
            if program in instance.programs:
                checks.append(DoctorCheck("program", "ok", f"{program} is open"))
            else:
                available = ", ".join(instance.programs) or "none"
                checks.append(
                    DoctorCheck(
                        "program",
                        "error",
                        f"{program} is not open; reported programs: {available}",
                    )
                )
                selected_program = None
        elif len(instance.programs) == 1:
            selected_program = instance.programs[0]
            checks.append(DoctorCheck("program", "ok", f"{selected_program} is open"))
        elif instance.programs:
            checks.append(
                DoctorCheck(
                    "program",
                    "warning",
                    f"multiple programs are open: {', '.join(instance.programs)}; use --program",
                )
            )
        else:
            checks.append(DoctorCheck("program", "warning", "no open program reported"))

        if selected_program:
            analysis = probe_analysis(instance.port, selected_program)
            if analysis is None:
                checks.append(DoctorCheck("analysis", "error", "analysis status probe failed"))
            elif analysis.program != selected_program:
                checks.append(
                    DoctorCheck(
                        "analysis",
                        "error",
                        f"analysis probe returned {analysis.program}, expected {selected_program}",
                    )
                )
            elif analysis.analyzing:
                checks.append(
                    DoctorCheck("analysis", "error", f"{selected_program} is still analyzing")
                )
            elif not analysis.analyzed:
                checks.append(
                    DoctorCheck("analysis", "error", f"{selected_program} is not analyzed")
                )
            else:
                checks.append(
                    DoctorCheck(
                        "analysis",
                        "ok",
                        f"{selected_program} analyzed; {analysis.function_count} functions",
                    )
                )

    @staticmethod
    def _doctor_server(
        checks: list[DoctorCheck],
        instance: Instance,
        pair: PairMetadata,
        mcp: PluginMetadata,
        *,
        name: str = "mcp-server",
    ) -> None:
        server = probe_server(instance.port)
        if server is None:
            checks.append(DoctorCheck(name, "error", "version probe failed"))
        else:
            mismatches = []
            if server.plugin_version != mcp.version:
                mismatches.append(f"plugin {server.plugin_version}, expected {mcp.version}")
            if server.ghidra_version != pair.ghidra_version:
                mismatches.append(f"Ghidra {server.ghidra_version}, expected {pair.ghidra_version}")
            if not server.java_version.startswith("21."):
                mismatches.append(f"Java {server.java_version}, expected 21.x")
            if server.endpoint_count <= 0:
                mismatches.append("endpoint catalog is empty")
            if mismatches:
                checks.append(DoctorCheck(name, "error", "; ".join(mismatches)))
            else:
                checks.append(
                    DoctorCheck(
                        name,
                        "ok",
                        f"GhidraMCP {server.plugin_version}; {server.endpoint_count} endpoints; "
                        f"Java {server.java_version}",
                    )
                )

    def sync(self, *, dry_run: bool = False) -> list[str]:
        lines = ["Resolving stable upstream releases..."]
        resolved = resolve_ghidra(self.client)
        lines.append(f"Upstream Ghidra:    {resolved.version}")
        store = StateStore(self.paths)
        state = store.load()
        selected_ids: list[str] = []
        if state.current:
            selected_ids = [plugin.plugin_id for plugin in store.pair(state.current).plugins]
        definitions = [plugin_definition(plugin_id) for plugin_id in selected_ids]
        sources = [
            (definition, resolve_plugin_source(self.client, definition))
            for definition in definitions
        ]
        for definition, source in sources:
            lines.append(f"Upstream plugin:    {definition.plugin_id} {source.version}")
        if dry_run:
            current = store.pair(state.current) if state.current else None
            current_sources = (
                {plugin.plugin_id: (plugin.tag, plugin.commit) for plugin in current.plugins}
                if current
                else {}
            )
            wanted_sources = {
                definition.plugin_id: (source.tag, source.commit) for definition, source in sources
            }
            if (
                current
                and current.ghidra_version == resolved.version
                and current_sources == wanted_sources
            ):
                lines.append("Dry run: the active pair is already current.")
            else:
                plugin_summary = ", ".join(selected_ids) or "none"
                lines.append(
                    f"Dry run: would activate Ghidra {resolved.version}; plugins {plugin_summary}."
                )
            return lines
        if self.process_check(self.paths.ghidra):
            raise ManagerError("Close the managed Ghidra instance before syncing")
        self.paths.home.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="transaction-", dir=self.paths.home) as temporary:
            transaction = Path(temporary)
            lines.extend(self._ensure_ghidra(resolved, transaction))
            installed_plugins = tuple(
                self._ensure_plugin(definition, source, resolved.version, transaction)
                for definition, source in sources
            )
            pair = self._pair_metadata(resolved.version, resolved.tag, installed_plugins)
            if state.current == pair.pair_id and self._pair_active(pair):
                lines.append(
                    f"Already current: Ghidra {resolved.version}; "
                    f"plugins {', '.join(selected_ids) or 'none'}."
                )
                return lines
            self._activate_plugins(pair, transaction)
            store.save_pair(pair)
            previous = state.current if state.current != pair.pair_id else state.previous
            store.save(ManagerState(current=pair.pair_id, previous=previous))
        self._prune(store.load())
        lines.append(
            f"Active pair: Ghidra {resolved.version}; plugins {', '.join(selected_ids) or 'none'}."
        )
        return lines

    def plugin_install(self, plugin_id: str) -> list[str]:
        definition = plugin_definition(plugin_id)
        store = StateStore(self.paths)
        state = store.load()
        if state.current is None:
            raise ManagerError("No active pair. Run ghidra-manager sync first.")
        current = store.pair(state.current)
        if self.process_check(self.paths.ghidra):
            raise ManagerError("Close the managed Ghidra instance before installing plugins")
        source = resolve_plugin_source(self.client, definition)
        self.paths.home.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="plugin-transaction-", dir=self.paths.home
        ) as value:
            transaction = Path(value)
            installed = self._ensure_plugin(definition, source, current.ghidra_version, transaction)
            plugins = {plugin.plugin_id: plugin for plugin in current.plugins}
            plugins[plugin_id] = installed
            pair = self._pair_metadata(
                current.ghidra_version,
                current.ghidra_tag,
                tuple(plugins.values()),
            )
            if state.current == pair.pair_id and self._pair_active(pair):
                return [f"Plugin already current: {plugin_id} {source.version}."]
            self._activate_plugins(pair, transaction)
            store.save_pair(pair)
            previous = state.current if state.current != pair.pair_id else state.previous
            store.save(ManagerState(current=pair.pair_id, previous=previous))
        self._prune(store.load())
        return [
            f"Installed plugin {plugin_id} {source.version} for Ghidra {current.ghidra_version}."
        ]

    def plugin_remove(self, plugin_id: str) -> list[str]:
        plugin_definition(plugin_id)
        store = StateStore(self.paths)
        state = store.load()
        if state.current is None:
            raise ManagerError("No active pair. Run ghidra-manager sync first.")
        current = store.pair(state.current)
        if current.plugin(plugin_id) is None:
            return [f"Plugin is not installed: {plugin_id}."]
        if self.process_check(self.paths.ghidra):
            raise ManagerError("Close the managed Ghidra instance before removing plugins")
        plugins = tuple(plugin for plugin in current.plugins if plugin.plugin_id != plugin_id)
        pair = self._pair_metadata(
            current.ghidra_version,
            current.ghidra_tag,
            plugins,
        )
        self.paths.home.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="plugin-remove-", dir=self.paths.home) as value:
            self._activate_plugins(pair, Path(value))
            store.save_pair(pair)
            store.save(ManagerState(current=pair.pair_id, previous=current.pair_id))
        self._prune(store.load())
        return [f"Removed plugin {plugin_id} from Ghidra {current.ghidra_version}."]

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
        with tempfile.TemporaryDirectory(prefix="rollback-", dir=self.paths.home) as temporary:
            self._activate_plugins(previous, Path(temporary))
            store.save(ManagerState(current=previous.pair_id, previous=current.pair_id))
        self._prune(store.load())
        plugins = ", ".join(plugin.plugin_id for plugin in previous.plugins) or "none"
        return [f"Rolled back to Ghidra {previous.ghidra_version}; plugins {plugins}."]

    def projects(self, *, base_port: int = DEFAULT_PORT) -> list[str]:
        return self._runtime().projects(base_port=base_port)

    def open_project(
        self,
        project: str,
        *,
        program: str | None = None,
        timeout: int = 180,
        base_port: int = DEFAULT_PORT,
    ) -> list[str]:
        return self._runtime().open_project(
            project,
            program=program,
            timeout=timeout,
            base_port=base_port,
        )

    def open_projects(
        self,
        projects: list[str],
        *,
        program: str | None = None,
        timeout: int = 180,
        base_port: int = DEFAULT_PORT,
    ) -> list[str]:
        return self._runtime().open_projects(
            projects,
            program=program,
            timeout=timeout,
            base_port=base_port,
        )

    def stop_instance(
        self,
        target: str,
        *,
        timeout: int = 10,
        force: bool = False,
        base_port: int = DEFAULT_PORT,
    ) -> list[str]:
        return self._runtime().stop_instance(
            target,
            timeout=timeout,
            force=force,
            base_port=base_port,
        )

    def restart_instance(
        self,
        target: str,
        *,
        program: str | None = None,
        timeout: int = 180,
        stop_timeout: int = 10,
        force: bool = False,
        base_port: int = DEFAULT_PORT,
    ) -> list[str]:
        return self._runtime().restart_instance(
            target,
            program=program,
            timeout=timeout,
            stop_timeout=stop_timeout,
            force=force,
            base_port=base_port,
        )

    def instance_reports(self, base_port: int = DEFAULT_PORT) -> list[InstanceReport]:
        return self._runtime().instance_reports(base_port)

    def instance_log(self, target: str | None = None) -> Path:
        return self._runtime().instance_log(target)

    def launch(self, arguments: list[str]) -> tuple[str, int]:
        return self._runtime().launch(arguments)

    def launch_multi(
        self,
        projects: list[str],
        *,
        count: int | None = None,
        timeout: int = 180,
        base_port: int = DEFAULT_PORT,
    ) -> list[str]:
        return self._runtime().launch_multi(
            projects,
            count=count,
            timeout=timeout,
            base_port=base_port,
        )

    def bridge(self, arguments: list[str]) -> int:
        return self._runtime().bridge(arguments)

    def compare(
        self, source_project: str, target_project: str, *, base_port: int = DEFAULT_PORT
    ) -> int:
        self._require_mcp(self._require_active_pair())
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
        self._require_mcp(self._require_active_pair())
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

    def require_mcp(self) -> None:
        self._require_mcp(self._require_active_pair())

    @staticmethod
    def _require_mcp(pair: PairMetadata) -> PluginMetadata:
        plugin = pair.plugin("mcp")
        if plugin is None:
            raise ManagerError(
                "MCP plugin is not installed. Run ghidra-manager plugins install mcp."
            )
        return plugin

    @staticmethod
    def _resolve_instance(project: str, instances: list[Instance]) -> Instance:
        matches = [item for item in instances if item.project == project]
        if not matches:
            raise ManagerError(f"No responding GhidraMCP instance has project name: {project}")
        if len(matches) != 1:
            raise ManagerError(f"Multiple responding instances have project name: {project}")
        return matches[0]

    def _runtime(self) -> InstanceService:
        return InstanceService(self.paths, self.instance_discovery)

    def _project_registry(self) -> tuple[PairMetadata, Path, list[str], str]:
        return self._runtime().project_registry()

    def _resolve_project(self, value: str) -> Path:
        return self._runtime().resolve_project(value)


    def _ensure_ghidra(self, resolved: ResolvedGhidra, transaction: Path) -> list[str]:
        destination = self.paths.ghidra / resolved.version
        if self._valid_ghidra(destination, resolved.version):
            return []
        archive = transaction / resolved.asset.name
        self._download(resolved.asset, archive)
        extract_dir = transaction / "ghidra-extract"
        safe_extract(archive, extract_dir)
        roots = [path for path in extract_dir.iterdir() if path.is_dir()]
        if len(roots) != 1 or not self._valid_ghidra(roots[0], resolved.version):
            raise ManagerError("Extracted Ghidra installation failed validation")
        atomic_json(
            roots[0] / ".manager-metadata.json",
            {
                "ghidra_version": resolved.version,
                "ghidra_tag": resolved.tag,
                "asset": resolved.asset.name,
                "digest": resolved.asset.digest,
            },
            mode=0o600,
        )
        self._replace_directory(roots[0], destination)
        return [f"Downloading Ghidra {resolved.version}..."]

    def _ensure_plugin(
        self,
        definition: PluginDefinition,
        source: ResolvedPluginSource,
        ghidra_version: str,
        transaction: Path,
    ) -> PluginMetadata:
        destination = self.paths.plugins / definition.plugin_id / ghidra_version / source.commit
        cached = self._cached_plugin(destination)
        if cached is not None:
            return cached
        source_archive = transaction / f"{definition.plugin_id}-source.zip"
        self.client.download(source.archive_url, source_archive)
        source_digest = file_digest(source_archive)
        source_extract = transaction / f"{definition.plugin_id}-source"
        safe_extract(source_archive, source_extract)
        roots = [path for path in source_extract.iterdir() if path.is_dir()]
        if len(roots) != 1:
            raise ManagerError(
                f"Plugin source archive has an unexpected layout: {definition.plugin_id}"
            )
        build_root = transaction / f"{definition.plugin_id}-build-root"
        build_root.mkdir()
        source_root = build_root / definition.extension_root
        source_root.parent.mkdir(parents=True, exist_ok=True)
        roots[0].replace(source_root)
        java_home = find_java21()
        self.paths.gradle_cache.mkdir(parents=True, exist_ok=True)
        run_plugin_build(
            self.paths.ghidra / ghidra_version,
            source_root,
            definition.build_task,
            java_home,
            self.paths.gradle_cache,
        )
        artifacts = [
            path for path in source_root.glob(definition.artifact_pattern) if path.is_file()
        ]
        if len(artifacts) != 1:
            raise ManagerError(
                f"Expected one built artifact for {definition.plugin_id}, found {len(artifacts)}"
            )
        validate_plugin_archive(
            artifacts[0],
            definition,
            ghidra_version=ghidra_version,
            plugin_version=source.version,
        )
        stage = transaction / f"{definition.plugin_id}-component"
        stage.mkdir()
        archive = stage / "extension.zip"
        shutil.copy2(artifacts[0], archive)
        runtime_files: list[tuple[str, str]] = []
        source_runtime = dict(definition.runtime_files)
        release_runtime = dict(source.runtime_assets)
        runtime_names = sorted(
            set(source_runtime)
            | {name for name, _pattern in definition.runtime_asset_patterns}
        )
        for name in runtime_names:
            asset = release_runtime.get(name)
            relative = source_runtime.get(name)
            if asset is not None:
                runtime_target = stage / "runtime" / asset.name
                runtime_target.parent.mkdir(parents=True, exist_ok=True)
                self.client.download(asset.url, runtime_target)
                verify_digest(runtime_target, asset.digest)
            elif relative is not None:
                runtime_source = source_root / relative
                if not runtime_source.is_file():
                    raise ManagerError(
                        f"Plugin source is missing runtime file: "
                        f"{definition.plugin_id} {relative}"
                    )
                runtime_target = stage / "runtime" / Path(relative).name
                runtime_target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(runtime_source, runtime_target)
            else:
                raise ManagerError(
                    f"Plugin release is missing runtime asset: {definition.plugin_id} {name}"
                )
            runtime_files.append(
                (
                    name,
                    str(
                        (destination / "runtime" / runtime_target.name).relative_to(self.paths.home)
                    ),
                )
            )
        plugin = PluginMetadata(
            plugin_id=definition.plugin_id,
            version=source.version,
            tag=source.tag,
            commit=source.commit,
            extension_name=definition.extension_name,
            extension_root=definition.extension_root,
            artifact=str((destination / "extension.zip").relative_to(self.paths.home)),
            digest=file_digest(archive),
            runtime_files=tuple(runtime_files),
        )
        atomic_json(
            stage / "metadata.json",
            {"plugin": self._plugin_json(plugin), "source_digest": source_digest},
            mode=0o600,
        )
        self._replace_directory(stage, destination)
        return plugin

    def _cached_plugin(self, destination: Path) -> PluginMetadata | None:
        metadata_path = destination / "metadata.json"
        if not metadata_path.is_file():
            return None
        try:
            raw: object = json.loads(metadata_path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict) or not isinstance(raw.get("plugin"), dict):
                return None
            plugin = StateStore._plugin_from_mapping(raw["plugin"])
        except (OSError, ValueError, TypeError, KeyError):
            return None
        archive = self.paths.home / plugin.artifact
        if not archive.is_file() or file_digest(archive) != plugin.digest:
            return None
        definition = plugin_definition(plugin.plugin_id)
        validate_plugin_archive(
            archive,
            definition,
            ghidra_version=destination.parent.name,
            plugin_version=plugin.version,
        )
        return plugin

    @staticmethod
    def _plugin_json(plugin: PluginMetadata) -> dict[str, object]:
        return {
            "plugin_id": plugin.plugin_id,
            "version": plugin.version,
            "tag": plugin.tag,
            "commit": plugin.commit,
            "extension_name": plugin.extension_name,
            "extension_root": plugin.extension_root,
            "artifact": plugin.artifact,
            "digest": plugin.digest,
            "runtime_files": list(plugin.runtime_files),
        }

    @classmethod
    def _pair_metadata(
        cls,
        ghidra_version: str,
        ghidra_tag: str,
        plugins: tuple[PluginMetadata, ...],
    ) -> PairMetadata:
        ordered = tuple(sorted(plugins, key=lambda plugin: plugin.plugin_id))
        if len({plugin.plugin_id for plugin in ordered}) != len(ordered):
            raise ManagerError("A managed pair cannot contain duplicate plugins")
        if ordered:
            manifest = json.dumps(
                [
                    {"id": plugin.plugin_id, "tag": plugin.tag, "commit": plugin.commit}
                    for plugin in ordered
                ],
                sort_keys=True,
                separators=(",", ":"),
            )
            suffix = hashlib.sha256(manifest.encode("utf-8")).hexdigest()[:12]
        else:
            suffix = "none"
        return PairMetadata(
            pair_id=f"ghidra-{ghidra_version}__plugins-{suffix}",
            ghidra_version=ghidra_version,
            ghidra_tag=ghidra_tag,
            plugins=ordered,
        )

    def _activate_plugins(self, pair: PairMetadata, transaction: Path) -> None:
        install = self.paths.ghidra / pair.ghidra_version
        if not self._valid_ghidra(install, pair.ghidra_version):
            raise ManagerError("Pair Ghidra installation is missing or invalid")
        prepared: dict[str, Path] = {}
        activation = transaction / "plugin-activation"
        activation.mkdir()
        for plugin in pair.plugins:
            definition = plugin_definition(plugin.plugin_id)
            archive = self.paths.home / plugin.artifact
            if not archive.is_file():
                raise ManagerError(f"Plugin artifact is missing: {plugin.plugin_id}")
            if plugin.digest and file_digest(archive) != plugin.digest:
                raise ManagerError(f"Plugin artifact digest mismatch: {plugin.plugin_id}")
            validate_plugin_archive(
                archive,
                definition,
                ghidra_version=pair.ghidra_version,
                plugin_version=plugin.version,
            )
            unpacked = activation / plugin.plugin_id
            safe_extract(archive, unpacked)
            source = unpacked / plugin.extension_root
            if not source.is_dir():
                raise ManagerError(f"Plugin archive has an unexpected root: {plugin.plugin_id}")
            prepared[plugin.extension_root] = source
        extension_dir = install / "Ghidra" / "Extensions"
        extension_dir.mkdir(parents=True, exist_ok=True)
        managed_roots = {definition.extension_root for definition in load_registry()}
        managed_roots.update(plugin.extension_root for plugin in pair.plugins)
        backup = transaction / "plugin-backup"
        backup.mkdir()
        try:
            for root in sorted(managed_roots):
                target = extension_dir / root
                if target.exists():
                    target.replace(backup / root)
            for plugin in pair.plugins:
                target = extension_dir / plugin.extension_root
                prepared[plugin.extension_root].replace(target)
                atomic_json(
                    target / ".manager-plugin.json",
                    {
                        "plugin_id": plugin.plugin_id,
                        "version": plugin.version,
                        "tag": plugin.tag,
                        "commit": plugin.commit,
                        "digest": plugin.digest,
                    },
                    mode=0o600,
                )
        except Exception:
            for root in managed_roots:
                target = extension_dir / root
                if target.is_dir():
                    shutil.rmtree(target)
                retained = backup / root
                if retained.exists():
                    retained.replace(target)
            raise

    def _pair_active(self, pair: PairMetadata) -> bool:
        if not self._valid_ghidra(self.paths.ghidra / pair.ghidra_version, pair.ghidra_version):
            return False
        expected = {plugin.extension_root: plugin for plugin in pair.plugins}
        extension_dir = self.paths.ghidra / pair.ghidra_version / "Ghidra" / "Extensions"
        for definition in load_registry():
            target = extension_dir / definition.extension_root
            plugin = expected.get(definition.extension_root)
            if plugin is None:
                if target.exists():
                    return False
                continue
            marker = target / ".manager-plugin.json"
            try:
                raw: object = json.loads(marker.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                return False
            if not isinstance(raw, dict) or raw.get("commit") != plugin.commit:
                return False
        return True

    def _installed_plugin_matches(self, pair: PairMetadata, plugin: PluginMetadata) -> bool:
        if plugin.commit.startswith("legacy-") and plugin.plugin_id == "mcp":
            return self._installed_mcp_version(pair.ghidra_version) == plugin.version
        marker = (
            self.paths.ghidra
            / pair.ghidra_version
            / "Ghidra"
            / "Extensions"
            / plugin.extension_root
            / ".manager-plugin.json"
        )
        try:
            raw: object = json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return False
        return isinstance(raw, dict) and raw.get("commit") == plugin.commit

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
        keep_mcp = {
            Path(plugin.artifact).parts[1]
            for pair in pairs
            for plugin in pair.plugins
            if Path(plugin.artifact).parts[:1] == ("ghidra-mcp",)
        }
        keep_plugins = {
            (self.paths.home / plugin.artifact).parent.resolve()
            for pair in pairs
            for plugin in pair.plugins
            if Path(plugin.artifact).parts[:1] == ("plugins",)
        }
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
        if self.paths.plugins.is_dir():
            components = [path for path in self.paths.plugins.glob("*/*/*") if path.is_dir()]
            for component in components:
                if component.resolve() not in keep_plugins:
                    shutil.rmtree(component)
            for directory in sorted(
                (path for path in self.paths.plugins.glob("*/*") if path.is_dir()),
                key=lambda path: len(path.parts),
                reverse=True,
            ):
                if not any(directory.iterdir()):
                    directory.rmdir()

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
