"""High-level manager operations."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from ghidra_manager import compare as compare_engine
from ghidra_manager.config import ManagerPaths
from ghidra_manager.errors import ManagerError
from ghidra_manager.github import GitHubClient
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
    ghidra_settings_dir,
    run_bridge,
    run_ghidra,
    run_plugin_build,
    start_ghidra_instance,
)
from ghidra_manager.plugins import (
    PluginDefinition,
    load_registry,
    plugin_definition,
    resolve_plugin_source,
    validate_plugin_archive,
)
from ghidra_manager.processes import managed_ghidra_running
from ghidra_manager.releases import (
    ReleaseClient,
    file_digest,
    resolve_ghidra,
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
        pair, preferences, unique, last_opened = self._project_registry()
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
                f"active MCP port {instance.port} (PID {instance.pid})" if instance else "inactive"
            )
            lines.append(
                f"{base_path.name} | {storage} | {last_status} | {active_status} | {project_file}"
            )
        lines.append(f"{len(unique)} recorded projects from {preferences}")
        return lines

    def _project_registry(self) -> tuple[PairMetadata, Path, list[str], str]:
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
        return pair, preferences, unique, last_opened

    def open_project(
        self,
        project: str,
        *,
        program: str | None = None,
        timeout: int = 180,
        base_port: int = DEFAULT_PORT,
    ) -> list[str]:
        if timeout <= 0:
            raise ManagerError("Timeout must be a positive integer")
        pair = self._require_active_pair()
        self._require_mcp(pair)
        project_path = self._resolve_project(project)
        baseline = self.instance_discovery(base_port)
        active = next((item for item in baseline if item.project == project_path.stem), None)
        if active:
            raise ManagerError(
                f"Project is already active in a GhidraMCP instance: {project_path.stem} "
                f"on port {active.port}"
            )
        java_home = find_java21()
        install = self.paths.ghidra / pair.ghidra_version
        stamp = time.strftime("%Y%m%d-%H%M%S")
        log_path = self.paths.home / "launch-logs" / f"{stamp}-open-{project_path.stem}.log"
        process = start_ghidra_instance(install, project_path, java_home, log_path)
        lines = [
            f"Opening {project_path} with Ghidra {pair.ghidra_version} and JDK 21...",
            f"Launcher PID {process.pid} | log {log_path}",
            f"Waiting up to {timeout} seconds for project {project_path.stem} "
            f"on ports {base_port}-{base_port + 15}...",
        ]
        time.sleep(1)
        self._require_running_launch(process, log_path)
        baseline_pids = {instance.pid for instance in baseline}
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            scanned = self.instance_discovery(base_port)
            match = next(
                (
                    item
                    for item in scanned
                    if item.pid not in baseline_pids
                    and item.project == project_path.stem
                    and (program is None or program in item.programs)
                ),
                None,
            )
            if match:
                lines.append("GhidraMCP instance ready:")
                lines.extend(self._instance_lines([match]))
                if match.programs:
                    lines.append(f"Open programs: {', '.join(match.programs)}")
                return lines
            self._require_running_launch(process, log_path)
            time.sleep(2)
        expectation = f" with program {program}" if program else ""
        raise ManagerError(
            f"No new GhidraMCP endpoint reported project {project_path.stem}{expectation} "
            f"within {timeout} seconds. Open CodeBrowser, enable GhidraMCP, and inspect "
            f"{log_path}."
        )

    def launch(self, arguments: list[str]) -> tuple[str, int]:
        store = StateStore(self.paths)
        state = store.load()
        if state.current is None:
            raise ManagerError("No active pair. Run ghidra-manager sync first.")
        pair = store.pair(state.current)
        java_home = find_java21()
        message = f"Launching Ghidra {pair.ghidra_version} with JDK 21..."
        return message, run_ghidra(self.paths.ghidra / pair.ghidra_version, arguments, java_home)

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
        self._require_mcp(pair)
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
        pair = self._require_active_pair()
        mcp = self._require_mcp(pair)
        bridge_name = mcp.runtime_file("bridge")
        if not bridge_name:
            raise ManagerError("Active MCP plugin has no bridge metadata")
        bridge_path = self.paths.home / bridge_name
        if not bridge_path.is_file():
            raise ManagerError("Active MCP bridge is missing. Reinstall the mcp plugin.")
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

    def _resolve_project(self, value: str) -> Path:
        candidate = Path(value)
        if candidate.suffix or candidate.is_absolute() or candidate.parent != Path("."):
            return self._normalize_project(value)
        _, _, recorded, _ = self._project_registry()
        matches = [Path(base).with_suffix(".gpr") for base in recorded if Path(base).name == value]
        if not matches:
            raise ManagerError(
                f"No recorded Ghidra project has name: {value}. Run ghidra-manager projects."
            )
        if len(matches) > 1:
            paths = ", ".join(str(path) for path in matches)
            raise ManagerError(f"Recorded Ghidra project name is ambiguous: {value}: {paths}")
        return self._normalize_project(str(matches[0]))

    @staticmethod
    def _require_running_launch(process: subprocess.Popen[bytes], log_path: Path) -> None:
        if process.poll() is None:
            return
        detail = log_path.read_text(encoding="utf-8", errors="replace")[:4000]
        raise ManagerError(f"Ghidra exited during startup; see {log_path}\n{detail}")

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
        source_root = roots[0]
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
        for name, relative in definition.runtime_files:
            runtime_source = source_root / relative
            if not runtime_source.is_file():
                raise ManagerError(
                    f"Plugin source is missing runtime file: {definition.plugin_id} {relative}"
                )
            runtime_target = stage / "runtime" / Path(relative).name
            runtime_target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(runtime_source, runtime_target)
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
