"""Ghidra project, process, MCP instance, and bridge lifecycle operations."""

from __future__ import annotations

import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from ghidra_manager.config import ManagerPaths
from ghidra_manager.errors import ManagerError
from ghidra_manager.instance_state import (
    InstanceHealth,
    InstanceReport,
    InstanceStore,
    ManagedInstanceRecord,
)
from ghidra_manager.mcp import DEFAULT_PORT, Instance, discover_instances
from ghidra_manager.models import PairMetadata, PluginMetadata
from ghidra_manager.platforms import (
    find_java21,
    ghidra_settings_dir,
    run_bridge,
    run_ghidra,
    start_ghidra_instance,
)
from ghidra_manager.processes import managed_ghidra_process, stop_managed_ghidra
from ghidra_manager.storage import StateStore, read_properties


@dataclass(slots=True)
class InstanceService:
    paths: ManagerPaths
    instance_discovery: Callable[[int], list[Instance]] = discover_instances

    def projects(self, *, base_port: int = DEFAULT_PORT) -> list[str]:
        pair, preferences, recorded, last_opened = self.project_registry()
        active = {instance.project: instance for instance in self.instance_discovery(base_port)}
        lines = [f"Projects known to Ghidra {pair.ghidra_version}:"]
        for base in recorded:
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
                f"{base_path.name} | {storage} | {last_status} | {active_status} | "
                f"{project_file}"
            )
        lines.append(f"{len(recorded)} recorded projects from {preferences}")
        return lines

    def project_registry(self) -> tuple[PairMetadata, Path, list[str], str]:
        pair = self.require_active_pair()
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
        pair = self.require_active_pair()
        self.require_mcp_plugin(pair)
        project_path = self.resolve_project(project)
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
        started_at = int(time.time())
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
                InstanceStore(self.paths).upsert(
                    ManagedInstanceRecord(
                        pid=match.pid,
                        launcher_pid=process.pid,
                        port=match.port,
                        project=match.project,
                        project_path=str(project_path),
                        log_path=str(log_path),
                        ghidra_version=pair.ghidra_version,
                        started_at=started_at,
                    )
                )
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

    def open_projects(
        self,
        projects: list[str],
        *,
        program: str | None = None,
        timeout: int = 180,
        base_port: int = DEFAULT_PORT,
    ) -> list[str]:
        if not projects:
            raise ManagerError("Open requires at least one project")
        if len(projects) == 1:
            return self.open_project(
                projects[0],
                program=program,
                timeout=timeout,
                base_port=base_port,
            )
        if program is not None:
            raise ManagerError("--program can only be used when opening one project")
        return self.launch_multi(projects, timeout=timeout, base_port=base_port)

    def stop_instance(
        self,
        target: str,
        *,
        timeout: int = 10,
        force: bool = False,
        base_port: int = DEFAULT_PORT,
    ) -> list[str]:
        pair = self.require_active_pair()
        self.require_mcp_plugin(pair)
        instance = self._resolve_instance_target(target, self.instance_discovery(base_port))
        self._require_owned_instance(instance)
        install = self.paths.ghidra / pair.ghidra_version
        stop_managed_ghidra(instance.pid, install, timeout=timeout, force=force)
        return [f"Stopped Ghidra PID {instance.pid} for project {instance.project}."]

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
        pair = self.require_active_pair()
        self.require_mcp_plugin(pair)
        instance = self._resolve_instance_target(target, self.instance_discovery(base_port))
        record = self._require_owned_instance(instance)
        project_path = (
            self._normalize_project(record.project_path)
            if record.project_path is not None
            else self.resolve_project(instance.project)
        )
        install = self.paths.ghidra / pair.ghidra_version
        stop_managed_ghidra(instance.pid, install, timeout=stop_timeout, force=force)
        lines = [f"Stopped Ghidra PID {instance.pid} for project {instance.project}."]
        lines.extend(
            self.open_project(
                str(project_path),
                program=program,
                timeout=timeout,
                base_port=base_port,
            )
        )
        return lines

    def instance_reports(self, base_port: int = DEFAULT_PORT) -> list[InstanceReport]:
        self.require_mcp_plugin(self.require_active_pair())
        live = self.instance_discovery(base_port)
        records = InstanceStore(self.paths).load()
        records_by_pid = {record.pid: record for record in records}
        reports: list[InstanceReport] = []
        live_pids: set[int] = set()
        for instance in live:
            live_pids.add(instance.pid)
            record = records_by_pid.get(instance.pid)
            owned = (
                record is not None
                and record.project == instance.project
                and managed_ghidra_process(
                    instance.pid, self.paths.ghidra / record.ghidra_version
                )
            )
            reports.append(
                self._instance_report(
                    instance.pid,
                    instance.port,
                    instance.project,
                    instance.programs,
                    instance.url,
                    "ready",
                    record if owned else None,
                )
            )
        for record in records:
            if record.pid in live_pids:
                continue
            running = managed_ghidra_process(
                record.pid, self.paths.ghidra / record.ghidra_version
            )
            reports.append(
                self._instance_report(
                    record.pid,
                    record.port,
                    record.project,
                    (),
                    None,
                    "mcp-unavailable" if running else "stale",
                    record,
                )
            )
        return sorted(reports, key=lambda report: (report.port, report.pid))

    def instance_log(self, target: str | None = None) -> Path:
        records = InstanceStore(self.paths).load()
        if target is None:
            matches = records
            description = "managed instance"
        elif target.isdecimal():
            matches = [record for record in records if record.pid == int(target)]
            description = f"managed PID {target}"
        else:
            matches = [record for record in records if record.project == target]
            description = f"managed project {target}"
        if not matches:
            raise ManagerError(f"No retained launch log found for {description}")
        record = max(matches, key=lambda item: (item.started_at, item.pid))
        log_root = (self.paths.home / "launch-logs").resolve()
        log_path = Path(record.log_path).resolve()
        if log_path == log_root or log_root not in log_path.parents:
            raise ManagerError(f"Retained launch log escapes manager state: {record.log_path}")
        if not log_path.is_file():
            raise ManagerError(f"Retained launch log is missing: {log_path}")
        return log_path

    def launch(self, arguments: list[str]) -> tuple[str, int]:
        pair = self.require_active_pair()
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
        normalized = [self.resolve_project(path) for path in projects]
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
        pair = self.require_active_pair()
        self.require_mcp_plugin(pair)
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
        launches: list[tuple[Path | None, int, Path, int]] = []
        for index in range(instance_count):
            project = normalized[index] if normalized else None
            description = str(project) if project else "restore/select a distinct project"
            lines.append(f"  Instance {index + 1}: {description}")
            log_path = log_dir / f"{stamp}-{index + 1}.log"
            process = start_ghidra_instance(install, project, java_home, log_path)
            launches.append((project, process.pid, log_path, int(time.time())))
            time.sleep(1)
            self._require_running_launch(process, log_path)
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
                self._record_launched_instances(new_instances, launches, pair.ghidra_version)
                lines.append("GhidraMCP instances ready:")
                lines.extend(self._instance_lines(new_instances))
                return lines
            time.sleep(2)
        if new_instances:
            self._record_launched_instances(new_instances, launches, pair.ghidra_version)
            lines.append("New MCP endpoints detected before timeout:")
            lines.extend(self._instance_lines(new_instances))
        raise ManagerError(
            f"Detected {len(new_instances)} of {instance_count} new MCP endpoints. "
            "Open CodeBrowser in each new project, enable GhidraMCP, and run instances "
            "to inspect ports."
        )

    def bridge(self, arguments: list[str]) -> int:
        pair = self.require_active_pair()
        mcp = self.require_mcp_plugin(pair)
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

    def require_active_pair(self) -> PairMetadata:
        store = StateStore(self.paths)
        state = store.load()
        if state.current is None:
            raise ManagerError("No active pair. Run ghidra-manager sync first.")
        return store.pair(state.current)

    @staticmethod
    def require_mcp_plugin(pair: PairMetadata) -> PluginMetadata:
        plugin = pair.plugin("mcp")
        if plugin is None:
            raise ManagerError(
                "MCP plugin is not installed. Run ghidra-manager plugins install mcp."
            )
        return plugin

    @staticmethod
    def resolve_instance(project: str, instances: list[Instance]) -> Instance:
        matches = [item for item in instances if item.project == project]
        if not matches:
            raise ManagerError(f"No responding GhidraMCP instance has project name: {project}")
        if len(matches) != 1:
            raise ManagerError(f"Multiple responding instances have project name: {project}")
        return matches[0]

    def resolve_project(self, value: str) -> Path:
        candidate = Path(value)
        if candidate.suffix or candidate.is_absolute() or candidate.parent != Path("."):
            return self._normalize_project(value)
        _, _, recorded, _ = self.project_registry()
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
    def _resolve_instance_target(target: str, instances: list[Instance]) -> Instance:
        if target.isdecimal():
            pid = int(target)
            matches = [item for item in instances if item.pid == pid]
            description = f"PID {pid}"
        else:
            matches = [item for item in instances if item.project == target]
            description = f"project name: {target}"
        if not matches:
            raise ManagerError(f"No responding GhidraMCP instance has {description}")
        if len(matches) != 1:
            raise ManagerError(f"Multiple responding GhidraMCP instances have {description}")
        return matches[0]

    def _require_owned_instance(self, instance: Instance) -> ManagedInstanceRecord:
        record = InstanceStore(self.paths).get(instance.pid)
        if record is None or record.project != instance.project:
            raise ManagerError(
                f"Refusing to manage untracked PID {instance.pid}; use an instance launched "
                "by ghidra-manager open"
            )
        return record

    def _record_launched_instances(
        self,
        instances: list[Instance],
        launches: list[tuple[Path | None, int, Path, int]],
        ghidra_version: str,
    ) -> None:
        remaining = list(launches)
        store = InstanceStore(self.paths)
        for instance in sorted(instances):
            match_index = next(
                (
                    index
                    for index, (project, *_rest) in enumerate(remaining)
                    if project is not None and project.stem == instance.project
                ),
                0 if remaining else None,
            )
            if match_index is None:
                continue
            project, launcher_pid, log_path, started_at = remaining.pop(match_index)
            store.upsert(
                ManagedInstanceRecord(
                    pid=instance.pid,
                    launcher_pid=launcher_pid,
                    port=instance.port,
                    project=instance.project,
                    project_path=str(project) if project is not None else None,
                    log_path=str(log_path),
                    ghidra_version=ghidra_version,
                    started_at=started_at,
                )
            )

    @staticmethod
    def _instance_report(
        pid: int,
        port: int,
        project: str,
        programs: tuple[str, ...],
        url: str | None,
        health: InstanceHealth,
        record: ManagedInstanceRecord | None,
    ) -> InstanceReport:
        return InstanceReport(
            pid=pid,
            port=port,
            project=project,
            programs=programs,
            url=url,
            owned=record is not None,
            health=health,
            launcher_pid=record.launcher_pid if record else None,
            project_path=record.project_path if record else None,
            log_path=record.log_path if record else None,
            ghidra_version=record.ghidra_version if record else None,
            started_at=record.started_at if record else None,
        )

    @staticmethod
    def _require_running_launch(process: subprocess.Popen[bytes], log_path: Path) -> None:
        if process.poll() is None:
            return
        detail = log_path.read_text(encoding="utf-8", errors="replace")[:4000]
        raise ManagerError(f"Ghidra exited during startup; see {log_path}\n{detail}")

    @staticmethod
    def _normalize_project(value: str | None) -> Path:
        if value is None:
            raise ManagerError("Managed instance has no retained project path")
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
