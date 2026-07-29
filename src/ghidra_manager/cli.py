"""Command-line interface for Ghidra Manager."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import deque
from collections.abc import Sequence
from pathlib import Path

from ghidra_manager import __version__
from ghidra_manager.errors import ManagerError
from ghidra_manager.instance_state import InstanceReport
from ghidra_manager.manager import Manager
from ghidra_manager.mcp import DEFAULT_PORT, PORT_RANGE


def _base_port(value: str) -> int:
    try:
        return int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("base port must be an integer") from exc


def _nonnegative_int(value: str) -> int:
    try:
        result = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("value must be an integer") from exc
    if result < 0:
        raise argparse.ArgumentTypeError("value must not be negative")
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ghidra-manager",
        description="Manage compatible Ghidra and GhidraMCP releases.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("help", help="Show this help")
    sync = commands.add_parser("sync", help="Install or update the newest compatible stable pair")
    sync.add_argument(
        "--dry-run", action="store_true", help="resolve without changing managed state"
    )
    commands.add_parser("status", help="Show installed and upstream versions")
    doctor = commands.add_parser("doctor", help="Check local reverse-engineering readiness")
    doctor.add_argument("project", nargs="?")
    doctor.add_argument("--program")
    doctor.add_argument("--json", action="store_true")
    doctor.add_argument(
        "--base-port",
        type=_base_port,
        default=int(os.environ.get("GHIDRA_MCP_BASE_PORT", DEFAULT_PORT)),
    )
    commands.add_parser("rollback", help="Swap to the previously active compatible pair")
    commands.add_parser("projects", help="List projects recorded by the active Ghidra version")
    plugins = commands.add_parser("plugins", help="Discover and manage Ghidra plugins")
    plugin_commands = plugins.add_subparsers(dest="plugin_command", required=True)
    plugin_discover = plugin_commands.add_parser(
        "discover", help="List plugins in the bundled registry"
    )
    plugin_discover.add_argument("--json", action="store_true")
    plugin_list = plugin_commands.add_parser("list", help="List active managed plugins")
    plugin_list.add_argument("--json", action="store_true")
    plugin_install = plugin_commands.add_parser(
        "install", help="Build and install a plugin for the active Ghidra"
    )
    plugin_install.add_argument("plugin")
    plugin_remove = plugin_commands.add_parser(
        "remove", help="Remove a plugin from the active Ghidra"
    )
    plugin_remove.add_argument("plugin")
    open_project = commands.add_parser(
        "open", help="Open one or more Ghidra projects and wait for their MCP endpoints"
    )
    open_project.add_argument("projects", nargs="+")
    open_project.add_argument("--program")
    open_project.add_argument(
        "--timeout",
        type=int,
        default=int(os.environ.get("GHIDRA_MCP_LAUNCH_TIMEOUT", "180")),
    )
    open_project.add_argument(
        "--base-port",
        type=_base_port,
        default=int(os.environ.get("GHIDRA_MCP_BASE_PORT", DEFAULT_PORT)),
    )
    stop = commands.add_parser(
        "stop", help="Stop one responding Ghidra instance by project name or PID"
    )
    stop.add_argument("target")
    stop.add_argument("--timeout", type=int, default=10)
    stop.add_argument("--force", action="store_true")
    stop.add_argument(
        "--base-port",
        type=_base_port,
        default=int(os.environ.get("GHIDRA_MCP_BASE_PORT", DEFAULT_PORT)),
    )
    restart = commands.add_parser(
        "restart", help="Restart one responding Ghidra instance by project name or PID"
    )
    restart.add_argument("target")
    restart.add_argument("--program")
    restart.add_argument(
        "--timeout",
        type=int,
        default=int(os.environ.get("GHIDRA_MCP_LAUNCH_TIMEOUT", "180")),
    )
    restart.add_argument("--stop-timeout", type=int, default=10)
    restart.add_argument("--force", action="store_true")
    restart.add_argument(
        "--base-port",
        type=_base_port,
        default=int(os.environ.get("GHIDRA_MCP_BASE_PORT", DEFAULT_PORT)),
    )
    launch = commands.add_parser(
        "launch",
        help="Pass arguments directly to Ghidra without project resolution or readiness checks",
        add_help=False,
    )
    launch.add_argument("arguments", nargs=argparse.REMAINDER)
    launch_multi = commands.add_parser(
        "launch-multi",
        help=argparse.SUPPRESS,
    )
    launch_multi.add_argument("--count", type=int)
    launch_multi.add_argument(
        "--timeout",
        type=int,
        default=int(os.environ.get("GHIDRA_MCP_LAUNCH_TIMEOUT", "180")),
    )
    launch_multi.add_argument(
        "--base-port",
        type=_base_port,
        default=int(os.environ.get("GHIDRA_MCP_BASE_PORT", DEFAULT_PORT)),
    )
    launch_multi.add_argument("projects", nargs="*")
    bridge = commands.add_parser(
        "bridge", help="Run the active GhidraMCP stdio bridge", add_help=False
    )
    bridge.add_argument("arguments", nargs=argparse.REMAINDER)
    compare = commands.add_parser(
        "compare", help="Compare two MCP instances or apply a retained plan"
    )
    compare.add_argument("--base-port", type=_base_port)
    compare.add_argument("--apply", type=str)
    compare.add_argument("projects", nargs="*")
    instances = commands.add_parser(
        "instances", help="List active GhidraMCP instances and TCP ports"
    )
    instances.add_argument("--json", action="store_true")
    instances.add_argument(
        "--base-port",
        type=_base_port,
        default=int(os.environ.get("GHIDRA_MCP_BASE_PORT", DEFAULT_PORT)),
        help=f"configured GhidraMCP TCP port (default: {DEFAULT_PORT})",
    )
    logs = commands.add_parser("logs", help="Show a retained managed-instance launch log")
    logs.add_argument("target", nargs="?")
    logs.add_argument("--lines", type=_nonnegative_int, default=200)
    logs.add_argument("--follow", action="store_true")
    return parser


def _instances(base_port: int, *, as_json: bool = False) -> int:
    reports = Manager.discover().instance_reports(base_port)
    if as_json:
        print(json.dumps({"instances": [report.as_dict() for report in reports]}, indent=2))
        return 0 if reports else 1
    if not reports:
        print(f"No GhidraMCP instances found on ports {base_port}-{base_port + PORT_RANGE - 1}.")
        return 1
    for report in reports:
        print(_instance_line(report))
    return 0


def _instance_line(report: InstanceReport) -> str:
    ownership = "managed" if report.owned else "external"
    programs = ", ".join(report.programs) if report.programs else "-"
    endpoint = f"MCP port {report.port}" if report.url else f"last MCP port {report.port}"
    line = (
        f"{report.health.upper():15} | {ownership:8} | {endpoint} | PID {report.pid} | "
        f"project {report.project} | programs {programs}"
    )
    return f"{line} | log {report.log_path}" if report.log_path else line


def _logs(target: str | None, *, lines: int, follow: bool) -> int:
    path = Manager.discover().instance_log(target)
    print(f"Log: {path}")
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in deque(handle, maxlen=lines):
            print(line, end="" if line.endswith("\n") else "\n")
        if not follow:
            return 0
        try:
            while True:
                position = handle.tell()
                line = handle.readline()
                if line:
                    print(line, end="" if line.endswith("\n") else "\n", flush=True)
                    continue
                if path.stat().st_size < position:
                    handle.seek(0)
                time.sleep(0.25)
        except KeyboardInterrupt:
            return 0


def run(argv: Sequence[str] | None = None) -> int:
    values = list(argv if argv is not None else sys.argv[1:])
    if not values:
        values = ["help"]
    if values and values[0] in {"launch", "bridge"}:
        args = build_parser().parse_args([values[0]])
        args.arguments = values[1:]
    else:
        args = build_parser().parse_args(values)
    if args.command == "sync":
        for line in Manager.discover().sync(dry_run=args.dry_run):
            print(line)
        return 0
    if args.command == "help":
        build_parser().print_help()
        return 0
    if args.command == "status":
        for line in Manager.discover().status_lines():
            print(line)
        return 0
    if args.command == "doctor":
        checks = Manager.discover().doctor(
            args.project, program=args.program, base_port=args.base_port
        )
        ready = not any(check.level == "error" for check in checks)
        if args.json:
            print(
                json.dumps(
                    {
                        "ready": ready,
                        "checks": [
                            {
                                "name": check.name,
                                "level": check.level,
                                "detail": check.detail,
                            }
                            for check in checks
                        ],
                    },
                    indent=2,
                )
            )
        else:
            for check in checks:
                print(f"{check.level.upper():7} {check.name}: {check.detail}")
            doctor_result = "ready" if ready else "not ready"
            print(f"Doctor result: {doctor_result}")
        return 0 if ready else 1
    if args.command == "rollback":
        for line in Manager.discover().rollback():
            print(line)
        return 0
    if args.command == "projects":
        base_port = int(os.environ.get("GHIDRA_MCP_BASE_PORT", DEFAULT_PORT))
        for line in Manager.discover().projects(base_port=base_port):
            print(line)
        return 0
    if args.command == "plugins":
        if args.plugin_command == "discover":
            catalog_entries = Manager.discover().plugin_discovery()
            if args.json:
                print(json.dumps({"plugins": catalog_entries}, indent=2))
            else:
                for entry in catalog_entries:
                    selection_state = "selected" if entry["selected"] else "available"
                    print(
                        f"{entry['id']} | {entry['name']} | {selection_state} | "
                        f"{entry['repository']}"
                    )
            return 0
        if args.plugin_command == "list":
            list_result = Manager.discover().plugin_list()
            if args.json:
                print(json.dumps(list_result, indent=2))
            elif list_result["ghidra_version"] is None:
                print("No active Ghidra installation.")
            else:
                print(f"Plugins for Ghidra {list_result['ghidra_version']}:")
                active_plugins = list_result["plugins"]
                assert isinstance(active_plugins, list)
                if not active_plugins:
                    print("none")
                for item in active_plugins:
                    assert isinstance(item, dict)
                    print(f"{item['id']} | {item['version']} | {item['tag']} | {item['commit']}")
            return 0
        if args.plugin_command == "install":
            for line in Manager.discover().plugin_install(args.plugin):
                print(line)
            return 0
        if args.plugin_command == "remove":
            for line in Manager.discover().plugin_remove(args.plugin):
                print(line)
            return 0
        raise AssertionError(f"Unhandled plugin command: {args.plugin_command}")
    if args.command == "open":
        for line in Manager.discover().open_projects(
            args.projects,
            program=args.program,
            timeout=args.timeout,
            base_port=args.base_port,
        ):
            print(line)
        return 0
    if args.command == "stop":
        for line in Manager.discover().stop_instance(
            args.target,
            timeout=args.timeout,
            force=args.force,
            base_port=args.base_port,
        ):
            print(line)
        return 0
    if args.command == "restart":
        for line in Manager.discover().restart_instance(
            args.target,
            program=args.program,
            timeout=args.timeout,
            stop_timeout=args.stop_timeout,
            force=args.force,
            base_port=args.base_port,
        ):
            print(line)
        return 0
    if args.command == "launch":
        message, returncode = Manager.discover().launch(args.arguments)
        print(message)
        return returncode
    if args.command == "launch-multi":
        print(
            "WARNING: launch-multi is retained for compatibility; use open PROJECT [PROJECT ...].",
            file=sys.stderr,
        )
        for line in Manager.discover().launch_multi(
            args.projects,
            count=args.count,
            timeout=args.timeout,
            base_port=args.base_port,
        ):
            print(line)
        return 0
    if args.command == "bridge":
        return Manager.discover().bridge(args.arguments)
    if args.command == "compare":
        manager = Manager.discover()
        if args.apply:
            if args.projects or args.base_port is not None:
                build_parser().error("compare --apply requires one plan path")
            return manager.compare_apply(Path(args.apply))
        if len(args.projects) != 2:
            build_parser().error("compare requires SOURCE_PROJECT and TARGET_PROJECT")
        base_port = args.base_port or int(os.environ.get("GHIDRA_MCP_BASE_PORT", DEFAULT_PORT))
        return manager.compare(args.projects[0], args.projects[1], base_port=base_port)
    if args.command == "instances":
        return _instances(args.base_port, as_json=args.json)
    if args.command == "logs":
        return _logs(args.target, lines=args.lines, follow=args.follow)
    raise AssertionError(f"Unhandled command: {args.command}")


def main() -> None:
    try:
        raise SystemExit(run())
    except ManagerError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
