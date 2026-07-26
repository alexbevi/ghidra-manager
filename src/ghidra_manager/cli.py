"""Command-line interface for Ghidra Manager."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from ghidra_manager import __version__
from ghidra_manager.errors import ManagerError
from ghidra_manager.manager import Manager
from ghidra_manager.mcp import DEFAULT_PORT, PORT_RANGE, discover_instances


def _base_port(value: str) -> int:
    try:
        return int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("base port must be an integer") from exc


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
        "open", help="Open a recorded Ghidra project and wait for its MCP endpoint"
    )
    open_project.add_argument("project")
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
    launch = commands.add_parser(
        "launch", help="Launch one active Ghidra with JDK 21", add_help=False
    )
    launch.add_argument("arguments", nargs=argparse.REMAINDER)
    launch_multi = commands.add_parser(
        "launch-multi", help="Launch multiple Ghidra projects and report their MCP ports"
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
    coverage = commands.add_parser(
        "coverage", help="Track reimplementation evidence and reviewed coverage"
    )
    coverage_commands = coverage.add_subparsers(dest="coverage_command", required=True)
    coverage_init = coverage_commands.add_parser(
        "init", help="Create an ignored coverage workspace"
    )
    coverage_init.add_argument("--repository", type=Path, default=Path.cwd())
    coverage_init.add_argument("--profile", type=Path)
    coverage_init.add_argument("--adapter", required=True)
    coverage_init.add_argument("--project", required=True)
    coverage_init.add_argument("--program", required=True)
    coverage_init.add_argument("--scope", required=True)
    coverage_init.add_argument("--architecture")
    coverage_init.add_argument(
        "--base-port",
        type=_base_port,
        default=int(os.environ.get("GHIDRA_MCP_BASE_PORT", DEFAULT_PORT)),
    )
    coverage_scan = coverage_commands.add_parser(
        "scan", help="Create a retained evidence scan plan"
    )
    coverage_scan.add_argument(
        "--profile", type=Path, default=Path("reports/coverage/profile.json")
    )
    coverage_scan.add_argument("--offline-snapshot")
    coverage_scan.add_argument("--allow-dirty", action="store_true")
    coverage_validate = coverage_commands.add_parser(
        "validate", help="Validate coverage inputs"
    )
    coverage_validate.add_argument(
        "--profile", type=Path, default=Path("reports/coverage/profile.json")
    )
    coverage_report = coverage_commands.add_parser(
        "report", help="Generate deterministic JSON and Markdown reports"
    )
    coverage_report.add_argument(
        "--profile", type=Path, default=Path("reports/coverage/profile.json")
    )
    coverage_report.add_argument("--json", type=Path)
    coverage_report.add_argument("--markdown", type=Path)
    coverage_diff = coverage_commands.add_parser(
        "diff", help="Compare two canonical coverage reports"
    )
    coverage_diff.add_argument("base", type=Path)
    coverage_diff.add_argument("head", type=Path)
    coverage_diff.add_argument("--json", type=Path, required=True)
    coverage_diff.add_argument("--markdown", type=Path, required=True)
    coverage_plans = coverage_commands.add_parser(
        "plans", help="List retained coverage plans"
    )
    coverage_plans.add_argument(
        "--profile", type=Path, default=Path("reports/coverage/profile.json")
    )
    coverage_apply = coverage_commands.add_parser(
        "apply", help="Apply a retained coverage plan"
    )
    coverage_apply.add_argument("plan", type=Path)
    instances = commands.add_parser(
        "instances", help="List active GhidraMCP instances and TCP ports"
    )
    instances.add_argument(
        "--base-port",
        type=_base_port,
        default=int(os.environ.get("GHIDRA_MCP_BASE_PORT", DEFAULT_PORT)),
        help=f"configured GhidraMCP TCP port (default: {DEFAULT_PORT})",
    )
    return parser


def _instances(base_port: int) -> int:
    instances = discover_instances(base_port)
    if not instances:
        print(f"No GhidraMCP instances found on ports {base_port}-{base_port + PORT_RANGE - 1}.")
        return 1
    for instance in instances:
        print(
            f"MCP port {instance.port} | PID {instance.pid} | "
            f"project {instance.project} | {instance.url}"
        )
    return 0


def run(argv: Sequence[str] | None = None) -> int:
    values = list(argv if argv is not None else sys.argv[1:])
    if not values:
        values = ["sync"]
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
        for line in Manager.discover().open_project(
            args.project,
            program=args.program,
            timeout=args.timeout,
            base_port=args.base_port,
        ):
            print(line)
        return 0
    if args.command == "launch":
        message, returncode = Manager.discover().launch(args.arguments)
        print(message)
        return returncode
    if args.command == "launch-multi":
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
    if args.command == "coverage":
        service = Manager.discover().coverage_service()
        if args.coverage_command == "init":
            architecture = args.architecture
            if architecture is None and args.adapter == "scummvm":
                architecture = "RIPPER-ARCHITECTURE.md"
            profile = service.init(
                repository=args.repository,
                profile_path=args.profile,
                adapter=args.adapter,
                project=args.project,
                program=args.program,
                scope=args.scope,
                architecture=architecture,
                base_port=args.base_port,
            )
            print(f"Coverage workspace initialized: {profile.parent}")
            print(f"Profile: {profile}")
            return 0
        if args.coverage_command == "scan":
            plan = service.scan(
                args.profile,
                offline_snapshot=args.offline_snapshot,
                allow_dirty=args.allow_dirty,
            )
            print(f"Coverage plan saved: {plan}")
            print("No canonical inputs changed. Review the plan, then apply it with:")
            print(f"  ghidra-manager coverage apply {plan}")
            return 0
        if args.coverage_command == "validate":
            errors = service.validate(args.profile)
            if errors:
                for error in errors:
                    print(f"ERROR: {error}")
                return 1
            print(f"Coverage inputs valid: {args.profile}")
            return 0
        if args.coverage_command == "report":
            json_path, markdown_path = service.report(
                args.profile,
                json_path=args.json,
                markdown_path=args.markdown,
            )
            print(f"Coverage JSON: {json_path}")
            print(f"Coverage Markdown: {markdown_path}")
            return 0
        if args.coverage_command == "diff":
            json_path, markdown_path = service.diff(
                args.base,
                args.head,
                json_path=args.json,
                markdown_path=args.markdown,
            )
            print(f"Coverage diff JSON: {json_path}")
            print(f"Coverage diff Markdown: {markdown_path}")
            return 0
        if args.coverage_command == "plans":
            plans = service.plans(args.profile)
            if not plans:
                print("No retained coverage plans.")
            for plan_record in plans:
                state = "current" if plan_record.get("current") else "stale"
                print(
                    f"{state} | {plan_record['path']} | "
                    f"{plan_record.get('plan_id', 'invalid')}"
                )
            return 0
        if args.coverage_command == "apply":
            for line in service.apply(args.plan):
                print(line)
            return 0
        raise AssertionError(f"Unhandled coverage command: {args.coverage_command}")
    if args.command == "instances":
        Manager.discover().require_mcp()
        return _instances(args.base_port)
    raise AssertionError(f"Unhandled command: {args.command}")


def main() -> None:
    try:
        raise SystemExit(run())
    except ManagerError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
