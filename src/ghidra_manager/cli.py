"""Command-line interface for Ghidra Manager."""

from __future__ import annotations

import argparse
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
    parser = argparse.ArgumentParser(prog="ghidra-manager")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    sync = commands.add_parser("sync", help="Install or update the newest compatible stable pair")
    sync.add_argument(
        "--dry-run", action="store_true", help="resolve without changing managed state"
    )
    commands.add_parser("status", help="Show installed and upstream versions")
    commands.add_parser("rollback", help="Swap to the previously active compatible pair")
    commands.add_parser("projects", help="List projects recorded by the active Ghidra version")
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
        print(
            f"No GhidraMCP instances found on ports {base_port}-{base_port + PORT_RANGE - 1}."
        )
        return 1
    for instance in instances:
        print(
            f"MCP port {instance.port} | PID {instance.pid} | "
            f"project {instance.project} | {instance.url}"
        )
    return 0


def run(argv: Sequence[str] | None = None) -> int:
    values = list(argv if argv is not None else sys.argv[1:])
    if values and values[0] in {"launch", "bridge"}:
        args = build_parser().parse_args([values[0]])
        args.arguments = values[1:]
    else:
        args = build_parser().parse_args(values)
    if args.command == "sync":
        for line in Manager.discover().sync(dry_run=args.dry_run):
            print(line)
        return 0
    if args.command == "status":
        for line in Manager.discover().status_lines():
            print(line)
        return 0
    if args.command == "rollback":
        for line in Manager.discover().rollback():
            print(line)
        return 0
    if args.command == "projects":
        base_port = int(os.environ.get("GHIDRA_MCP_BASE_PORT", DEFAULT_PORT))
        for line in Manager.discover().projects(base_port=base_port):
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
        base_port = args.base_port or int(
            os.environ.get("GHIDRA_MCP_BASE_PORT", DEFAULT_PORT)
        )
        return manager.compare(args.projects[0], args.projects[1], base_port=base_port)
    if args.command == "instances":
        return _instances(args.base_port)
    raise AssertionError(f"Unhandled command: {args.command}")


def main() -> None:
    try:
        raise SystemExit(run())
    except ManagerError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
