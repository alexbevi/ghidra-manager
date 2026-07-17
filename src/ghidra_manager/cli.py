"""Command-line interface for Ghidra Manager."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence

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
    commands.add_parser("status", help="Show installed and upstream versions")
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
    args = build_parser().parse_args(argv)
    if args.command == "status":
        for line in Manager.discover().status_lines():
            print(line)
        return 0
    if args.command == "instances":
        return _instances(args.base_port)
    raise AssertionError(f"Unhandled command: {args.command}")


def main() -> None:
    try:
        raise SystemExit(run())
    except ManagerError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
