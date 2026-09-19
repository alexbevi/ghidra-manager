"""Campaign CLI; offline commands never discover or mutate Ghidra."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from ghidra_manager.campaign import budget, init_project, report_project, validate_project
from ghidra_manager.campaign.diffing import compare
from ghidra_manager.campaign.evidence import packet
from ghidra_manager.campaign.inventory import read, scan
from ghidra_manager.campaign.transport import Client
from ghidra_manager.errors import ManagerError


def add_parser(commands: Any) -> None:
    parser = commands.add_parser("campaign", help="Manage reverse-engineering campaign evidence")
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--json", action="store_true")
    actions = parser.add_subparsers(dest="campaign_command", required=True)
    init = actions.add_parser("init", help="Initialize an empty campaign directory")
    init.add_argument("--project", required=True)
    init.add_argument("--program", required=True)
    init.add_argument("--program-path", required=True)
    init.add_argument("--goal", default="")
    init.add_argument(
        "--profile", choices=["symbol-recovery", "reimplementation"], default="symbol-recovery"
    )
    init.add_argument("--target", choices=["generic", "scummvm"])
    for name in ["status", "validate", "report"]:
        actions.add_parser(name)
    diff_parser = actions.add_parser("diff", help="Classify retained snapshot changes")
    diff_parser.add_argument("before", type=Path)
    diff_parser.add_argument("after", type=Path)
    packet_parser = actions.add_parser("packet", help="Capture cached, bounded function evidence")
    packet_parser.add_argument("addresses", nargs="+")
    packet_parser.add_argument("--port", type=int, default=8089)
    packet_parser.add_argument("--max-bytes", type=int, default=32768)
    scan_parser = actions.add_parser("scan", help="Capture complete live inventory")
    scan_parser.add_argument("--port", type=int, default=8089)
    admit = actions.add_parser("admit", help="Check budget before starting a batch")
    admit.add_argument(
        "--purpose", choices=["analysis", "verify", "recover", "save"], default="analysis"
    )

    for group, verbs in [
        ("budget", ["show", "set"]),
        ("session", ["start", "finish"]),
        ("usage", ["record"]),
    ]:
        command = actions.add_parser(group)
        children = command.add_subparsers(dest="budget_action", required=True)
        for verb in verbs:
            child = children.add_parser(verb)
            if verb in ("set", "start"):
                child.add_argument("--tokens", type=int, required=verb == "set")
            if verb == "record":
                for field in ("source", "stream", "measurement"):
                    child.add_argument("--" + field, required=True)
                child.add_argument("--counter", required=True, type=int)
                child.add_argument("--scope", action="append", required=True)


def run(args: argparse.Namespace) -> int:
    root = args.state.expanduser().resolve()
    try:
        if args.campaign_command == "init":
            values = [
                "--output",
                str(root),
                "--project",
                args.project,
                "--program",
                args.program,
                "--program-path",
                args.program_path,
                "--goal",
                args.goal,
                "--profile",
                args.profile,
            ]
            if args.target:
                values += ["--target", args.target]
            return init_project.main(values)
        errors = validate_project.validate(root)
        if errors:
            raise ManagerError("Invalid campaign: " + "; ".join(errors))
        if args.campaign_command == "diff":
            print(json.dumps(compare(read(args.before), read(args.after)), sort_keys=True))
            return 0
        if args.campaign_command == "admit":
            result = budget.admission(root, purpose=args.purpose)
            print(json.dumps(result, sort_keys=True))
            return 0 if result["admitted"] else 3
        if args.campaign_command in ("budget", "session", "usage"):
            result = budget.operate(root, args.budget_action, **vars(args))
            print(json.dumps(result, sort_keys=True))
            return 0
        project = validate_project.load_json(root / "project.json")
        if args.campaign_command == "packet":
            print(
                json.dumps(
                    packet(
                        root,
                        Client(args.port, project["ghidra"]["program_path"]),
                        args.addresses,
                        args.max_bytes,
                    )
                )
            )
            return 0
        if args.campaign_command == "scan":
            print(json.dumps(scan(root, Client(args.port, project["ghidra"]["program_path"]))))
            return 0
        progress = validate_project.load_json(root / "progress.json")
        if args.campaign_command == "report":
            report = report_project.render(root)
            print(json.dumps({"report": report}) if args.json else report, end="\n")
        else:
            result = {
                "valid": True,
                "state": str(root),
                "identity": project["ghidra"],
                "goal": project["goal_objective"],
                "phase": progress.get("phase"),
                "current": progress.get("current", {}),
                "active_mutation_lease": progress.get("active_mutation_lease"),
            }
            print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError) as exc:
        raise ManagerError(f"Campaign operation failed: {exc}") from exc
