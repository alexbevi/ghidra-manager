"""Campaign CLI; offline commands never discover or mutate Ghidra."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from ghidra_manager.campaign import init_project, report_project, validate_project
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
    init.add_argument("--profile", choices=["symbol-recovery", "reimplementation"],
                      default="symbol-recovery")
    init.add_argument("--target", choices=["generic", "scummvm"])
    for name in ["status", "validate", "report"]:
        actions.add_parser(name)


def run(args: argparse.Namespace) -> int:
    root = args.state.expanduser().resolve()
    try:
        if args.campaign_command == "init":
            values = ["--output", str(root), "--project", args.project,
                      "--program", args.program, "--program-path", args.program_path,
                      "--goal", args.goal, "--profile", args.profile]
            if args.target:
                values += ["--target", args.target]
            return init_project.main(values)
        errors = validate_project.validate(root)
        if errors:
            raise ManagerError("Invalid campaign: " + "; ".join(errors))
        project = validate_project.load_json(root / "project.json")
        progress = validate_project.load_json(root / "progress.json")
        if args.campaign_command == "report":
            report = report_project.render(root)
            print(json.dumps({"report": report}) if args.json else report, end="\n")
        else:
            result = {"valid": True, "state": str(root), "identity": project["ghidra"],
                      "goal": project["goal_objective"], "phase": progress.get("phase"),
                      "current": progress.get("current", {}),
                      "active_mutation_lease": progress.get("active_mutation_lease")}
            print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError) as exc:
        raise ManagerError(f"Campaign operation failed: {exc}") from exc
