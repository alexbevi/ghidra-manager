"""Campaign CLI; offline commands never discover or mutate Ghidra."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from ghidra_manager.campaign import budget, init_project, queue, report_project, validate_project
from ghidra_manager.campaign.diffing import compare
from ghidra_manager.campaign.evidence import packet
from ghidra_manager.campaign.inventory import fingerprint, latest, read, scan
from ghidra_manager.campaign.matching import candidates
from ghidra_manager.campaign.mutations import apply, reconcile
from ghidra_manager.campaign.plans import create
from ghidra_manager.campaign.selftest import run as selftest
from ghidra_manager.campaign.transport import Client
from ghidra_manager.campaign.verification import finalize, verify
from ghidra_manager.errors import ManagerError
from ghidra_manager.storage import atomic_json


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
    for name in ["status", "validate", "report", "self-test"]:
        actions.add_parser(name)
    match_parser = actions.add_parser(
        "match", help="Find reference candidates without changing names"
    )
    match_parser.add_argument("--reference", type=Path, required=True)
    match_parser.add_argument("--provenance", required=True)
    next_parser = actions.add_parser("next", help="Select an admissible bounded task")
    next_parser.add_argument("--queue", choices=["naming", "types", "repair"], default="naming")
    task_parser = actions.add_parser("task")
    task_actions = task_parser.add_subparsers(dest="task_action", required=True)
    for verb in ["add", "start", "fail", "defer", "retry", "complete"]:
        child = task_actions.add_parser(verb)
        child.add_argument("task_id")
        if verb == "add":
            child.add_argument("--queue", choices=["naming", "types", "repair"], default="naming")
            child.add_argument("--address", action="append", dest="addresses", required=True)
            child.add_argument("--depends-on", action="append", default=[])
            child.add_argument("--priority", type=int, default=0)
        if verb in {"fail", "defer", "retry"}:
            child.add_argument("--reason", required=True)
        if verb == "complete":
            child.add_argument("--batch", required=True)
    for verb in ("apply", "reconcile", "verify", "finalize"):
        command = actions.add_parser(verb)
        command.add_argument("--port", type=int, default=8089)
        if verb == "apply":
            command.add_argument("plan", type=Path)
        if verb == "finalize":
            command.add_argument("review", type=Path)
    plan_parser = actions.add_parser("plan", help="Validate and retain a rename proposal")
    plan_parser.add_argument("proposal", type=Path)
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
        if args.campaign_command == "match":
            result = candidates(latest(root), read(args.reference), args.provenance)
            path = root / "artifacts" / "matches" / (fingerprint(result) + ".json")
            path.parent.mkdir(parents=True, exist_ok=True)
            atomic_json(path, result)
            print(json.dumps({"artifact": str(path), "candidates": len(result["matches"])}))
            return 0
        if args.campaign_command == "next":
            print(json.dumps(queue.next_task(root, args.queue)))
            return 0
        if args.campaign_command == "task":
            task_values = {k: v for k, v in vars(args).items() if k != "task_id"}
            print(json.dumps(queue.operate(root, args.task_action, args.task_id, **task_values)))
            return 0
        if args.campaign_command == "self-test":
            print(json.dumps(selftest(root)))
            return 0
        if args.campaign_command == "plan":
            print(json.dumps(create(root, read(args.proposal))))
            return 0
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
        if args.campaign_command in {"verify", "finalize"}:
            client = Client(args.port, project["ghidra"]["program_path"])
            result = (
                verify(root, client)
                if args.campaign_command == "verify"
                else finalize(root, client, read(args.review))
            )
            print(json.dumps(result))
            return 0
        if args.campaign_command in {"apply", "reconcile"}:
            client = Client(args.port, project["ghidra"]["program_path"])
            result = (
                apply(root, client, args.plan)
                if args.campaign_command == "apply"
                else reconcile(root, client)
            )
            print(json.dumps(result))
            return 0
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
