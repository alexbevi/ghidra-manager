"""Bounded deterministic queues; difficult tasks stay deferred, not forgotten."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ghidra_manager.campaign.budget import locked, require_admission, timestamp
from ghidra_manager.campaign.inventory import read
from ghidra_manager.errors import ManagerError
from ghidra_manager.storage import atomic_json


def load(root: Path) -> dict[str, Any]:
    path = root / "work-queue.json"
    value = read(path) if path.exists() else {"schema_version": 1, "tasks": []}
    if value.get("schema_version") != 1:
        raise ManagerError("Unsupported work queue")
    return value


def next_task(root: Path, queue: str = "naming") -> dict[str, Any]:
    require_admission(root)
    tasks = load(root)["tasks"]
    completed = {t["id"] for t in tasks if t["status"] == "complete"}
    if any(t["status"] == "active" for t in tasks):
        raise ManagerError("Finish or defer the active bounded task first")
    candidates = sorted(
        (
            t
            for t in tasks
            if t["queue"] == queue
            and t["status"] == "pending"
            and set(t["depends_on"]) <= completed
        ),
        key=lambda t: (-t["priority"], t["id"]),
    )
    return {
        "task": candidates[0] if candidates else None,
        "queue": queue,
        "deferred": sum(t["status"] == "deferred" for t in tasks),
    }


def operate(root: Path, action: str, task_id: str, **values: Any) -> dict[str, Any]:
    if not task_id or "/" in task_id or "\\" in task_id:
        raise ManagerError("Task ID must be a nonempty local identifier")
    with locked(root):
        document = load(root)
        tasks = document["tasks"]
        task = next((t for t in tasks if t["id"] == task_id), None)
        if action == "add":
            addresses = values.get("addresses", [])
            if task or not addresses or len(set(addresses)) != len(addresses):
                raise ManagerError("Require a new task ID and unique target addresses")
            if values["queue"] == "naming" and len(addresses) > 10:
                raise ManagerError("Split naming tasks into batches of at most ten targets")
            if not set(values.get("depends_on", [])) <= {t["id"] for t in tasks}:
                raise ManagerError("Dependencies must already exist")
            task = {
                "id": task_id,
                "queue": values["queue"],
                "addresses": addresses,
                "depends_on": values.get("depends_on", []),
                "priority": values.get("priority", 0),
                "status": "pending",
                "attempts": 0,
                "history": [],
            }
            tasks.append(task)
        elif task is None:
            raise ManagerError("Unknown task")
        elif action == "start":
            require_admission(root)
            completed = {t["id"] for t in tasks if t["status"] == "complete"}
            if (
                task["status"] != "pending"
                or not set(task["depends_on"]) <= completed
                or any(t["status"] == "active" for t in tasks)
            ):
                raise ManagerError("Task cannot start: state, dependencies, or active worker")
            task["status"] = "active"
        elif action in {"fail", "defer", "retry"}:
            if not values.get("reason", "").strip():
                raise ManagerError("Record the failure evidence or explicit retry decision")
            if action == "retry":
                if task["status"] != "deferred":
                    raise ManagerError("Only a deferred task can be retried")
                task["attempts"] = 0
                task["status"] = "pending"
            else:
                if task["status"] != "active":
                    raise ManagerError("Only active work can fail or be deferred")
                task["attempts"] += 1
                task["status"] = (
                    "deferred" if action == "defer" or task["attempts"] >= 2 else "pending"
                )
        elif action == "complete":
            if task["status"] != "active":
                raise ManagerError("Only active work can complete")
            batch = read(root / "batch.json")
            plan = read(Path(batch["plan_path"]))
            if (
                batch["status"] != "saved"
                or batch["plan"] != values.get("batch")
                or plan["queue"] != task["queue"]
                or not set(task["addresses"])
                <= {c.get("address", c.get("path", c.get("name"))) for c in plan["changes"]}
            ):
                raise ManagerError("Completion requires a saved batch covering the task")
            task["status"] = "complete"
        else:
            raise ManagerError("Unknown task operation")
        task["history"].append(
            {
                "action": action,
                "at": timestamp(),
                "reason": values.get("reason"),
                "batch": values.get("batch"),
            }
        )
        atomic_json(root / "work-queue.json", document)
        return dict(task)
