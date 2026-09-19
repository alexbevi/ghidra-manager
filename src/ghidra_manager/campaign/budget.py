"""Provider-neutral usage accounting. Counters are observations, not quota estimates."""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ghidra_manager.errors import ManagerError
from ghidra_manager.storage import atomic_json

DEFAULT_TOKENS = 100_000


def admission(root: Path, *, purpose: str = "analysis") -> dict[str, Any]:
    """Gate new batches, not completion of a batch that already changed Ghidra."""
    if purpose not in {"analysis", "verify", "recover", "save"}:
        raise ManagerError("Unknown admission purpose")
    result = summary(load(root))
    result["purpose"] = purpose
    result["admitted"] = purpose != "analysis" or result["status"] in {"ready", "warning"}
    return result


def require_admission(root: Path) -> None:
    result = admission(root)
    if not result["admitted"]:
        raise ManagerError(
            f"New work blocked: budget {result['status']}; record usage or adjust the allowance"
        )


def timestamp() -> str:
    return datetime.now(UTC).isoformat()


@contextmanager
def locked(root: Path) -> Iterator[None]:
    """Exclusive local writer; never guess that another writer is stale."""
    path = root / ".campaign.lock"
    try:
        handle = path.open("x", encoding="utf-8")
    except FileExistsError as exc:
        raise ManagerError(
            f"Campaign locked: {path}; reconcile the writer before removing it"
        ) from exc
    try:
        handle.write(str(uuid.uuid4()))
        handle.close()
        yield
    finally:
        path.unlink()


def load(root: Path) -> dict[str, Any]:
    path = root / "budget.json"
    if not path.exists():
        return {
            "schema_version": 1,
            "default_tokens": DEFAULT_TOKENS,
            "sessions": [],
            "adjustments": [],
        }
    value = json.loads(path.read_text())
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise ManagerError("Unsupported budget ledger")
    return value


def active(ledger: dict[str, Any]) -> dict[str, Any] | None:
    return next((s for s in reversed(ledger["sessions"]) if s["closed_at"] is None), None)


def summary(ledger: dict[str, Any]) -> dict[str, Any]:
    session = active(ledger)
    streams = session["streams"] if session else []
    used = sum(s["last_counter"] - s["baseline"] for s in streams) if streams else None
    limit = session["limit"] if session else ledger["default_tokens"]
    return {
        "session": session["id"] if session else None,
        "limit": limit,
        "used": used,
        "remaining": max(0, limit - used) if used is not None else None,
        "overshoot": max(0, used - limit) if used is not None else None,
        "status": "unknown"
        if used is None
        else ("exhausted" if used >= limit else "warning" if used >= limit * 0.8 else "ready"),
        "coverage": [s["scope"] for s in streams],
        "last_measurement": max((s["updated_at"] for s in streams), default=None),
        "campaign_measured_tokens": sum(
            s["last_counter"] - s["baseline"]
            for session in ledger["sessions"]
            for s in session["streams"]
        ),
        "note": "Reported counter deltas; not weekly allowance or an in-flight model cap",
    }


def operate(root: Path, action: str, **values: Any) -> dict[str, Any]:
    if action == "show":
        return summary(load(root))
    with locked(root):
        ledger = load(root)
        session = active(ledger)
        tokens = values.get("tokens")
        if tokens is not None and (type(tokens) is not int or tokens <= 0):
            raise ManagerError("Token allowance must be a positive integer")
        if action == "set":
            ledger["adjustments"].append(
                {"at": timestamp(), "tokens": tokens, "session": session["id"] if session else None}
            )
            ledger["default_tokens"] = tokens
            if session:
                session["limit"] = tokens
        elif action == "start":
            if session:
                raise ManagerError("Finish the active session before starting another baseline")
            ledger["sessions"].append(
                {
                    "id": str(uuid.uuid4()),
                    "started_at": timestamp(),
                    "closed_at": None,
                    "limit": tokens or ledger["default_tokens"],
                    "streams": [],
                    "measurements": {},
                }
            )
        elif action == "finish":
            if not session:
                raise ManagerError("No active session")
            session["closed_at"] = timestamp()
        elif action == "record":
            if not session:
                raise ManagerError("Start a session before recording its usage baseline")
            counter = values["counter"]
            if type(counter) is not int or counter < 0:
                raise ManagerError("Counter must be a nonnegative integer")
            scope = sorted(set(values["scope"]))
            if not scope or any(not x.strip() for x in scope):
                raise ManagerError("Measurement scope must explicitly identify covered agents")
            record = {
                "source": values["source"],
                "stream": values["stream"],
                "counter": counter,
                "scope": scope,
            }
            previous = session["measurements"].get(values["measurement"])
            if previous:
                if previous != record:
                    raise ManagerError("Measurement identifier already has different contents")
                return summary(ledger)
            stream = next(
                (
                    s
                    for s in session["streams"]
                    if (s["source"], s["stream"]) == (record["source"], record["stream"])
                ),
                None,
            )
            if stream:
                if stream["scope"] != scope or counter < stream["last_counter"]:
                    raise ManagerError("Counter reset or scope change; reconcile before recording")
                stream["last_counter"] = counter
                stream["updated_at"] = timestamp()
            else:
                if any(set(s["scope"]) & set(scope) for s in session["streams"]):
                    raise ManagerError("Measurement scopes overlap; refusing double-counting")
                session["streams"].append(
                    {
                        **record,
                        "baseline": counter,
                        "last_counter": counter,
                        "updated_at": timestamp(),
                    }
                )
            session["measurements"][values["measurement"]] = record
        else:
            raise ManagerError(f"Unknown budget operation: {action}")
        atomic_json(root / "budget.json", ledger)
        return summary(ledger)
