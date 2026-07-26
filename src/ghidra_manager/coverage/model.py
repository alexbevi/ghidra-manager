"""Coverage schemas, canonical serialization, and stable identities."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ghidra_manager.errors import ManagerError
from ghidra_manager.storage import atomic_json

PROFILE_SCHEMA = "ghidra-manager-coverage-profile"
LEDGER_SCHEMA = "ghidra-manager-coverage-ledger"
SNAPSHOT_SCHEMA = "ghidra-manager-coverage-snapshot"
EVIDENCE_SCHEMA = "ghidra-manager-coverage-evidence"
PLAN_SCHEMA = "ghidra-manager-coverage-plan"
REPORT_SCHEMA = "ghidra-manager-coverage-report"
DIFF_SCHEMA = "ghidra-manager-coverage-diff"
REVIEW_QUEUE_SCHEMA = "ghidra-manager-coverage-review-queue"
SCHEMA_VERSION = 1

COVERAGE_STATUSES = {
    "complete",
    "partial",
    "equivalent",
    "missing",
    "not_applicable",
    "unknown",
}
SCOPE_STATES = {"in_scope", "out_of_scope", "unreviewed"}
VERIFICATION_STATES = {
    "unverified",
    "static_verified",
    "test_verified",
    "runtime_verified",
    "retail_parity_tested",
}
EVIDENCE_CLAIMS = {"mentioned", "mapped", "changed_with", "diagnostic", "verified_by"}
REACHABILITY_STATES = {
    "direct_static",
    "declared_indirect",
    "data_driven",
    "runtime_observed",
    "unknown",
    "proven_unreachable",
}


def canonical_bytes(value: object) -> bytes:
    """Serialize canonical coverage JSON."""
    return (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True, separators=(",", ": "))
        + "\n"
    ).encode()


def content_id(value: object) -> str:
    return f"sha256:{hashlib.sha256(canonical_bytes(value)).hexdigest()}"


def with_content_id(value: dict[str, Any], field: str) -> dict[str, Any]:
    result = dict(value)
    result.pop(field, None)
    result[field] = content_id(result)
    return result


def load_json(path: Path) -> dict[str, Any]:
    try:
        value: object = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ManagerError(f"Unable to read coverage JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ManagerError(f"Coverage JSON must contain an object: {path}")
    return value


def write_canonical(path: Path, value: object, *, mode: int | None = None) -> None:
    atomic_json(path, value, mode=mode)


def require_schema(value: dict[str, Any], schema: str, *, path: Path | None = None) -> None:
    location = f" in {path}" if path else ""
    if value.get("schema") != schema or value.get("version") != SCHEMA_VERSION:
        raise ManagerError(f"Unsupported {schema} schema or version{location}")


def safe_component(value: str) -> str:
    component = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip()).strip("-")
    if not component:
        raise ManagerError("Coverage identifier cannot be empty")
    return component.lower()


@dataclass(frozen=True, slots=True, order=True)
class Address:
    """A lossless Ghidra address-space-qualified address."""

    space: str
    offset: int
    segment: int | None = None
    display: str | None = None

    @classmethod
    def parse(
        cls,
        value: str,
        *,
        default_space: str = "ram",
        known_spaces: set[str] | None = None,
    ) -> Address:
        text = value.strip()
        if not text:
            raise ManagerError("Ghidra address cannot be empty")
        space = default_space
        segment: int | None = None
        number = text
        if "::" in text:
            space, number = text.split("::", 1)
        elif text.count(":") == 1:
            prefix, suffix = text.split(":", 1)
            if known_spaces and prefix in known_spaces:
                space, number = prefix, suffix
            elif re.fullmatch(r"(?:0x)?[0-9a-fA-F]+", prefix) and re.fullmatch(
                r"(?:0x)?[0-9a-fA-F]+", suffix
            ):
                segment = int(prefix, 16)
                number = suffix
            else:
                space, number = prefix, suffix
        if known_spaces and space not in known_spaces:
            raise ManagerError(f"Unknown Ghidra address space: {space}")
        normalized = number.removeprefix("0x").removeprefix("0X")
        try:
            offset = int(normalized, 16)
        except ValueError as exc:
            raise ManagerError(f"Invalid Ghidra address: {value}") from exc
        return cls(space=space, offset=offset, segment=segment, display=text)

    @property
    def key(self) -> str:
        segment = f"{self.segment:x}:" if self.segment is not None else ""
        return f"{self.space}:{segment}{self.offset:08x}"

    def to_json(self) -> dict[str, object]:
        result: dict[str, object] = {
            "space": self.space,
            "offset": f"0x{self.offset:08x}",
            "display": self.display or self.key,
        }
        if self.segment is not None:
            result["segment"] = f"0x{self.segment:x}"
        return result


@dataclass(frozen=True, slots=True)
class CoveragePaths:
    """Filesystem layout for one ignored coverage workspace."""

    root: Path

    @classmethod
    def from_profile(cls, profile: Path) -> CoveragePaths:
        resolved = profile.expanduser().resolve()
        return cls(resolved if resolved.is_dir() else resolved.parent)

    @property
    def profile(self) -> Path:
        return self.root / "profile.json"

    @property
    def ledger(self) -> Path:
        return self.root / "ledger.json"

    @property
    def snapshots(self) -> Path:
        return self.root / "snapshots"

    @property
    def evidence(self) -> Path:
        return self.root / "evidence"

    @property
    def plans(self) -> Path:
        return self.root / "plans"

    @property
    def review_queue(self) -> Path:
        return self.root / "review-queue.json"

    @property
    def reports(self) -> Path:
        return self.root / "reports"


def validate_profile(value: dict[str, Any]) -> list[str]:
    require_schema(value, PROFILE_SCHEMA)
    errors: list[str] = []
    if not isinstance(value.get("id"), str) or not value["id"]:
        errors.append("profile id is required")
    repository = value.get("repository")
    if not isinstance(repository, dict) or not isinstance(repository.get("root"), str):
        errors.append("repository.root is required")
    source = value.get("source")
    if not isinstance(source, dict):
        errors.append("source is required")
    elif not all(isinstance(source.get(key), str) for key in ("project", "program")):
        errors.append("source.project and source.program are required")
    adapter = value.get("adapter")
    if not isinstance(adapter, dict) or not isinstance(adapter.get("id"), str):
        errors.append("adapter.id is required")
    active = value.get("active")
    if not isinstance(active, dict):
        errors.append("active snapshot/evidence pointers are required")
    return errors


def validate_ledger(value: dict[str, Any]) -> list[str]:
    require_schema(value, LEDGER_SCHEMA)
    errors: list[str] = []
    records = value.get("records")
    if not isinstance(records, list):
        return ["ledger records must be an array"]
    identifiers: set[str] = set()
    for index, raw in enumerate(records):
        if not isinstance(raw, dict):
            errors.append(f"record {index} must be an object")
            continue
        identifier = raw.get("id")
        if not isinstance(identifier, str) or not identifier:
            errors.append(f"record {index} has no stable id")
        elif identifier in identifiers:
            errors.append(f"duplicate ledger record id: {identifier}")
        else:
            identifiers.add(identifier)
        scope = raw.get("scope", {})
        if not isinstance(scope, dict) or scope.get("state") not in SCOPE_STATES:
            errors.append(f"{identifier or index}: invalid scope state")
        if raw.get("status") not in COVERAGE_STATUSES:
            errors.append(f"{identifier or index}: invalid coverage status")
        verification = raw.get("verification", {})
        if (
            not isinstance(verification, dict)
            or verification.get("state") not in VERIFICATION_STATES
        ):
            errors.append(f"{identifier or index}: invalid verification state")
        reachability = raw.get("reachability", "unknown")
        if reachability not in REACHABILITY_STATES:
            errors.append(f"{identifier or index}: invalid reachability state")
        if raw.get("kind") not in {"function", "behavioral_unit"}:
            errors.append(f"{identifier or index}: invalid coverage record kind")
        if raw.get("kind") == "behavioral_unit" and raw.get(
            "unit_type", "registry"
        ) not in {"registry", "scenario"}:
            errors.append(f"{identifier or index}: invalid behavioral unit type")
        if raw.get("player_impact") is not None and not isinstance(
            raw.get("player_impact"), str
        ):
            errors.append(f"{identifier or index}: player_impact must be text")
        for field in ("known_missing", "deviations"):
            if field in raw and not isinstance(raw.get(field), list):
                errors.append(f"{identifier or index}: {field} must be an array")
        if raw.get("status") == "not_applicable":
            if not isinstance(scope, dict) or scope.get("state") != "out_of_scope":
                errors.append(f"{identifier or index}: not_applicable must be out_of_scope")
            if not raw.get("exclusion_reason"):
                errors.append(f"{identifier or index}: not_applicable requires exclusion_reason")
        if raw.get("status") == "equivalent" and not raw.get("equivalent_reason"):
            errors.append(f"{identifier or index}: equivalent requires equivalent_reason")
        if (
            isinstance(verification, dict)
            and verification.get("state") != "unverified"
            and not verification.get("records")
        ):
            errors.append(
                f"{identifier or index}: verified state requires verification records"
            )
    return errors
