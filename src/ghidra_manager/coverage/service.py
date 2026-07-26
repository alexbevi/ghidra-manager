"""Coverage command orchestration."""

from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ghidra_manager.config import ManagerPaths
from ghidra_manager.coverage.diffing import build_diff, markdown_diff
from ghidra_manager.coverage.evidence import collect_evidence
from ghidra_manager.coverage.inventory import EndpointFetch, build_snapshot, fetch_endpoint
from ghidra_manager.coverage.model import (
    DIFF_SCHEMA,
    EVIDENCE_SCHEMA,
    LEDGER_SCHEMA,
    PLAN_SCHEMA,
    PROFILE_SCHEMA,
    REPORT_SCHEMA,
    REVIEW_QUEUE_SCHEMA,
    SCHEMA_VERSION,
    SNAPSHOT_SCHEMA,
    CoveragePaths,
    content_id,
    load_json,
    require_schema,
    safe_component,
    validate_ledger,
    validate_profile,
    with_content_id,
    write_canonical,
)
from ghidra_manager.coverage.rendering import markdown_report
from ghidra_manager.coverage.reporting import build_report
from ghidra_manager.coverage.repository import (
    atomic_directory_create,
    ensure_locally_ignored,
    repository_identity,
    repository_root,
)
from ghidra_manager.coverage.seeding import AUTOMATED_STATUSES, build_seed
from ghidra_manager.errors import ManagerError
from ghidra_manager.mcp import DEFAULT_PORT, Instance, discover_instances

PLAN_RETENTION = 10


def _file_hash(path: Path) -> str:
    try:
        return f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"
    except OSError as exc:
        raise ManagerError(f"Unable to fingerprint coverage input {path}: {exc}") from exc


def _id_filename(identifier: str) -> str:
    return f"{identifier.removeprefix('sha256:')}.json"


class CoverageService:
    """Implement coverage workflows without coupling them to argparse."""

    def __init__(
        self,
        manager_paths: ManagerPaths,
        *,
        instance_discovery: Callable[[int], list[Instance]] = discover_instances,
        endpoint_fetch: EndpointFetch = fetch_endpoint,
    ):
        self.manager_paths = manager_paths
        self.instance_discovery = instance_discovery
        self.endpoint_fetch = endpoint_fetch

    @property
    def cache(self) -> Path:
        return self.manager_paths.coverage / "blobs"

    @staticmethod
    def default_profile(repository: Path) -> Path:
        return repository_root(repository) / "reports" / "coverage" / "profile.json"

    def init(
        self,
        *,
        repository: Path,
        profile_path: Path | None,
        adapter: str,
        project: str,
        program: str,
        scope: str,
        architecture: str | None,
        base_port: int = DEFAULT_PORT,
    ) -> Path:
        root = repository_root(repository)
        profile_file = (
            profile_path.expanduser().resolve()
            if profile_path
            else self.default_profile(root)
        )
        paths = CoveragePaths.from_profile(profile_file)
        if paths.root.exists():
            raise ManagerError(f"Coverage workspace already exists: {paths.root}")
        try:
            relative = paths.root.relative_to(root)
        except ValueError as exc:
            raise ManagerError(
                "Coverage workspace must be inside the reimplementation repository"
            ) from exc
        ensure_locally_ignored(root, relative)
        profile_id = safe_component(f"{adapter}-{project}-{Path(program).name}")
        profile: dict[str, Any] = {
            "schema": PROFILE_SCHEMA,
            "version": SCHEMA_VERSION,
            "id": profile_id,
            "repository": {
                "root": str(root),
                "scope": scope,
            },
            "source": {
                "project": project,
                "program": program,
                "base_port": base_port,
                "roots": [],
                "declared_edges": [],
            },
            "adapter": {
                "id": adapter,
                "version": 1,
                "architecture": architecture,
            },
            "active": {"snapshot": None, "evidence": None},
        }
        ledger = {
            "schema": LEDGER_SCHEMA,
            "version": SCHEMA_VERSION,
            "profile_id": profile_id,
            "records": [],
        }
        paths.root.parent.mkdir(parents=True, exist_ok=True)
        staged = Path(
            tempfile.mkdtemp(prefix=f".{paths.root.name}.", dir=paths.root.parent)
        )
        try:
            write_canonical(staged / "profile.json", profile)
            write_canonical(staged / "ledger.json", ledger)
            for directory in ("snapshots", "evidence", "plans", "reports"):
                (staged / directory).mkdir()
            atomic_directory_create(staged, paths.root)
        finally:
            shutil.rmtree(staged, ignore_errors=True)
        return paths.profile

    def validate(self, profile_path: Path) -> list[str]:
        paths = CoveragePaths.from_profile(profile_path)
        profile = load_json(paths.profile)
        ledger = load_json(paths.ledger)
        errors = validate_profile(profile) + validate_ledger(ledger)
        if ledger.get("profile_id") != profile.get("id"):
            errors.append("ledger profile_id does not match profile id")
        active = profile.get("active", {})
        if isinstance(active, dict):
            snapshot: dict[str, Any] | None = None
            snapshot_id = active.get("snapshot")
            evidence_id = active.get("evidence")
            if snapshot_id:
                snapshot_path = paths.snapshots / _id_filename(str(snapshot_id))
                if not snapshot_path.is_file():
                    errors.append(f"active snapshot is missing: {snapshot_id}")
                else:
                    snapshot = load_json(snapshot_path)
                    require_schema(snapshot, SNAPSHOT_SCHEMA, path=snapshot_path)
                    expected = with_content_id(snapshot, "snapshot_id")["snapshot_id"]
                    if snapshot.get("snapshot_id") != expected:
                        errors.append(f"snapshot content id is invalid: {snapshot_id}")
            if evidence_id:
                evidence_path = paths.evidence / _id_filename(str(evidence_id))
                if not evidence_path.is_file():
                    errors.append(f"active evidence is missing: {evidence_id}")
                else:
                    evidence = load_json(evidence_path)
                    require_schema(evidence, EVIDENCE_SCHEMA, path=evidence_path)
                    expected = with_content_id(evidence, "scan_id")["scan_id"]
                    if evidence.get("scan_id") != expected:
                        errors.append(f"evidence content id is invalid: {evidence_id}")
                    if evidence.get("snapshot_id") != snapshot_id:
                        errors.append("active evidence references a different snapshot")
                    fact_ids = {
                        str(item["id"])
                        for item in evidence.get("facts", [])
                        if isinstance(item, dict) and isinstance(item.get("id"), str)
                    }
                    historical_fact_ids = set(fact_ids)
                    for historical_path in sorted(paths.evidence.glob("*.json")):
                        if historical_path == evidence_path:
                            continue
                        try:
                            historical = load_json(historical_path)
                            require_schema(
                                historical,
                                EVIDENCE_SCHEMA,
                                path=historical_path,
                            )
                        except ManagerError:
                            continue
                        historical_fact_ids.update(
                            str(item["id"])
                            for item in historical.get("facts", [])
                            if isinstance(item, dict)
                            and isinstance(item.get("id"), str)
                        )
                    for record in ledger.get("records", []):
                        if not isinstance(record, dict):
                            continue
                        for reference in record.get("evidence", []):
                            if reference not in historical_fact_ids:
                                errors.append(
                                    f"{record.get('id')}: unknown evidence reference {reference}"
                                )
                    if snapshot is not None:
                        function_ids = {
                            str(item["id"])
                            for item in snapshot.get("functions", [])
                            if isinstance(item, dict) and isinstance(item.get("id"), str)
                        }
                        for record in ledger.get("records", []):
                            if (
                                isinstance(record, dict)
                                and record.get("kind") == "function"
                                and record.get("id") not in function_ids
                            ):
                                errors.append(
                                    f"unknown source function record: {record.get('id')}"
                                )
            if paths.review_queue.is_file():
                queue = load_json(paths.review_queue)
                require_schema(queue, REVIEW_QUEUE_SCHEMA, path=paths.review_queue)
                expected_queue = with_content_id(queue, "queue_id")["queue_id"]
                if queue.get("queue_id") != expected_queue:
                    errors.append("review queue content id is invalid")
                if queue.get("snapshot_id") != snapshot_id:
                    errors.append("review queue references a different snapshot")
                if queue.get("evidence_scan_id") != evidence_id:
                    errors.append("review queue references different evidence")
                ledger_ids = {
                    str(record["id"])
                    for record in ledger.get("records", [])
                    if isinstance(record, dict) and isinstance(record.get("id"), str)
                }
                for candidate in queue.get("candidates", []):
                    if not isinstance(candidate, dict):
                        errors.append("review queue candidate must be an object")
                        continue
                    if candidate.get("record_id") not in ledger_ids:
                        errors.append(
                            f"review queue references unknown record: "
                            f"{candidate.get('record_id')}"
                        )
                    if candidate.get("suggested_status") not in AUTOMATED_STATUSES:
                        errors.append(
                            f"review queue contains authoritative status suggestion: "
                            f"{candidate.get('suggested_status')}"
                        )
        return errors

    def _resolve_live_instance(self, profile: dict[str, Any]) -> Instance:
        source = profile["source"]
        project = str(source["project"])
        program = str(source["program"])
        instances = [
            item
            for item in self.instance_discovery(int(source.get("base_port", DEFAULT_PORT)))
            if item.project == project
        ]
        if len(instances) != 1:
            raise ManagerError(
                f"Coverage requires exactly one responding Ghidra project named {project}"
            )
        instance = instances[0]
        program_names = {item.lstrip("/") for item in instance.programs}
        if instance.programs and program.lstrip("/") not in program_names:
            raise ManagerError(
                f"Ghidra project {project} does not have program {program} open"
            )
        return instance

    def _load_offline_snapshot(
        self, paths: CoveragePaths, snapshot_reference: str
    ) -> dict[str, Any]:
        candidate = Path(snapshot_reference).expanduser()
        path = (
            candidate.resolve()
            if candidate.is_file()
            else paths.snapshots / _id_filename(snapshot_reference)
        )
        snapshot = load_json(path)
        require_schema(snapshot, SNAPSHOT_SCHEMA, path=path)
        return snapshot

    def scan(
        self,
        profile_path: Path,
        *,
        offline_snapshot: str | None,
        allow_dirty: bool,
    ) -> Path:
        paths = CoveragePaths.from_profile(profile_path)
        profile = load_json(paths.profile)
        ledger = load_json(paths.ledger)
        profile_errors = validate_profile(profile)
        ledger_errors = validate_ledger(ledger)
        if profile_errors or ledger_errors:
            raise ManagerError("; ".join(profile_errors + ledger_errors))
        source_mode = "offline" if offline_snapshot else "live"
        if offline_snapshot:
            snapshot = self._load_offline_snapshot(paths, offline_snapshot)
        else:
            instance = self._resolve_live_instance(profile)
            source = profile["source"]
            snapshot = build_snapshot(
                project=str(source["project"]),
                program=str(source["program"]),
                port=instance.port,
                fetch=self.endpoint_fetch,
                roots=list(source.get("roots", [])),
                declared_edges=list(source.get("declared_edges", [])),
            )
        evidence = collect_evidence(
            profile=profile,
            snapshot=snapshot,
            allow_dirty=allow_dirty,
        )
        snapshot_cache = self.cache / "snapshots" / _id_filename(snapshot["snapshot_id"])
        evidence_cache = self.cache / "evidence" / _id_filename(evidence["scan_id"])
        write_canonical(snapshot_cache, snapshot, mode=0o600)
        write_canonical(evidence_cache, evidence, mode=0o600)
        plan: dict[str, Any] = {
            "schema": PLAN_SCHEMA,
            "version": SCHEMA_VERSION,
            "created_at": datetime.now(UTC).isoformat(),
            "profile_path": str(paths.profile),
            "preconditions": {
                "profile_hash": _file_hash(paths.profile),
                "ledger_hash": _file_hash(paths.ledger),
                "active": profile["active"],
                "repository": evidence["repository"],
                "source_mode": source_mode,
                "allow_dirty": allow_dirty,
            },
            "payloads": {
                "snapshot": {
                    "id": snapshot["snapshot_id"],
                    "cache_path": str(snapshot_cache),
                    "hash": _file_hash(snapshot_cache),
                },
                "evidence": {
                    "id": evidence["scan_id"],
                    "cache_path": str(evidence_cache),
                    "hash": _file_hash(evidence_cache),
                },
            },
            "operations": [
                {
                    "kind": "publish_snapshot",
                    "id": snapshot["snapshot_id"],
                },
                {
                    "kind": "publish_evidence",
                    "id": evidence["scan_id"],
                },
                {
                    "kind": "update_active_inputs",
                    "snapshot": snapshot["snapshot_id"],
                    "evidence": evidence["scan_id"],
                },
            ],
            "policy": {
                "mutates_ghidra": False,
                "mutates_reviewed_ledger": False,
            },
        }
        plan = with_content_id(plan, "plan_id")
        paths.plans.mkdir(parents=True, exist_ok=True)
        plan_path = paths.plans / _id_filename(plan["plan_id"])
        write_canonical(plan_path, plan, mode=0o600)
        plans = sorted(paths.plans.glob("*.json"), key=lambda item: item.stat().st_mtime)
        for stale in plans[:-PLAN_RETENTION]:
            stale.unlink()
        return plan_path

    def seed(self, profile_path: Path) -> Path:
        """Generate a retained plan that seeds only missing/unreviewed ledger data."""
        paths = CoveragePaths.from_profile(profile_path)
        errors = self.validate(paths.profile)
        if errors:
            raise ManagerError("; ".join(errors))
        profile = load_json(paths.profile)
        ledger = load_json(paths.ledger)
        active = profile["active"]
        if not active.get("snapshot") or not active.get("evidence"):
            raise ManagerError("Coverage seed requires an applied snapshot/evidence scan")
        snapshot_path = paths.snapshots / _id_filename(str(active["snapshot"]))
        evidence_path = paths.evidence / _id_filename(str(active["evidence"]))
        snapshot = load_json(snapshot_path)
        evidence = load_json(evidence_path)
        seeded_ledger, review_queue, summary = build_seed(
            profile, ledger, snapshot, evidence
        )
        ledger_id = content_id(seeded_ledger)
        ledger_cache = self.cache / "seeds" / f"{ledger_id.removeprefix('sha256:')}-ledger.json"
        queue_cache = self.cache / "seeds" / _id_filename(str(review_queue["queue_id"]))
        write_canonical(ledger_cache, seeded_ledger, mode=0o600)
        write_canonical(queue_cache, review_queue, mode=0o600)
        plan: dict[str, Any] = {
            "schema": PLAN_SCHEMA,
            "version": SCHEMA_VERSION,
            "plan_type": "ledger_seed",
            "created_at": datetime.now(UTC).isoformat(),
            "profile_path": str(paths.profile),
            "preconditions": {
                "profile_hash": _file_hash(paths.profile),
                "ledger_hash": _file_hash(paths.ledger),
                "active": active,
                "snapshot_hash": _file_hash(snapshot_path),
                "evidence_hash": _file_hash(evidence_path),
            },
            "payloads": {
                "ledger": {
                    "id": ledger_id,
                    "cache_path": str(ledger_cache),
                    "hash": _file_hash(ledger_cache),
                },
                "review_queue": {
                    "id": review_queue["queue_id"],
                    "cache_path": str(queue_cache),
                    "hash": _file_hash(queue_cache),
                },
            },
            "summary": summary,
            "operations": [
                {
                    "kind": "merge_unreviewed_ledger_records",
                    "added": summary["added_records"],
                    "refreshed": summary["refreshed_unreviewed_records"],
                    "preserved": summary["preserved_records"],
                },
                {
                    "kind": "publish_review_queue",
                    "candidates": summary["review_candidates"],
                },
            ],
            "policy": {
                "mutates_ghidra": False,
                "mutates_ledger": True,
                "preserves_reviewed_records": True,
                "suggestions_are_advisory": True,
            },
        }
        plan = with_content_id(plan, "plan_id")
        paths.plans.mkdir(parents=True, exist_ok=True)
        plan_path = paths.plans / _id_filename(str(plan["plan_id"]))
        write_canonical(plan_path, plan, mode=0o600)
        plans = sorted(paths.plans.glob("*.json"), key=lambda item: item.stat().st_mtime)
        for stale in plans[:-PLAN_RETENTION]:
            stale.unlink()
        return plan_path

    def _recheck_live_snapshot(
        self, profile: dict[str, Any], expected_snapshot_id: str
    ) -> None:
        instance = self._resolve_live_instance(profile)
        source = profile["source"]
        current = build_snapshot(
            project=str(source["project"]),
            program=str(source["program"]),
            port=instance.port,
            fetch=self.endpoint_fetch,
            roots=list(source.get("roots", [])),
            declared_edges=list(source.get("declared_edges", [])),
        )
        if current["snapshot_id"] != expected_snapshot_id:
            raise ManagerError("Ghidra program changed since coverage scan; rerun scan")

    def apply(self, plan_path: Path) -> list[str]:
        plan = load_json(plan_path.expanduser().resolve())
        require_schema(plan, PLAN_SCHEMA, path=plan_path)
        if plan.get("plan_id") != with_content_id(plan, "plan_id")["plan_id"]:
            raise ManagerError("Coverage plan content id is invalid")
        paths = CoveragePaths.from_profile(Path(str(plan["profile_path"])))
        profile = load_json(paths.profile)
        preconditions = plan["preconditions"]
        if _file_hash(paths.profile) != preconditions["profile_hash"]:
            raise ManagerError("Coverage profile changed since plan creation; regenerate plan")
        if _file_hash(paths.ledger) != preconditions["ledger_hash"]:
            raise ManagerError("Coverage ledger changed since plan creation; regenerate plan")
        if profile.get("active") != preconditions["active"]:
            raise ManagerError(
                "Active coverage inputs changed since plan creation; regenerate plan"
            )
        if plan.get("plan_type") == "ledger_seed":
            return self._apply_seed_plan(plan, paths)
        repository = Path(str(profile["repository"]["root"]))
        current_repository = repository_identity(
            repository, allow_dirty=bool(preconditions["allow_dirty"])
        )
        current_repository.pop("root", None)
        if current_repository != preconditions["repository"]:
            raise ManagerError("Reimplementation repository changed since scan; rerun scan")
        snapshot_payload = plan["payloads"]["snapshot"]
        evidence_payload = plan["payloads"]["evidence"]
        for payload in (snapshot_payload, evidence_payload):
            cache_path = Path(str(payload["cache_path"]))
            if _file_hash(cache_path) != payload["hash"]:
                raise ManagerError("Coverage plan payload is missing or changed; rerun scan")
        if preconditions["source_mode"] == "live":
            self._recheck_live_snapshot(profile, str(snapshot_payload["id"]))
        snapshot = load_json(Path(str(snapshot_payload["cache_path"])))
        evidence = load_json(Path(str(evidence_payload["cache_path"])))
        if snapshot.get("snapshot_id") != snapshot_payload["id"]:
            raise ManagerError("Coverage snapshot payload identity is invalid")
        if evidence.get("scan_id") != evidence_payload["id"]:
            raise ManagerError("Coverage evidence payload identity is invalid")
        snapshot_target = paths.snapshots / _id_filename(str(snapshot_payload["id"]))
        evidence_target = paths.evidence / _id_filename(str(evidence_payload["id"]))
        if snapshot_target.exists() and _file_hash(snapshot_target) != snapshot_payload["hash"]:
            raise ManagerError("Published coverage snapshot conflicts with plan payload")
        if evidence_target.exists() and _file_hash(evidence_target) != evidence_payload["hash"]:
            raise ManagerError("Published coverage evidence conflicts with plan payload")
        if not snapshot_target.exists():
            write_canonical(snapshot_target, snapshot)
        if not evidence_target.exists():
            write_canonical(evidence_target, evidence)
        updated_profile = dict(profile)
        updated_profile["active"] = {
            "snapshot": snapshot_payload["id"],
            "evidence": evidence_payload["id"],
        }
        write_canonical(paths.profile, updated_profile)
        paths.review_queue.unlink(missing_ok=True)
        return [
            f"Published snapshot {snapshot_payload['id']}.",
            f"Published evidence {evidence_payload['id']}.",
            "Reviewed ledger unchanged.",
        ]

    def _apply_seed_plan(
        self, plan: dict[str, Any], paths: CoveragePaths
    ) -> list[str]:
        preconditions = plan["preconditions"]
        active = preconditions["active"]
        snapshot_path = paths.snapshots / _id_filename(str(active["snapshot"]))
        evidence_path = paths.evidence / _id_filename(str(active["evidence"]))
        if _file_hash(snapshot_path) != preconditions["snapshot_hash"]:
            raise ManagerError("Coverage snapshot changed since seed; regenerate plan")
        if _file_hash(evidence_path) != preconditions["evidence_hash"]:
            raise ManagerError("Coverage evidence changed since seed; regenerate plan")
        ledger_payload = plan["payloads"]["ledger"]
        queue_payload = plan["payloads"]["review_queue"]
        for payload in (ledger_payload, queue_payload):
            cache_path = Path(str(payload["cache_path"]))
            if _file_hash(cache_path) != payload["hash"]:
                raise ManagerError("Coverage seed payload is missing or changed; regenerate plan")
        seeded_ledger = load_json(Path(str(ledger_payload["cache_path"])))
        review_queue = load_json(Path(str(queue_payload["cache_path"])))
        if content_id(seeded_ledger) != ledger_payload["id"]:
            raise ManagerError("Coverage seed ledger payload identity is invalid")
        require_schema(review_queue, REVIEW_QUEUE_SCHEMA)
        if review_queue.get("queue_id") != queue_payload["id"]:
            raise ManagerError("Coverage review queue payload identity is invalid")
        ledger_errors = validate_ledger(seeded_ledger)
        if ledger_errors:
            raise ManagerError("; ".join(ledger_errors))
        if any(
            not isinstance(candidate, dict)
            or candidate.get("suggested_status") not in AUTOMATED_STATUSES
            for candidate in review_queue.get("candidates", [])
        ):
            raise ManagerError("Coverage review queue contains an authoritative suggestion")
        write_canonical(paths.review_queue, review_queue)
        write_canonical(paths.ledger, seeded_ledger)
        summary = plan["summary"]
        return [
            f"Added {summary['added_records']} unreviewed ledger records.",
            f"Refreshed {summary['refreshed_unreviewed_records']} unreviewed records.",
            f"Preserved {summary['preserved_records']} existing records.",
            f"Review queue: {paths.review_queue} "
            f"({summary['review_candidates']} candidates).",
        ]

    def plans(self, profile_path: Path) -> list[dict[str, object]]:
        paths = CoveragePaths.from_profile(profile_path)
        profile_hash = _file_hash(paths.profile)
        ledger_hash = _file_hash(paths.ledger)
        result: list[dict[str, object]] = []
        for path in sorted(paths.plans.glob("*.json")):
            try:
                plan = load_json(path)
                current = (
                    plan.get("preconditions", {}).get("profile_hash") == profile_hash
                    and plan.get("preconditions", {}).get("ledger_hash") == ledger_hash
                )
                result.append(
                    {
                        "path": str(path),
                        "plan_id": plan.get("plan_id"),
                        "created_at": plan.get("created_at"),
                        "plan_type": plan.get("plan_type", "scan"),
                        "current": current,
                    }
                )
            except ManagerError:
                result.append({"path": str(path), "current": False, "invalid": True})
        return result

    def report(
        self,
        profile_path: Path,
        *,
        json_path: Path | None,
        markdown_path: Path | None,
    ) -> tuple[Path, Path]:
        paths = CoveragePaths.from_profile(profile_path)
        profile = load_json(paths.profile)
        ledger = load_json(paths.ledger)
        errors = self.validate(paths.profile)
        if errors:
            raise ManagerError("; ".join(errors))
        active = profile["active"]
        if not active.get("snapshot") or not active.get("evidence"):
            raise ManagerError("Coverage profile has no applied snapshot/evidence scan")
        snapshot = load_json(paths.snapshots / _id_filename(str(active["snapshot"])))
        evidence = load_json(paths.evidence / _id_filename(str(active["evidence"])))
        review_queue = (
            load_json(paths.review_queue) if paths.review_queue.is_file() else None
        )
        value = build_report(profile, ledger, snapshot, evidence, review_queue)
        output_json = (json_path or paths.reports / "latest.json").expanduser().resolve()
        output_markdown = (
            markdown_path or paths.reports / "latest.md"
        ).expanduser().resolve()
        write_canonical(output_json, value)
        output_markdown.parent.mkdir(parents=True, exist_ok=True)
        temporary = output_markdown.with_name(f".{output_markdown.name}.{os.getpid()}.tmp")
        try:
            temporary.write_text(markdown_report(value), encoding="utf-8", newline="\n")
            os.replace(temporary, output_markdown)
        finally:
            temporary.unlink(missing_ok=True)
        return output_json, output_markdown

    def diff(
        self,
        base_path: Path,
        head_path: Path,
        *,
        json_path: Path,
        markdown_path: Path,
    ) -> tuple[Path, Path]:
        base = load_json(base_path)
        head = load_json(head_path)
        require_schema(base, REPORT_SCHEMA, path=base_path)
        require_schema(head, REPORT_SCHEMA, path=head_path)
        value = build_diff(base, head)
        require_schema(value, DIFF_SCHEMA)
        write_canonical(json_path, value)
        markdown_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = markdown_path.with_name(f".{markdown_path.name}.{os.getpid()}.tmp")
        try:
            temporary.write_text(markdown_diff(value), encoding="utf-8", newline="\n")
            os.replace(temporary, markdown_path)
        finally:
            temporary.unlink(missing_ok=True)
        return json_path, markdown_path
