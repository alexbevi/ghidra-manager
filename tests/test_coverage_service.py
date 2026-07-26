import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from ghidra_manager.config import ManagerPaths
from ghidra_manager.coverage.inventory import build_snapshot
from ghidra_manager.coverage.model import CoveragePaths, load_json, write_canonical
from ghidra_manager.coverage.service import CoverageService
from ghidra_manager.errors import ManagerError


def git(repository: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


def repository_fixture(tmp_path: Path) -> Path:
    repository = tmp_path / "reimplementation"
    repository.mkdir()
    git(repository, "init", "-q")
    git(repository, "config", "user.name", "Coverage Test")
    git(repository, "config", "user.email", "coverage@example.invalid")
    source = repository / "engines" / "ripper"
    source.mkdir(parents=True)
    (source / "script.h").write_text(
        """
enum ScriptOpcode : byte {
    kNoOp = 0x00, // OriginalNoOp at 0x1000
};
enum SceneAction {
    kPuzzle = 11
};
""",
        encoding="utf-8",
    )
    (source / "scene_dispatcher.cpp").write_text(
        """
const char *actionName(unsigned action) {
    switch (action) {
    case 11: return "puzzle";
    case 12: return "unimplemented board puzzle";
    default: return "unknown";
    }
}
""",
        encoding="utf-8",
    )
    (repository / "RIPPER-ARCHITECTURE.md").write_text(
        "`OriginalNoOp` at `0x1000`\n", encoding="utf-8"
    )
    git(repository, "add", ".")
    git(repository, "commit", "-q", "-m", "RIPPER: Map OriginalNoOp at 0x1000")
    return repository


def snapshot_fixture(tmp_path: Path) -> dict[str, Any]:
    binary = tmp_path / "RIPPER.LE"
    binary.write_bytes(b"ripper")

    def fetch(port: int, path: str, params: object) -> object | None:
        values: dict[str, Any] = {
            "/get_current_program_info": {
                "executable_path": str(binary),
                "format": "Linear Executable",
                "language": "x86:LE:32:default",
                "compiler": "borlandcpp",
            },
            "/get_metadata": {},
            "/get_address_spaces": {
                "spaces": [{"name": "ram", "kind": "memory"}]
            },
            "/get_bulk_function_hashes": {
                "functions": [
                    {
                        "name": "OriginalNoOp",
                        "address": "00001000",
                        "instruction_count": 5,
                    }
                ],
                "total_matching": 1,
            },
        }
        return values.get(path)

    return build_snapshot(
        project="ripper", program="/RIPPER.LE", port=9000, fetch=fetch
    )


def initialized_service(
    tmp_path: Path,
) -> tuple[CoverageService, CoveragePaths, Path, dict[str, Any]]:
    repository = repository_fixture(tmp_path)
    manager_paths = ManagerPaths(tmp_path / "manager")
    service = CoverageService(manager_paths)
    profile = service.init(
        repository=repository,
        profile_path=None,
        adapter="scummvm",
        project="ripper",
        program="/RIPPER.LE",
        scope="engines/ripper",
        architecture="RIPPER-ARCHITECTURE.md",
    )
    paths = CoveragePaths.from_profile(profile)
    snapshot = snapshot_fixture(tmp_path)
    write_canonical(
        paths.snapshots / f"{snapshot['snapshot_id'].removeprefix('sha256:')}.json",
        snapshot,
    )
    return service, paths, repository, snapshot


def test_init_uses_locally_ignored_reports_coverage(tmp_path: Path) -> None:
    service, paths, repository, _snapshot = initialized_service(tmp_path)

    assert paths.root == repository / "reports" / "coverage"
    assert paths.profile.is_file()
    assert paths.ledger.is_file()
    assert (
        subprocess.run(
            [
                "git",
                "-C",
                str(repository),
                "check-ignore",
                "-q",
                "reports/coverage/profile.json",
            ],
            check=False,
        ).returncode
        == 0
    )
    assert service.validate(paths.profile) == []


def test_offline_scan_apply_and_report_preserve_ledger(tmp_path: Path) -> None:
    service, paths, _repository, snapshot = initialized_service(tmp_path)
    ledger_before = paths.ledger.read_bytes()

    plan = service.scan(
        paths.profile,
        offline_snapshot=str(snapshot["snapshot_id"]),
        allow_dirty=False,
    )

    assert paths.ledger.read_bytes() == ledger_before
    assert load_json(paths.profile)["active"] == {"snapshot": None, "evidence": None}
    assert load_json(plan)["policy"]["mutates_reviewed_ledger"] is False

    service.apply(plan)

    profile = load_json(paths.profile)
    assert profile["active"]["snapshot"] == snapshot["snapshot_id"]
    assert paths.ledger.read_bytes() == ledger_before
    evidence = load_json(
        paths.evidence
        / f"{str(profile['active']['evidence']).removeprefix('sha256:')}.json"
    )
    assert len(evidence["behavioral_units"]) == 13
    assert any(
        unit["id"] == "scummvm-ripper:scene-action:12"
        for unit in evidence["behavioral_units"]
    )
    assert any(
        unit["id"] == "scummvm-ripper:scenario:save-restore"
        for unit in evidence["behavioral_units"]
    )
    save_restore = next(
        unit
        for unit in evidence["behavioral_units"]
        if unit["id"] == "scummvm-ripper:scenario:save-restore"
    )
    assert save_restore["subsystem"] == "save-restore"
    assert any(fact["kind"] == "commit_anchor" for fact in evidence["facts"])
    assert any(fact["kind"] == "architecture_anchor" for fact in evidence["facts"])
    assert all(
        fact["source"].get("patch_fingerprint")
        for fact in evidence["facts"]
        if fact["kind"] == "commit_anchor"
    )

    function_id = snapshot["functions"][0]["id"]
    evidence_id = next(
        fact["id"] for fact in evidence["facts"] if fact["original_targets"]
    )
    ledger = load_json(paths.ledger)
    ledger["records"] = [
        {
            "id": function_id,
            "kind": "function",
            "scope": {"state": "in_scope", "category": "game_logic"},
            "status": "unknown",
            "verification": {"state": "unverified", "records": []},
            "evidence": [evidence_id],
            "reachability": "unknown",
        }
    ]
    write_canonical(paths.ledger, ledger)

    json_path, markdown_path = service.report(
        paths.profile, json_path=None, markdown_path=None
    )

    assert json.loads(json_path.read_text())["metrics"]["function_traceability"]["ratio"] == 1.0
    assert "Conservative implementation coverage" in markdown_path.read_text()


def test_apply_rejects_changed_reviewed_ledger(tmp_path: Path) -> None:
    service, paths, _repository, snapshot = initialized_service(tmp_path)
    plan = service.scan(
        paths.profile,
        offline_snapshot=str(snapshot["snapshot_id"]),
        allow_dirty=False,
    )
    ledger = load_json(paths.ledger)
    ledger["records"] = []
    ledger["review_note"] = "changed"
    write_canonical(paths.ledger, ledger)

    with pytest.raises(ManagerError, match="ledger changed"):
        service.apply(plan)


def test_scan_refuses_dirty_repository_unless_fingerprinted(tmp_path: Path) -> None:
    service, paths, repository, snapshot = initialized_service(tmp_path)
    source = repository / "engines" / "ripper" / "script.h"
    source.write_text(source.read_text() + "\n// dirty\n", encoding="utf-8")

    with pytest.raises(ManagerError, match="repository is dirty"):
        service.scan(
            paths.profile,
            offline_snapshot=str(snapshot["snapshot_id"]),
            allow_dirty=False,
        )

    plan = service.scan(
        paths.profile,
        offline_snapshot=str(snapshot["snapshot_id"]),
        allow_dirty=True,
    )

    assert load_json(plan)["preconditions"]["repository"]["dirty"] is True


def test_seed_plan_populates_unreviewed_records_and_review_queue(tmp_path: Path) -> None:
    service, paths, _repository, snapshot = initialized_service(tmp_path)
    scan_plan = service.scan(
        paths.profile,
        offline_snapshot=str(snapshot["snapshot_id"]),
        allow_dirty=False,
    )
    service.apply(scan_plan)
    ledger_before = paths.ledger.read_bytes()

    seed_plan = service.seed(paths.profile)

    assert paths.ledger.read_bytes() == ledger_before
    plan = load_json(seed_plan)
    assert plan["plan_type"] == "ledger_seed"
    assert plan["summary"]["added_records"] == 14
    assert plan["policy"]["preserves_reviewed_records"] is True

    service.apply(seed_plan)

    ledger = load_json(paths.ledger)
    assert len(ledger["records"]) == 14
    assert all(record["status"] == "unknown" for record in ledger["records"])
    assert all(
        record["scope"]["state"] == "unreviewed" for record in ledger["records"]
    )
    function = next(
        record for record in ledger["records"] if record["kind"] == "function"
    )
    assert function["evidence"]
    queue = load_json(paths.review_queue)
    assert len(queue["candidates"]) == 14
    assert all(
        candidate["suggested_status"] in {"unknown", "partial"}
        for candidate in queue["candidates"]
    )
    assert service.validate(paths.profile) == []


def test_seed_preserves_reviewed_record_fields(tmp_path: Path) -> None:
    service, paths, _repository, snapshot = initialized_service(tmp_path)
    scan_plan = service.scan(
        paths.profile,
        offline_snapshot=str(snapshot["snapshot_id"]),
        allow_dirty=False,
    )
    service.apply(scan_plan)
    first_seed = service.seed(paths.profile)
    service.apply(first_seed)
    ledger = load_json(paths.ledger)
    function = next(
        record for record in ledger["records"] if record["kind"] == "function"
    )
    function["scope"] = {"state": "in_scope", "category": "game_logic"}
    function["status"] = "complete"
    function["notes"] = "human-reviewed"
    function["known_missing"] = []
    write_canonical(paths.ledger, ledger)

    second_seed = service.seed(paths.profile)
    service.apply(second_seed)

    updated = load_json(paths.ledger)
    reviewed = next(
        record for record in updated["records"] if record["id"] == function["id"]
    )
    assert reviewed["scope"] == {"state": "in_scope", "category": "game_logic"}
    assert reviewed["status"] == "complete"
    assert reviewed["notes"] == "human-reviewed"
    queue = load_json(paths.review_queue)
    assert function["id"] not in {
        candidate["record_id"] for candidate in queue["candidates"]
    }


def test_seed_apply_rejects_ledger_changes_after_plan_creation(tmp_path: Path) -> None:
    service, paths, _repository, snapshot = initialized_service(tmp_path)
    scan_plan = service.scan(
        paths.profile,
        offline_snapshot=str(snapshot["snapshot_id"]),
        allow_dirty=False,
    )
    service.apply(scan_plan)
    seed_plan = service.seed(paths.profile)
    ledger = load_json(paths.ledger)
    ledger["review_note"] = "changed after seed"
    write_canonical(paths.ledger, ledger)

    with pytest.raises(ManagerError, match="ledger changed since plan creation"):
        service.apply(seed_plan)
