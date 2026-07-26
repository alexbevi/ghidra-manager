"""Generic evidence collection and the initial ScummVM adapter."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from ghidra_manager.coverage.adapters.scummvm import scenario_units
from ghidra_manager.coverage.model import (
    EVIDENCE_SCHEMA,
    SCHEMA_VERSION,
    Address,
    with_content_id,
)
from ghidra_manager.coverage.repository import git, repository_identity

ANCHOR_RE = re.compile(
    r"`?\b(?P<name>[A-Za-z_][A-Za-z0-9_:~]*)`?\s*(?:at|@)\s*`?"
    r"(?P<address>(?:[A-Za-z_.][A-Za-z0-9_.]*::)?0x[0-9a-fA-F]+)\b`?"
)
ENUM_RE = re.compile(
    r"enum\s+(?P<name>ScriptOpcode|SceneAction)\b[^{]*\{(?P<body>.*?)\};",
    re.DOTALL,
)
ENUM_ITEM_RE = re.compile(
    r"^\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"(?P<value>0x[0-9a-fA-F]+|\d+)",
    re.MULTILINE,
)
DIAGNOSTIC_RE = re.compile(r"\b(unsupported|unimplemented|not implemented|stub)\b", re.IGNORECASE)
ACTION_CASE_RE = re.compile(
    r'case\s+(?P<value>\d+)\s*:\s*return\s+"(?P<label>[^"]+)"\s*;'
)


def _fact(value: dict[str, Any]) -> dict[str, Any]:
    result = dict(value)
    result["id"] = f"evidence:{hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
    ).hexdigest()}"
    return result


def _address_index(snapshot: dict[str, Any]) -> dict[str, str]:
    result: dict[str, str] = {}
    spaces = {
        str(item["name"])
        for item in snapshot["program"].get("address_spaces", [])
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    }
    for function in snapshot.get("functions", []):
        if not isinstance(function, dict):
            continue
        address = function.get("address")
        if not isinstance(address, dict):
            continue
        try:
            parsed = Address.parse(
                str(address["display"]),
                default_space=str(address["space"]),
                known_spaces=spaces,
            )
        except (KeyError, TypeError):
            continue
        result[parsed.key] = str(function["id"])
    return result


def _targets(
    match: re.Match[str],
    address_index: dict[str, str],
    known_spaces: set[str],
) -> list[str]:
    address = Address.parse(match.group("address"), known_spaces=known_spaces)
    target = address_index.get(address.key)
    return [target] if target else []


def _source_files(repository: Path, scope: str, architecture: str | None) -> list[Path]:
    root = repository / scope
    files = (
        [
            path
            for path in root.rglob("*")
            if path.is_file() and path.suffix.lower() in {".cpp", ".c", ".h", ".hpp"}
        ]
        if root.is_dir()
        else []
    )
    if architecture:
        document = repository / architecture
        if document.is_file():
            files.append(document)
    return sorted(set(files))


def _commit_records(repository: Path, scope: str) -> list[tuple[str, str, str]]:
    output = str(
        git(
            repository,
            "log",
            "--format=%x1e%H%x1f%s%x1f%b",
            "HEAD",
            "--",
            scope,
        )
    )
    records: list[tuple[str, str, str]] = []
    for raw in output.split("\x1e"):
        record = raw.lstrip("\r\n")
        if not record:
            continue
        fields = record.split("\x1f", 2)
        if len(fields) == 3:
            records.append((fields[0], fields[1], fields[2].rstrip("\r\n")))
    return records


def collect_evidence(
    *,
    profile: dict[str, Any],
    snapshot: dict[str, Any],
    allow_dirty: bool,
) -> dict[str, Any]:
    repository = Path(str(profile["repository"]["root"])).resolve()
    scope = str(profile["repository"]["scope"])
    adapter_id = str(profile["adapter"]["id"])
    identity = repository_identity(repository, allow_dirty=allow_dirty)
    identity.pop("root", None)
    address_index = _address_index(snapshot)
    known_spaces = {
        str(item["name"])
        for item in snapshot["program"].get("address_spaces", [])
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    }
    facts: list[dict[str, Any]] = []
    for commit, subject, body in _commit_records(repository, scope):
        text = f"{subject}\n{body}"
        patch = git(
            repository,
            "show",
            "--format=",
            "--binary",
            commit,
            "--",
            scope,
            text=False,
        )
        assert isinstance(patch, bytes)
        patch_fingerprint = f"sha256:{hashlib.sha256(patch).hexdigest()}"
        changed = str(
            git(
                repository,
                "diff-tree",
                "--no-commit-id",
                "--name-only",
                "-r",
                commit,
                "--",
                scope,
            )
        ).splitlines()
        for match in ANCHOR_RE.finditer(text):
            targets = _targets(match, address_index, known_spaces)
            facts.append(
                _fact(
                    {
                        "kind": "commit_anchor",
                        "claim": "mapped" if targets else "mentioned",
                        "source": {
                            "commit": commit,
                            "patch_fingerprint": patch_fingerprint,
                            "subject": subject,
                            "anchor": match.group(0),
                        },
                        "original_targets": targets,
                        "unresolved_original": None
                        if targets
                        else {
                            "name": match.group("name"),
                            "address": match.group("address"),
                        },
                        "implementation_targets": [
                            {"path": path, "symbol": None} for path in sorted(changed)
                        ],
                        "context_only": False,
                    }
                )
            )
    behavioral_units: list[dict[str, Any]] = []
    if adapter_id == "scummvm":
        behavioral_units.extend(scenario_units(profile))
    architecture = profile["adapter"].get("architecture")
    for path in _source_files(
        repository, scope, str(architecture) if architecture else None
    ):
        relative = path.relative_to(repository).as_posix()
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        source_kind = "architecture_anchor" if relative == architecture else "source_anchor"
        for line_number, line in enumerate(text.splitlines(), 1):
            for match in ANCHOR_RE.finditer(line):
                targets = _targets(match, address_index, known_spaces)
                facts.append(
                    _fact(
                        {
                            "kind": source_kind,
                            "claim": "mapped" if targets else "mentioned",
                            "source": {
                                "path": relative,
                                "line": line_number,
                                "anchor": match.group(0),
                            },
                            "original_targets": targets,
                            "unresolved_original": None
                            if targets
                            else {
                                "name": match.group("name"),
                                "address": match.group("address"),
                            },
                            "implementation_targets": [
                                {"path": relative, "symbol": None}
                            ],
                            "context_only": source_kind == "architecture_anchor",
                        }
                    )
                )
            if source_kind != "architecture_anchor" and DIAGNOSTIC_RE.search(line):
                facts.append(
                    _fact(
                        {
                            "kind": "diagnostic",
                            "claim": "diagnostic",
                            "source": {
                                "path": relative,
                                "line": line_number,
                                "text": line.strip(),
                            },
                            "original_targets": [],
                            "implementation_targets": [
                                {"path": relative, "symbol": None}
                            ],
                            "context_only": False,
                        }
                    )
                )
        if adapter_id == "scummvm":
            for enum in ENUM_RE.finditer(text):
                registry = (
                    "script-opcode"
                    if enum.group("name") == "ScriptOpcode"
                    else "scene-action"
                )
                subsystem = "scripts" if registry == "script-opcode" else "scene-actions"
                for item in ENUM_ITEM_RE.finditer(enum.group("body")):
                    value = int(item.group("value"), 0)
                    behavioral_units.append(
                        {
                            "id": f"scummvm-ripper:{registry}:{value}",
                            "kind": "behavioral_unit",
                            "subsystem": subsystem,
                            "label": item.group("name"),
                            "provider": f"scummvm.{registry}s",
                            "source": {"path": relative, "value": value},
                        }
                    )
            if path.name == "scene_dispatcher.cpp":
                for action in ACTION_CASE_RE.finditer(text):
                    value = int(action.group("value"))
                    behavioral_units.append(
                        {
                            "id": f"scummvm-ripper:scene-action:{value}",
                            "kind": "behavioral_unit",
                            "subsystem": "scene-actions",
                            "label": action.group("label"),
                            "provider": "scummvm.scene-action-names",
                            "source": {"path": relative, "value": value},
                        }
                    )
    unique_facts = {str(item["id"]): item for item in facts}
    unique_units = {str(item["id"]): item for item in behavioral_units}
    evidence: dict[str, Any] = {
        "schema": EVIDENCE_SCHEMA,
        "version": SCHEMA_VERSION,
        "snapshot_id": snapshot["snapshot_id"],
        "repository": identity,
        "adapter": {
            "id": adapter_id,
            "version": profile["adapter"].get("version", 1),
        },
        "facts": [unique_facts[key] for key in sorted(unique_facts)],
        "behavioral_units": [unique_units[key] for key in sorted(unique_units)],
    }
    return with_content_id(evidence, "scan_id")
