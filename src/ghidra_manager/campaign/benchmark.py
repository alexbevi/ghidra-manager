"""Reproducible offline workload exercising the real diff and packet pipelines."""

from __future__ import annotations

import io
from contextlib import redirect_stdout
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from ghidra_manager.campaign import budget, init_project, metrics
from ghidra_manager.campaign.diffing import compare
from ghidra_manager.campaign.evidence import packet
from ghidra_manager.campaign.inventory import fingerprint
from ghidra_manager.campaign.transport import Client
from ghidra_manager.errors import ManagerError
from ghidra_manager.storage import atomic_json


class FixtureClient(Client):
    def __init__(self, snapshot: dict[str, Any]) -> None:
        super().__init__(1, "/fixture.exe")
        self.snapshot = snapshot
        self.decompiled = 0

    def script(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if name == "CampaignInventory":
            return deepcopy(self.snapshot)
        if name != "CampaignEvidence":
            raise ManagerError("Benchmark attempted a mutation")
        self.decompiled += len(arguments["addresses"])
        return {
            "complete": True,
            "functions": [
                {
                    "address": address,
                    "decompilation": "void fixture() {}",
                    "instructions": [],
                    "callers": [],
                }
                for address in arguments["addresses"]
            ],
        }


def run(root: Path) -> dict[str, Any]:
    snapshot: dict[str, Any] = {
        "schema_version": 1,
        "collector_version": 6,
        "complete": True,
        "identity": {
            "project": "fixture",
            "project_path": "/fixture.gpr",
            "program_path": "/fixture.exe",
            "digest": "synthetic",
            "language": "x86",
            "compiler": "windows",
            "format": "fixture",
            "image_base": "00400000",
        },
        "configuration": {},
        "types": [],
        "symbols": [],
        "strings": [],
        "functions": [
            {
                "address": f"{0x401000 + n * 16:08x}",
                "name": f"FUN_{n}",
                "callees": [],
                "variables": [],
                "abi": {},
                "byte_hash": str(n),
            }
            for n in range(1000)
        ],
    }
    after = deepcopy(snapshot)
    for function in after["functions"][:5]:
        function["name"] = "reviewed_" + function["address"]
    delta = compare(snapshot, after)
    with TemporaryDirectory(prefix="ghidra-campaign-benchmark-") as temporary:
        fixture = Path(temporary) / "campaign"
        with redirect_stdout(io.StringIO()):
            init_project.main(
                [
                    "--output",
                    str(fixture),
                    "--project",
                    "fixture",
                    "--program",
                    "fixture.exe",
                    "--program-path",
                    "/fixture.exe",
                ]
            )
        budget.operate(fixture, "start")
        budget.operate(
            fixture,
            "record",
            source="synthetic",
            stream="test",
            counter=0,
            scope=["fixture"],
            measurement="baseline",
        )
        client = FixtureClient(snapshot)
        addresses = [f["address"] for f in snapshot["functions"][:5]]
        first = packet(fixture, client, addresses)
        second = packet(fixture, client, addresses)
        result = {
            "schema_version": 1,
            "synthetic": True,
            "functions": 1000,
            "renamed_functions": len(delta["changed"]),
            "functions_requiring_native_audit_after_rename": len(delta["native_review"]),
            "first_packet_captures": first["captured"],
            "repeat_packet_captures": second["captured"],
            "repeat_cache_hits": second["cache_hits"],
            "total_fixture_decompilations": client.decompiled,
            "packet_bytes": second["bytes"],
            "local_work": metrics.report(fixture)["local_work"],
            "model_token_savings": None,
        }
    path = root / "artifacts" / "benchmarks" / (fingerprint(result) + ".json")
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_json(path, result)
    return {**result, "artifact": str(path)}
