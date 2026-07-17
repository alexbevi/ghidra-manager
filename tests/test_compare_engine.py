import json
from pathlib import Path

import pytest

from ghidra_manager import compare


def test_apply_rejects_stale_target_identity(monkeypatch, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    plan = tmp_path / "plan.json"
    plan.write_text(
        json.dumps(
            {
                "schema": "ghidra-manager-compare-plan",
                "version": 1,
                "target": {"port": 8090, "pid": 100, "project": "target"},
                "operations": [],
            }
        ),
        encoding="utf-8",
    )
    compare.plan_version = 1
    compare.engine_arguments = [str(plan)]
    monkeypatch.setattr(
        compare,
        "instance_info",
        lambda _port: {"pid": 101, "project": "different-target"},
    )

    with pytest.raises(compare.CompareError, match="Target instance identity changed"):
        compare.apply_plan()
