import pytest

from ghidra_manager.campaign.budget import admission, load, operate, summary
from ghidra_manager.errors import ManagerError


def record(root, counter, identifier, **extra):
    return operate(
        root,
        "record",
        source="goal",
        stream="root",
        counter=counter,
        measurement=identifier,
        scope=["root"],
        **extra,
    )


def test_baselines_adjustments_and_idempotency(tmp_path):
    assert operate(tmp_path, "show")["used"] is None
    operate(tmp_path, "start")
    record(tmp_path, 2_000_000, "baseline")
    result = record(tmp_path, 2_080_000, "second")
    assert result["used"] == 80_000
    assert result["status"] == "warning"
    assert record(tmp_path, 2_080_000, "second") == result
    operate(tmp_path, "set", tokens=50_000)
    assert summary(load(tmp_path))["overshoot"] == 30_000
    operate(tmp_path, "finish")
    operate(tmp_path, "start", tokens=100_000)
    assert operate(tmp_path, "show")["used"] is None
    assert operate(tmp_path, "show")["campaign_measured_tokens"] == 80_000


def test_bad_measurements_leave_ledger_unchanged(tmp_path):
    operate(tmp_path, "start")
    record(tmp_path, 100, "first")
    before = (tmp_path / "budget.json").read_bytes()
    for counter, identifier in [(99, "second"), (101, "first")]:
        with pytest.raises(ManagerError):
            record(tmp_path, counter, identifier)
    with pytest.raises(ManagerError, match="overlap"):
        operate(
            tmp_path,
            "record",
            source="other",
            stream="all",
            counter=100,
            measurement="overlap",
            scope=["root", "worker"],
        )
    with pytest.raises(ManagerError, match="Finish"):
        operate(tmp_path, "start")
    assert (tmp_path / "budget.json").read_bytes() == before


def test_exhaustion_blocks_analysis_but_not_closure(tmp_path):
    assert not admission(tmp_path)["admitted"]
    operate(tmp_path, "start", tokens=100)
    record(tmp_path, 1000, "baseline")
    assert admission(tmp_path)["admitted"]
    record(tmp_path, 1100, "exhausted")
    assert not admission(tmp_path)["admitted"]
    for purpose in ["verify", "recover", "save"]:
        assert admission(tmp_path, purpose=purpose)["admitted"]
    operate(tmp_path, "set", tokens=150)
    assert admission(tmp_path)["admitted"]
