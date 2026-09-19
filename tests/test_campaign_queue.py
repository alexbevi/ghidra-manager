import pytest

from ghidra_manager.campaign.budget import operate as budget
from ghidra_manager.campaign.queue import next_task, operate
from ghidra_manager.errors import ManagerError
from tests.test_campaign_budget import record


def test_order_dependencies_and_two_failure_deferral(tmp_path):
    budget(tmp_path, "start")
    record(tmp_path, 0, "baseline")
    operate(tmp_path, "add", "b", queue="naming", addresses=["b"])
    operate(tmp_path, "add", "a", queue="naming", addresses=["a"])
    operate(
        tmp_path, "add", "dependent", queue="naming", addresses=["c"], depends_on=["a"], priority=99
    )
    assert next_task(tmp_path)["task"]["id"] == "a"
    for _ in range(2):
        operate(tmp_path, "start", "a")
        operate(tmp_path, "fail", "a", reason="Ambiguous output storage")
    assert next_task(tmp_path)["task"]["id"] == "b"
    with pytest.raises(ManagerError, match="retry decision"):
        operate(tmp_path, "retry", "a")
    operate(tmp_path, "retry", "a", reason="New caller evidence")
    assert next_task(tmp_path)["task"]["id"] == "a"


def test_large_name_batch_rejected(tmp_path):
    with pytest.raises(ManagerError, match="ten"):
        operate(tmp_path, "add", "large", queue="naming", addresses=list(map(str, range(11))))
