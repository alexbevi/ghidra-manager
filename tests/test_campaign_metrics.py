from pathlib import Path

from ghidra_manager.campaign import benchmark, budget, metrics
from ghidra_manager.campaign.inventory import read
from ghidra_manager.storage import atomic_json
from tests.test_campaign_budget import record
from tests.test_campaign_cli import initialize


def test_metrics_distinguish_unknown_usage_and_measured_ratios(tmp_path):
    root = tmp_path / "campaign"
    initialize(root)
    assert metrics.report(root)["accepted_changes_per_1000_reported_tokens"] is None
    budget.operate(root, "start")
    record(root, 100, "baseline")
    record(root, 600, "batch")
    directory = root / "artifacts" / "batches" / "batch"
    directory.mkdir(parents=True)
    atomic_json(directory / "plan.json", {"changes": [{}, {}]})
    atomic_json(
        directory / "receipt.json", {"status": "saved", "plan_path": str(directory / "plan.json")}
    )
    report = metrics.report(root)
    assert report["accepted_changes"] == 2
    assert report["accepted_changes_per_1000_reported_tokens"] == 4
    assert report["budget"]["used"] == 500


def test_offline_benchmark_reuses_evidence_and_skips_rename_native_work(tmp_path):
    initialize(tmp_path / "campaign")
    result = benchmark.run(tmp_path / "campaign")
    assert result["functions"] == 1000
    assert result["renamed_functions"] == 5
    assert result["functions_requiring_native_audit_after_rename"] == 0
    assert result["total_fixture_decompilations"] == 5
    assert result["repeat_cache_hits"] == 5
    assert result["repeat_packet_captures"] == 0
    assert result["model_token_savings"] is None
    assert result["local_work"]["packet_requests"] == 2
    assert read(Path(result["artifact"]))["packet_bytes"] <= 32768
