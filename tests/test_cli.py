from pathlib import Path

from ghidra_manager import cli
from ghidra_manager.mcp import Instance


def test_instances_output(monkeypatch, capsys) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(
        cli,
        "discover_instances",
        lambda port: [Instance(port=port, pid=123, project="demo")],
    )

    assert cli.run(["instances", "--base-port", "9000"]) == 0
    assert capsys.readouterr().out == (
        "MCP port 9000 | PID 123 | project demo | http://127.0.0.1:9000\n"
    )


def test_no_arguments_defaults_to_sync(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    class FakeManager:
        def sync(self, *, dry_run: bool) -> list[str]:
            assert not dry_run
            return []

    monkeypatch.setattr(cli.Manager, "discover", lambda: FakeManager())

    assert cli.run([]) == 0


def test_help_command(capsys) -> None:  # type: ignore[no-untyped-def]
    assert cli.run(["help"]) == 0
    assert "Manage compatible Ghidra and GhidraMCP releases." in capsys.readouterr().out


def test_instances_empty_state(monkeypatch, capsys) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(cli, "discover_instances", lambda port: [])

    assert cli.run(["instances"]) == 1
    assert capsys.readouterr().out == (
        "No GhidraMCP instances found on ports 8089-8104.\n"
    )


def test_status_output(monkeypatch, capsys) -> None:  # type: ignore[no-untyped-def]
    class FakeManager:
        def status_lines(self) -> list[str]:
            return ["Active pair:        not installed", "Upstream Ghidra:    12.2"]

    monkeypatch.setattr(cli.Manager, "discover", lambda: FakeManager())

    assert cli.run(["status"]) == 0
    assert capsys.readouterr().out == (
        "Active pair:        not installed\nUpstream Ghidra:    12.2\n"
    )


def test_sync_output(monkeypatch, capsys) -> None:  # type: ignore[no-untyped-def]
    class FakeManager:
        def sync(self, *, dry_run: bool = False) -> list[str]:
            assert dry_run
            return ["Resolving stable upstream releases...", "Dry run: already current."]

    monkeypatch.setattr(cli.Manager, "discover", lambda: FakeManager())

    assert cli.run(["sync", "--dry-run"]) == 0
    assert capsys.readouterr().out == (
        "Resolving stable upstream releases...\nDry run: already current.\n"
    )


def test_rollback_output(monkeypatch, capsys) -> None:  # type: ignore[no-untyped-def]
    class FakeManager:
        def rollback(self) -> list[str]:
            return ["Rolled back."]

    monkeypatch.setattr(cli.Manager, "discover", lambda: FakeManager())

    assert cli.run(["rollback"]) == 0
    assert capsys.readouterr().out == "Rolled back.\n"


def test_projects_output(monkeypatch, capsys) -> None:  # type: ignore[no-untyped-def]
    class FakeManager:
        def projects(self, *, base_port: int) -> list[str]:
            assert base_port == 8089
            return ["Projects known to Ghidra 12.1.2:", "demo"]

    monkeypatch.setattr(cli.Manager, "discover", lambda: FakeManager())

    assert cli.run(["projects"]) == 0
    assert capsys.readouterr().out == "Projects known to Ghidra 12.1.2:\ndemo\n"


def test_launch_forwards_arguments(monkeypatch, capsys) -> None:  # type: ignore[no-untyped-def]
    class FakeManager:
        def launch(self, arguments: list[str]) -> tuple[str, int]:
            assert arguments == ["demo.gpr", "--flag"]
            return "Launching Ghidra 12.1.2 with JDK 21...", 0

    monkeypatch.setattr(cli.Manager, "discover", lambda: FakeManager())

    assert cli.run(["launch", "demo.gpr", "--flag"]) == 0
    assert capsys.readouterr().out == "Launching Ghidra 12.1.2 with JDK 21...\n"


def test_launch_multi_options(monkeypatch, capsys) -> None:  # type: ignore[no-untyped-def]
    class FakeManager:
        def launch_multi(
            self,
            projects: list[str],
            *,
            count: int | None,
            timeout: int,
            base_port: int,
        ) -> list[str]:
            assert (projects, count, timeout, base_port) == ([], 2, 30, 9000)
            return ["GhidraMCP instances ready:"]

    monkeypatch.setattr(cli.Manager, "discover", lambda: FakeManager())

    assert cli.run(
        ["launch-multi", "--count", "2", "--timeout", "30", "--base-port", "9000"]
    ) == 0
    assert capsys.readouterr().out == "GhidraMCP instances ready:\n"


def test_bridge_forwards_arguments(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    class FakeManager:
        def bridge(self, arguments: list[str]) -> int:
            assert arguments == ["--help"]
            return 0

    monkeypatch.setattr(cli.Manager, "discover", lambda: FakeManager())

    assert cli.run(["bridge", "--help"]) == 0


def test_compare_arguments(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    class FakeManager:
        def compare(self, source: str, target: str, *, base_port: int) -> int:
            assert (source, target, base_port) == ("source", "target", 9000)
            return 0

    monkeypatch.setattr(cli.Manager, "discover", lambda: FakeManager())

    assert cli.run(["compare", "--base-port", "9000", "source", "target"]) == 0


def test_compare_apply_argument(monkeypatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    plan = tmp_path / "plan.json"

    class FakeManager:
        def compare_apply(self, value: Path) -> int:
            assert value == plan
            return 0

    monkeypatch.setattr(cli.Manager, "discover", lambda: FakeManager())

    assert cli.run(["compare", "--apply", str(plan)]) == 0
