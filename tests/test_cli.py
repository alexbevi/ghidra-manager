import json
from pathlib import Path

from ghidra_manager import cli
from ghidra_manager.instance_state import InstanceReport
from ghidra_manager.models import DoctorCheck


def test_instances_output(monkeypatch, capsys) -> None:  # type: ignore[no-untyped-def]
    class FakeManager:
        def instance_reports(self, base_port: int) -> list[InstanceReport]:
            assert base_port == 9000
            return [
                InstanceReport(
                    pid=123,
                    port=9000,
                    project="demo",
                    programs=("DEMO.EXE",),
                    url="http://127.0.0.1:9000",
                    owned=True,
                    health="ready",
                    log_path="/logs/demo.log",
                )
            ]

    monkeypatch.setattr(cli.Manager, "discover", lambda: FakeManager())

    assert cli.run(["instances", "--base-port", "9000"]) == 0
    assert capsys.readouterr().out == (
        "READY           | managed  | MCP port 9000 | PID 123 | project demo | "
        "programs DEMO.EXE | log /logs/demo.log\n"
    )


def test_no_arguments_show_help_without_discovery(monkeypatch, capsys) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(
        cli.Manager,
        "discover",
        lambda: (_ for _ in ()).throw(AssertionError("manager discovery must not run")),
    )
    assert cli.run([]) == 0
    assert "Manage compatible Ghidra and GhidraMCP releases." in capsys.readouterr().out


def test_help_command(capsys) -> None:  # type: ignore[no-untyped-def]
    assert cli.run(["help"]) == 0
    output = capsys.readouterr().out
    assert "Manage compatible Ghidra and GhidraMCP releases." in output
    assert "launch-multi        Compatibility alias; prefer open" in output
    assert "==SUPPRESS==" not in output


def test_instances_empty_state(monkeypatch, capsys) -> None:  # type: ignore[no-untyped-def]
    class FakeManager:
        def instance_reports(self, base_port: int) -> list[InstanceReport]:
            return []

    monkeypatch.setattr(cli.Manager, "discover", lambda: FakeManager())

    assert cli.run(["instances"]) == 1
    assert capsys.readouterr().out == ("No GhidraMCP instances found on ports 8089-8104.\n")


def test_instances_json(monkeypatch, capsys) -> None:  # type: ignore[no-untyped-def]
    class FakeManager:
        def instance_reports(self, base_port: int) -> list[InstanceReport]:
            return [
                InstanceReport(
                    pid=123,
                    port=base_port,
                    project="demo",
                    programs=("DEMO.EXE",),
                    url=f"http://127.0.0.1:{base_port}",
                    owned=False,
                    health="ready",
                )
            ]

    monkeypatch.setattr(cli.Manager, "discover", lambda: FakeManager())

    assert cli.run(["instances", "--json"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["instances"][0]["programs"] == ["DEMO.EXE"]
    assert output["instances"][0]["owned"] is False


def test_logs_tail(monkeypatch, capsys, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    log = tmp_path / "launch.log"
    log.write_text("one\ntwo\nthree\n", encoding="utf-8")

    class FakeManager:
        def instance_log(self, target: str | None) -> Path:
            assert target == "demo"
            return log

    monkeypatch.setattr(cli.Manager, "discover", lambda: FakeManager())

    assert cli.run(["logs", "demo", "--lines", "2"]) == 0
    assert capsys.readouterr().out == f"Log: {log}\ntwo\nthree\n"


def test_status_output(monkeypatch, capsys) -> None:  # type: ignore[no-untyped-def]
    class FakeManager:
        def status_lines(self) -> list[str]:
            return ["Active pair:        not installed", "Upstream Ghidra:    12.2"]

    monkeypatch.setattr(cli.Manager, "discover", lambda: FakeManager())

    assert cli.run(["status"]) == 0
    assert capsys.readouterr().out == (
        "Active pair:        not installed\nUpstream Ghidra:    12.2\n"
    )


def test_doctor_json_output(monkeypatch, capsys) -> None:  # type: ignore[no-untyped-def]
    class FakeManager:
        def doctor(
            self, project: str | None, *, program: str | None, base_port: int
        ) -> list[DoctorCheck]:
            assert (project, program, base_port) == ("demo", "DEMO.EXE", 9000)
            return [DoctorCheck("analysis", "ok", "DEMO.EXE analyzed")]

    monkeypatch.setattr(cli.Manager, "discover", lambda: FakeManager())

    assert (
        cli.run(["doctor", "demo", "--program", "DEMO.EXE", "--base-port", "9000", "--json"]) == 0
    )
    output = capsys.readouterr().out
    assert '"ready": true' in output
    assert '"name": "analysis"' in output


def test_doctor_errors_return_failure(monkeypatch, capsys) -> None:  # type: ignore[no-untyped-def]
    class FakeManager:
        def doctor(
            self, project: str | None, *, program: str | None, base_port: int
        ) -> list[DoctorCheck]:
            return [DoctorCheck("instance", "error", "not responding")]

    monkeypatch.setattr(cli.Manager, "discover", lambda: FakeManager())

    assert cli.run(["doctor"]) == 1
    assert "Doctor result: not ready" in capsys.readouterr().out


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


def test_plugins_discover_output(monkeypatch, capsys) -> None:  # type: ignore[no-untyped-def]
    class FakeManager:
        def plugin_discovery(self) -> list[dict[str, object]]:
            return [
                {
                    "id": "mcp",
                    "name": "GhidraMCP",
                    "selected": True,
                    "repository": "bethington/ghidra-mcp",
                }
            ]

    monkeypatch.setattr(cli.Manager, "discover", lambda: FakeManager())

    assert cli.run(["plugins", "discover"]) == 0
    assert capsys.readouterr().out == ("mcp | GhidraMCP | selected | bethington/ghidra-mcp\n")


def test_plugins_discover_json(monkeypatch, capsys) -> None:  # type: ignore[no-untyped-def]
    class FakeManager:
        def plugin_discovery(self) -> list[dict[str, object]]:
            return [{"id": "mcp", "selected": False}]

    monkeypatch.setattr(cli.Manager, "discover", lambda: FakeManager())

    assert cli.run(["plugins", "discover", "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == {"plugins": [{"id": "mcp", "selected": False}]}


def test_plugins_list_json(monkeypatch, capsys) -> None:  # type: ignore[no-untyped-def]
    class FakeManager:
        def plugin_list(self) -> dict[str, object]:
            return {
                "ghidra_version": "12.1.2",
                "plugins": [{"id": "mcp", "version": "5.14.2"}],
            }

    monkeypatch.setattr(cli.Manager, "discover", lambda: FakeManager())

    assert cli.run(["plugins", "list", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["plugins"][0]["id"] == "mcp"


def test_plugins_install_output(monkeypatch, capsys) -> None:  # type: ignore[no-untyped-def]
    class FakeManager:
        def plugin_install(self, plugin: str) -> list[str]:
            assert plugin == "ghidra-lx-loader"
            return ["Installed plugin ghidra-lx-loader 12.0.1 for Ghidra 12.1.2."]

    monkeypatch.setattr(cli.Manager, "discover", lambda: FakeManager())

    assert cli.run(["plugins", "install", "ghidra-lx-loader"]) == 0
    assert "Installed plugin ghidra-lx-loader" in capsys.readouterr().out


def test_plugins_remove_output(monkeypatch, capsys) -> None:  # type: ignore[no-untyped-def]
    class FakeManager:
        def plugin_remove(self, plugin: str) -> list[str]:
            assert plugin == "mcp"
            return ["Removed plugin mcp from Ghidra 12.1.2."]

    monkeypatch.setattr(cli.Manager, "discover", lambda: FakeManager())

    assert cli.run(["plugins", "remove", "mcp"]) == 0
    assert capsys.readouterr().out == "Removed plugin mcp from Ghidra 12.1.2.\n"


def test_launch_forwards_arguments(monkeypatch, capsys) -> None:  # type: ignore[no-untyped-def]
    class FakeManager:
        def launch(self, arguments: list[str]) -> tuple[str, int]:
            assert arguments == ["demo.gpr", "--flag"]
            return "Launching Ghidra 12.1.2 with JDK 21...", 0

    monkeypatch.setattr(cli.Manager, "discover", lambda: FakeManager())

    assert cli.run(["launch", "demo.gpr", "--flag"]) == 0
    assert capsys.readouterr().out == "Launching Ghidra 12.1.2 with JDK 21...\n"


def test_open_options(monkeypatch, capsys) -> None:  # type: ignore[no-untyped-def]
    class FakeManager:
        def open_projects(
            self,
            projects: list[str],
            *,
            program: str | None,
            timeout: int,
            base_port: int,
        ) -> list[str]:
            assert (projects, program, timeout, base_port) == (
                ["demo"],
                "DEMO.EXE",
                30,
                9000,
            )
            return ["GhidraMCP instance ready:"]

    monkeypatch.setattr(cli.Manager, "discover", lambda: FakeManager())

    assert (
        cli.run(
            [
                "open",
                "demo",
                "--program",
                "DEMO.EXE",
                "--timeout",
                "30",
                "--base-port",
                "9000",
            ]
        )
        == 0
    )
    assert capsys.readouterr().out == "GhidraMCP instance ready:\n"


def test_open_multiple_projects(monkeypatch, capsys) -> None:  # type: ignore[no-untyped-def]
    class FakeManager:
        def open_projects(
            self,
            projects: list[str],
            *,
            program: str | None,
            timeout: int,
            base_port: int,
        ) -> list[str]:
            assert (projects, program, timeout, base_port) == (
                ["first", "second"],
                None,
                30,
                9000,
            )
            return ["GhidraMCP instances ready:"]

    monkeypatch.setattr(cli.Manager, "discover", lambda: FakeManager())

    assert (
        cli.run(
            [
                "open",
                "first",
                "second",
                "--timeout",
                "30",
                "--base-port",
                "9000",
            ]
        )
        == 0
    )
    assert capsys.readouterr().out == "GhidraMCP instances ready:\n"


def test_stop_options(monkeypatch, capsys) -> None:  # type: ignore[no-untyped-def]
    class FakeManager:
        def stop_instance(
            self,
            target: str,
            *,
            timeout: int,
            force: bool,
            base_port: int,
        ) -> list[str]:
            assert (target, timeout, force, base_port) == ("123", 5, True, 9000)
            return ["Stopped Ghidra PID 123 for project demo."]

    monkeypatch.setattr(cli.Manager, "discover", lambda: FakeManager())

    assert (
        cli.run(["stop", "123", "--timeout", "5", "--force", "--base-port", "9000"]) == 0
    )
    assert capsys.readouterr().out == "Stopped Ghidra PID 123 for project demo.\n"


def test_restart_options(monkeypatch, capsys) -> None:  # type: ignore[no-untyped-def]
    class FakeManager:
        def restart_instance(
            self,
            target: str,
            *,
            program: str | None,
            timeout: int,
            stop_timeout: int,
            force: bool,
            base_port: int,
        ) -> list[str]:
            assert (target, program, timeout, stop_timeout, force, base_port) == (
                "demo",
                "DEMO.EXE",
                30,
                5,
                True,
                9000,
            )
            return ["GhidraMCP instance ready:"]

    monkeypatch.setattr(cli.Manager, "discover", lambda: FakeManager())

    assert (
        cli.run(
            [
                "restart",
                "demo",
                "--program",
                "DEMO.EXE",
                "--timeout",
                "30",
                "--stop-timeout",
                "5",
                "--force",
                "--base-port",
                "9000",
            ]
        )
        == 0
    )
    assert capsys.readouterr().out == "GhidraMCP instance ready:\n"


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

    assert cli.run(["launch-multi", "--count", "2", "--timeout", "30", "--base-port", "9000"]) == 0
    captured = capsys.readouterr()
    assert captured.out == "GhidraMCP instances ready:\n"
    assert "retained for compatibility" in captured.err


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
