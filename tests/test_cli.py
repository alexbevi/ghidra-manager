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


def test_instances_empty_state(monkeypatch, capsys) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(cli, "discover_instances", lambda port: [])

    assert cli.run(["instances"]) == 1
    assert capsys.readouterr().out == (
        "No GhidraMCP instances found on ports 8089-8104.\n"
    )
