import hashlib
from pathlib import Path
from typing import Any

from ghidra_manager.coverage.inventory import build_snapshot


def test_snapshot_records_unavailable_optional_fields_and_is_deterministic(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "GAME.EXE"
    executable.write_bytes(b"game binary")

    def fetch(port: int, path: str, params: object) -> object | None:
        assert port == 9000
        if path == "/get_current_program_info":
            return {
                "name": "GAME.EXE",
                "executable_path": str(executable),
                "format": "Portable Executable",
                "language": "x86:LE:32:default",
                "compiler": "windows",
                "image_base": "00400000",
            }
        if path == "/get_metadata":
            return {"data": {"format": "Portable Executable"}}
        if path == "/get_address_spaces":
            return {"spaces": [{"name": "ram", "kind": "memory"}]}
        if path == "/get_bulk_function_hashes":
            typed = params
            assert isinstance(typed, dict)
            if typed["offset"] == "0":
                return {
                    "functions": [
                        {
                            "name": "Entry",
                            "address": "00401000",
                            "instruction_count": 4,
                            "hash": "abc",
                        }
                    ],
                    "total_matching": 1,
                }
        return None

    first = build_snapshot(
        project="demo", program="/GAME.EXE", port=9000, fetch=fetch
    )
    second = build_snapshot(
        project="demo", program="/GAME.EXE", port=9000, fetch=fetch
    )

    assert first == second
    assert first["program"]["binary_sha256"] == (
        f"sha256:{hashlib.sha256(b'game binary').hexdigest()}"
    )
    assert first["functions"][0]["id"].endswith(":ram:00401000")
    assert first["availability"]["call_graph"] is False
    assert first["availability"]["namespace"] is False


def test_snapshot_preserves_overlay_function_addresses(tmp_path: Path) -> None:
    executable = tmp_path / "GAME.LE"
    executable.write_bytes(b"linear executable")

    def fetch(port: int, path: str, params: object) -> object | None:
        values: dict[str, Any] = {
            "/get_current_program_info": {
                "executable_path": str(executable),
                "language": "x86:LE:32:default",
            },
            "/get_metadata": {},
            "/get_address_spaces": {
                "spaces": [
                    {"name": "ram", "kind": "memory"},
                    {"name": ".image", "kind": "overlay", "overlay_of": "ram"},
                ]
            },
            "/get_bulk_function_hashes": {
                "functions": [{"name": "Overlay", "address": ".image::00001000"}],
                "total": 1,
            },
        }
        return values.get(path)

    snapshot = build_snapshot(
        project="demo", program="/GAME.LE", port=9000, fetch=fetch
    )

    assert snapshot["functions"][0]["address"]["space"] == ".image"
    assert snapshot["functions"][0]["id"].endswith(":.image:00001000")


def test_snapshot_parses_plain_text_entry_points_and_call_graph(tmp_path: Path) -> None:
    executable = tmp_path / "GAME.EXE"
    executable.write_bytes(b"call graph")

    def fetch(port: int, path: str, params: object) -> object | None:
        values: dict[str, Any] = {
            "/get_current_program_info": {
                "executable_path": str(executable),
                "language": "x86:LE:32:default",
            },
            "/get_metadata": {},
            "/get_address_spaces": {
                "spaces": [{"name": "ram", "kind": "memory"}]
            },
            "/get_bulk_function_hashes": {
                "functions": [
                    {"name": "Entry", "address": "00001000"},
                    {"name": "Callee", "address": "00002000"},
                ],
                "total_matching": 2,
            },
            "/get_entry_points": "_entry @ 00001000 [Function] (0 params)\n",
            "/get_full_call_graph": "Entry@00001000 -> Callee@00002000\n",
        }
        return values.get(path)

    snapshot = build_snapshot(
        project="demo", program="/GAME.EXE", port=9000, fetch=fetch
    )

    assert snapshot["availability"]["entry_points"] is True
    assert snapshot["availability"]["call_graph"] is True
    assert snapshot["entry_points"][0]["name"] == "_entry"
    assert snapshot["call_graph"][0]["kind"] == "direct_static"
    assert snapshot["call_graph"][0]["caller"].endswith(":ram:00001000")
    assert snapshot["call_graph"][0]["callee"].endswith(":ram:00002000")
