import io
import json
import zipfile
from pathlib import Path

import pytest

from ghidra_manager.config import ManagerPaths
from ghidra_manager.errors import ManagerError
from ghidra_manager.models import ManagerState, PairMetadata
from ghidra_manager.storage import StateStore, safe_extract


def _legacy_pair(paths: ManagerPaths, name: str) -> Path:
    pair = paths.pairs / name
    pair.mkdir(parents=True)
    (pair / "metadata").write_text(
        "ghidra_version=12.1.2\n"
        "mcp_version=5.14.2\n"
        "ghidra_tag=Ghidra_12.1.2_build\n"
        "mcp_tag=v5.14.2\n",
        encoding="utf-8",
    )
    return pair


def test_legacy_links_migrate_to_json_without_removal(tmp_path: Path) -> None:
    paths = ManagerPaths(tmp_path)
    current = _legacy_pair(paths, "ghidra-12.1.2__mcp-5.14.2")
    (paths.home / "current").symlink_to(current, target_is_directory=True)

    state = StateStore(paths).load()

    assert state == ManagerState(current=current.name)
    assert (paths.home / "current").is_symlink()
    assert json.loads(paths.state.read_text(encoding="utf-8")) == {
        "current": current.name,
        "previous": None,
        "schema_version": 1,
    }


def test_json_pair_round_trip(tmp_path: Path) -> None:
    store = StateStore(ManagerPaths(tmp_path))
    pair = PairMetadata(
        pair_id="pair",
        ghidra_version="12.1.2",
        mcp_version="5.14.2",
        ghidra_tag="Ghidra_12.1.2_build",
        mcp_tag="v5.14.2",
    )

    store.save_pair(pair)
    store.save(ManagerState(current=pair.pair_id))

    assert store.load() == ManagerState(current="pair")
    assert store.pair("pair") == pair


def test_unknown_state_schema_is_rejected(tmp_path: Path) -> None:
    paths = ManagerPaths(tmp_path)
    paths.state.write_text(
        '{"schema_version": 2, "current": null, "previous": null}', encoding="utf-8"
    )

    with pytest.raises(ManagerError, match="Unsupported manager state schema"):
        StateStore(paths).load()


def test_safe_extract_rejects_path_traversal(tmp_path: Path) -> None:
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w") as archive:
        archive.writestr("../escape", "bad")
    path = tmp_path / "bad.zip"
    path.write_bytes(payload.getvalue())

    with pytest.raises(ManagerError, match="escapes destination"):
        safe_extract(path, tmp_path / "output")

    assert not (tmp_path / "escape").exists()
