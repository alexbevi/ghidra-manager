import hashlib
import io
import zipfile
from pathlib import Path

import pytest

from ghidra_manager.errors import ManagerError
from ghidra_manager.releases import resolve_ghidra, resolve_pair, verify_digest


def _extension() -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr(
            "GhidraMCP/extension.properties",
            "name=GhidraMCP\ndescription=Ghidra MCP Plugin version 5.14.2.\nversion=12.1.2\n",
        )
    return output.getvalue()


def _asset(name: str, content: bytes) -> dict[str, str]:
    return {
        "name": name,
        "browser_download_url": f"https://download.test/{name}",
        "digest": f"sha256:{hashlib.sha256(content).hexdigest()}",
    }


class FakeClient:
    def __init__(self) -> None:
        self.extension = _extension()
        empty = b"asset"
        self.responses: dict[str, object] = {
            "repos/bethington/ghidra-mcp/releases/latest": {
                "tag_name": "v5.14.2",
                "assets": [
                    _asset("GhidraMCP-5.14.2.zip", self.extension),
                    _asset("bridge_mcp_ghidra.py", empty),
                    _asset("requirements.txt", empty),
                ],
            },
            "repos/NationalSecurityAgency/ghidra/releases/tags/Ghidra_12.1.2_build": {
                "assets": [_asset("ghidra_12.1.2_PUBLIC_20260623.zip", empty)]
            },
            "repos/NationalSecurityAgency/ghidra/releases/latest": {"name": "Ghidra 12.2"},
        }

    def get_json(self, endpoint: str) -> object:
        return self.responses[endpoint]

    def download(self, url: str, destination: Path) -> None:
        destination.write_bytes(self.extension)


def test_resolve_compatible_pair() -> None:
    pair = resolve_pair(FakeClient())

    assert pair.pair_id == "ghidra-12.1.2__mcp-5.14.2"
    assert pair.ghidra_version == "12.1.2"
    assert pair.ghidra_latest_version == "12.2"


def test_resolve_latest_ghidra_directly() -> None:
    client = FakeClient()
    client.responses["repos/NationalSecurityAgency/ghidra/releases/latest"] = {
        "name": "Ghidra 12.1.2",
        "tag_name": "Ghidra_12.1.2_build",
        "assets": [_asset("ghidra_12.1.2_PUBLIC_20260623.zip", b"asset")],
    }

    resolved = resolve_ghidra(client)

    assert resolved.version == "12.1.2"
    assert resolved.tag == "Ghidra_12.1.2_build"


def test_digest_mismatch(tmp_path: Path) -> None:
    path = tmp_path / "asset"
    path.write_bytes(b"wrong")

    with pytest.raises(ManagerError, match="SHA-256 mismatch"):
        verify_digest(path, f"sha256:{'0' * 64}")


def test_missing_github_digest_is_rejected() -> None:
    client = FakeClient()
    release = client.responses["repos/bethington/ghidra-mcp/releases/latest"]
    assert isinstance(release, dict)
    assets = release["assets"]
    assert isinstance(assets, list)
    assert isinstance(assets[0], dict)
    assets[0].pop("digest")

    with pytest.raises(ManagerError, match="no usable SHA-256 digest"):
        resolve_pair(client)
