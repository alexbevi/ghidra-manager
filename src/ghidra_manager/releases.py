"""Resolve the newest stable compatible Ghidra and GhidraMCP pair."""

from __future__ import annotations

import hashlib
import re
import tempfile
import zipfile
from pathlib import Path
from typing import Protocol

from ghidra_manager.errors import ManagerError
from ghidra_manager.models import ReleaseAsset, ResolvedPair
from ghidra_manager.storage import parse_properties

GHIDRA_REPOSITORY = "NationalSecurityAgency/ghidra"
MCP_REPOSITORY = "bethington/ghidra-mcp"


class ReleaseClient(Protocol):
    def get_json(self, endpoint: str) -> object: ...

    def download(self, url: str, destination: Path) -> None: ...


def _release(value: object, description: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ManagerError(f"GitHub returned invalid {description} release metadata")
    return value


def _asset(release: dict[str, object], pattern: str) -> ReleaseAsset:
    assets = release.get("assets")
    if not isinstance(assets, list):
        raise ManagerError("GitHub release has no asset list")
    matches = [
        item
        for item in assets
        if isinstance(item, dict) and re.search(pattern, str(item.get("name", "")))
    ]
    if len(matches) != 1:
        raise ManagerError(f"Expected one release asset matching: {pattern}")
    item = matches[0]
    digest = item.get("digest")
    if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-fA-F]{64}", digest):
        raise ManagerError(f"Release asset has no usable SHA-256 digest: {item.get('name')}")
    try:
        return ReleaseAsset(
            name=str(item["name"]),
            url=str(item["browser_download_url"]),
            digest=digest,
        )
    except KeyError as exc:
        raise ManagerError("Release asset metadata is incomplete") from exc


def verify_digest(path: Path, digest: str) -> None:
    expected = digest.removeprefix("sha256:").lower()
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != expected:
        raise ManagerError(f"SHA-256 mismatch for {path.name}")


def extension_properties(archive: Path) -> dict[str, str]:
    try:
        with zipfile.ZipFile(archive) as bundle:
            text = bundle.read("GhidraMCP/extension.properties").decode("utf-8")
    except (OSError, KeyError, UnicodeError, zipfile.BadZipFile) as exc:
        raise ManagerError(f"Invalid GhidraMCP extension archive: {archive.name}") from exc
    return parse_properties(text)


def resolve_pair(client: ReleaseClient) -> ResolvedPair:
    mcp_release = _release(
        client.get_json(f"repos/{MCP_REPOSITORY}/releases/latest"), "GhidraMCP"
    )
    mcp_tag = str(mcp_release.get("tag_name", ""))
    if not mcp_tag:
        raise ManagerError("GhidraMCP release has no tag")
    mcp_version = mcp_tag.removeprefix("v")
    extension = _asset(mcp_release, r"^GhidraMCP-[0-9].*\.zip$")
    bridge = _asset(mcp_release, r"^bridge_mcp_ghidra\.py$")
    requirements = _asset(mcp_release, r"^requirements\.txt$")

    with tempfile.TemporaryDirectory(prefix="ghidra-manager-resolve-") as temporary:
        extension_path = Path(temporary) / extension.name
        client.download(extension.url, extension_path)
        verify_digest(extension_path, extension.digest)
        properties = extension_properties(extension_path)

    if properties.get("name") != "GhidraMCP":
        raise ManagerError(f"Unexpected extension name in {extension.name}")
    version_match = re.search(r"Plugin version ([0-9.]+)\.", properties.get("description", ""))
    if version_match is None or version_match.group(1) != mcp_version:
        raise ManagerError("MCP release tag and extension metadata do not match")
    ghidra_version = properties.get("version")
    if not ghidra_version:
        raise ManagerError("GhidraMCP extension declares no Ghidra version")
    ghidra_tag = f"Ghidra_{ghidra_version}_build"
    ghidra_release = _release(
        client.get_json(f"repos/{GHIDRA_REPOSITORY}/releases/tags/{ghidra_tag}"),
        "compatible Ghidra",
    )
    escaped_version = re.escape(ghidra_version)
    ghidra_asset = _asset(
        ghidra_release, rf"^ghidra_{escaped_version}_PUBLIC_[0-9]+\.zip$"
    )
    latest_release = _release(
        client.get_json(f"repos/{GHIDRA_REPOSITORY}/releases/latest"), "latest Ghidra"
    )
    latest_name = str(latest_release.get("name", ""))
    if not latest_name.startswith("Ghidra "):
        raise ManagerError("Latest Ghidra release has an unexpected name")
    return ResolvedPair(
        ghidra_version=ghidra_version,
        ghidra_latest_version=latest_name.removeprefix("Ghidra "),
        ghidra_tag=ghidra_tag,
        ghidra_asset=ghidra_asset,
        mcp_version=mcp_version,
        mcp_tag=mcp_tag,
        mcp_extension=extension,
        mcp_bridge=bridge,
        mcp_requirements=requirements,
    )
