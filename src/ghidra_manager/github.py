"""Minimal authenticated GitHub release client."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from collections.abc import Mapping
from pathlib import Path

from ghidra_manager.errors import ManagerError


class GitHubClient:
    def __init__(
        self,
        *,
        environ: Mapping[str, str] | None = None,
        api_url: str = "https://api.github.com",
    ):
        environ = environ or os.environ
        self.token = environ.get("GH_TOKEN") or environ.get("GITHUB_TOKEN")
        self.api_url = api_url.rstrip("/")

    def _headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "ghidra-manager",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def get_json(self, endpoint: str) -> object:
        request = urllib.request.Request(
            f"{self.api_url}/{endpoint.lstrip('/')}", headers=self._headers()
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                value: object = json.load(response)
                return value
        except (OSError, ValueError, urllib.error.URLError) as exc:
            raise ManagerError(f"GitHub API request failed: {endpoint}: {exc}") from exc

    def download(self, url: str, destination: Path) -> None:
        request = urllib.request.Request(url, headers=self._headers())
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                destination.write_bytes(response.read())
        except (OSError, urllib.error.URLError) as exc:
            raise ManagerError(f"Download failed: {url}: {exc}") from exc
