"""Explicit-program, local MCP transport for bundled campaign collectors."""

from __future__ import annotations

import base64
import json
import urllib.parse
import urllib.request
from importlib.resources import files
from typing import Any

from ghidra_manager.errors import ManagerError


class Client:
    def __init__(self, port: int, program: str) -> None:
        if not 0 < port < 65536 or not program.startswith("/"):
            raise ManagerError("Require a valid local port and full Ghidra program path")
        self.port = port
        self.program = program

    def request(self, endpoint: str, body: dict[str, Any] | None = None) -> Any:
        query = urllib.parse.urlencode({"program": self.program})
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{endpoint}?{query}",
            data=data,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                raw = response.read().decode()
            try:
                value = json.loads(raw)
            except ValueError:
                value = raw
            if isinstance(value, dict) and set(value) == {"data"}:
                value = value["data"]
            if isinstance(value, dict) and (value.get("error") or value.get("success") is False):
                raise ManagerError(f"MCP {endpoint}: {value}")
            return value
        except (OSError, ValueError) as exc:
            raise ManagerError(
                f"MCP {endpoint} failed; reconcile before retrying writes: {exc}"
            ) from exc

    def idle(self) -> None:
        status = self.request("/analysis_status")
        if not isinstance(status, dict) or status.get("analyzing") is not False:
            raise ManagerError("Ghidra analysis is busy or its status is unknown")

    def script(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        self.idle()
        code = files("ghidra_manager.campaign").joinpath(name + ".java").read_text()
        encoded = base64.b64encode(json.dumps(arguments).encode()).decode()
        response = self.request("/run_script_inline", {"code": code, "args": encoded})
        output = response.get("console_output", "") if isinstance(response, dict) else response
        if not isinstance(output, str):
            raise ManagerError("Malformed script response")
        lines = [
            line.removeprefix("CAMPAIGN_RESULT:")
            for line in output.splitlines()
            if line.startswith("CAMPAIGN_RESULT:")
        ]
        if len(lines) != 1:
            raise ManagerError("Bundled script did not return exactly one complete result")
        result = json.loads(lines[0])
        if not isinstance(result, dict) or result.get("complete") is not True:
            raise ManagerError(f"Incomplete script result: {result}")
        self.idle()
        return result
