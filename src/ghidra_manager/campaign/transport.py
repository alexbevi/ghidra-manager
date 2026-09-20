"""Explicit-program, local MCP transport for bundled campaign collectors."""

from __future__ import annotations

import base64
import json
import time
import urllib.parse
import urllib.request
from importlib.resources import files
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from uuid import uuid4

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
        # Repair trials keep one transaction open during a whole-program native
        # audit. The server may ignore its timeout hint; never retry on expiry.
        timeout = 120
        if endpoint == "/run_ghidra_script" and body:
            timeout = max(timeout, int(body.get("timeout_seconds", 60)) + 60)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
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
        script = files("ghidra_manager.campaign").joinpath(name + ".java")
        with TemporaryDirectory(prefix="ghidra-campaign-") as directory:
            output_path = Path(directory) / "result.json"
            if name == "CampaignRepair" and "directory" in arguments:
                # Retain the worker result even if this client exits or times out.
                output_path = Path(arguments["directory"]) / f"script-result-{uuid4()}.json"
            encoded = base64.b64encode(
                json.dumps(
                    {
                        **arguments,
                        "output": str(output_path),
                        "script_directory": str(files("ghidra_manager.campaign")),
                    }
                ).encode()
            ).decode()
            response = self.request(
                "/run_ghidra_script",
                {
                    "script_name": str(script),
                    "args": encoded,
                    "timeout_seconds": 1800 if name == "CampaignRepair" else 60,
                    "capture_output": True,
                },
            )
            output = response.get("console_output", "") if isinstance(response, dict) else response
            if (
                name == "CampaignRepair"
                and isinstance(output, str)
                and "CAMPAIGN_RESULT:scheduled" in output
            ):
                deadline = time.monotonic() + 1800
                while not output_path.is_file():
                    if time.monotonic() >= deadline:
                        raise ManagerError(
                            "Repair worker outcome unknown; reconcile before retrying: "
                            f"{output_path}"
                        )
                    time.sleep(0.5)
                result = json.loads(output_path.read_text())
                if not isinstance(result, dict) or result.get("complete") is not True:
                    raise ManagerError(f"Repair worker failed; reconcile before retrying: {result}")
                self.idle()
                return result
            if not isinstance(output, str) or "CAMPAIGN_RESULT:complete" not in output:
                raise ManagerError("Bundled script did not return a complete result")
            if not output_path.is_file():
                raise ManagerError("Bundled script did not write its result artifact")
            result = json.loads(output_path.read_text())
            if not isinstance(result, dict) or result.get("complete") is not True:
                raise ManagerError("Incomplete script result")
        self.idle()
        return result
