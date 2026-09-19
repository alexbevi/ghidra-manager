"""Validate explicit ABI contracts without guessing register preservation."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Any

from ghidra_manager.errors import ManagerError


def validate(change: dict[str, Any], snapshot: dict[str, Any]) -> str:
    if change["kind"] == "compiler_model":
        if set(change) != {"kind", "name", "xml", "evidence_ids"}:
            raise ManagerError("Unexpected compiler model properties")
        xml = change["xml"]
        if "<!" in xml:
            raise ManagerError("Compiler model declarations and external entities are forbidden")
        try:
            model = ET.fromstring(xml)
        except ET.ParseError as exc:
            raise ManagerError("Invalid compiler model XML") from exc
        if model.tag != "prototype" or model.get("name") != change["name"]:
            raise ManagerError("Require one named prototype extension")
        return "model:" + str(change["name"])
    if set(change) != {
        "kind",
        "address",
        "convention",
        "return",
        "parameters",
        "varargs",
        "noreturn",
        "evidence_ids",
    }:
        raise ManagerError("Unexpected ABI properties")
    if not any(f["address"] == change["address"] for f in snapshot["functions"]):
        raise ManagerError("ABI target must already be a function")
    if type(change["varargs"]) is not bool or type(change["noreturn"]) is not bool:
        raise ManagerError("ABI flags must be explicit booleans")
    names = set()
    for index, value in enumerate([change["return"], *change["parameters"]]):
        expected = {"type", "storage"} | ({"name"} if index else set())
        if set(value) != expected:
            raise ManagerError("Unexpected ABI value fields")
        storage = value["storage"]
        if storage is None and index == 0 and value["type"] == "/void":
            continue
        if not isinstance(storage, dict) or set(storage) not in ({"register"}, {"stack"}):
            raise ManagerError("Storage must explicitly name one register or stack offset")
        if "stack" in storage and type(storage["stack"]) is not int:
            raise ManagerError("Stack offset must be an integer")
        if index:
            if not re.fullmatch(r"[A-Za-z_]\w*", value["name"]) or value["name"] in names:
                raise ManagerError("Invalid or duplicate ABI parameter name")
            names.add(value["name"])
    return "abi:" + str(change["address"])


def matches_storage(actual: str, expected: dict[str, Any] | None) -> bool:
    if expected is None:
        return actual == "<VOID>"
    if "register" in expected:
        return bool(actual.split(":")[0] == expected["register"])
    match = re.fullmatch(r"Stack\[(-?(?:0x)?[0-9a-fA-F]+)\]:\d+", actual)
    return bool(match and int(match[1], 0) == expected["stack"])


def readback(change: dict[str, Any], after: dict[str, Any]) -> None:
    if change["kind"] == "compiler_model":
        if change["name"] not in after.get("calling_conventions", []):
            raise ManagerError("Compiler model not present after application")
        return
    function = next(f for f in after["functions"] if f["address"] == change["address"])
    contract = function["abi"]
    if (
        contract["convention"] != change["convention"]
        or contract["varargs"] != change["varargs"]
        or contract["noreturn"] != change["noreturn"]
        or contract["return_type"] != change["return"]["type"]
        or not matches_storage(contract["return_storage"], change["return"]["storage"])
    ):
        raise ManagerError("Return or calling-convention readback failed")
    parameters = [v for v in function["variables"] if v["parameter"]]
    if len(parameters) != len(change["parameters"]):
        raise ManagerError("Parameter count changed")
    for actual, expected in zip(parameters, change["parameters"], strict=True):
        if (
            actual["name"] != expected["name"]
            or actual["type"] != expected["type"]
            or not matches_storage(actual["storage"], expected["storage"])
        ):
            raise ManagerError("Parameter storage readback failed")
