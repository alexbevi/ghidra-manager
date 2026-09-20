"""Conservative readback for names of existing structure components."""

from __future__ import annotations

import re
from copy import deepcopy
from typing import Any

from ghidra_manager.errors import ManagerError


def expected_types(plan: dict[str, Any], before: dict[str, Any]) -> list[dict[str, Any]]:
    """Permit only the named component and its exact rendered definition row."""
    types: list[dict[str, Any]] = deepcopy(before["types"])
    for change in plan["changes"]:
        if change["kind"] != "field":
            continue
        owners = [t for t in types if t["path"] == change["address"]]
        if len(owners) != 1:
            raise ManagerError("Missing structure during field readback")
        owner = owners[0]
        fields = [f for f in owner.get("fields", []) if f["offset"] == change["offset"]]
        if len(fields) != 1 or fields[0]["name"] != change["old_name"]:
            raise ManagerError("Ambiguous or stale structure component")
        field = fields[0]
        # Ghidra Structure.toString has one row per defined component. Anchor
        # offset, extent and name; preserve type display, comments and spacing.
        pattern = (
            rf"(?m)^([ \t]+{field['offset']}[ \t]+[^\n]+?[ \t]+"
            rf'{field["length"]}[ \t]+){re.escape(change["old_name"])}([ \t]+")'
        )
        definition, count = re.subn(
            pattern, r"\g<1>" + change["new_name"] + r"\g<2>", owner["definition"]
        )
        if count != 1:
            raise ManagerError("Unsupported structure definition rendering; retain old state")
        owner["definition"] = definition
        field["name"] = change["new_name"]
    return types
