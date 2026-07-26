"""ScummVM-specific reviewed-coverage seed catalogs."""

from __future__ import annotations

from typing import Any

RIPPER_SCENARIOS = (
    (
        "startup-menu",
        "Start the engine and reach the main menu",
        "game-progression",
        "Establishes that the engine, data files, and initial presentation are usable.",
        True,
    ),
    (
        "new-game",
        "Start a new game and enter the opening scene",
        "game-progression",
        "Establishes the basic new-game bootstrap and initial progression state.",
        True,
    ),
    (
        "scripted-scene-transition",
        "Execute a script-driven scene transition",
        "scripts",
        "Covers the script dispatcher, scene state, and navigation handoff.",
        True,
    ),
    (
        "representative-puzzle",
        "Complete a representative puzzle",
        "puzzles",
        "Demonstrates interactive puzzle logic and its progression side effects.",
        True,
    ),
    (
        "inventory-toolbar",
        "Use inventory and toolbar actions in a scene",
        "inventory",
        "Covers common player interaction outside scripted dialogue.",
        False,
    ),
    (
        "wac-interaction",
        "Complete a representative WAC interaction",
        "wac",
        "Covers database presentation, input, and state updates.",
        False,
    ),
    (
        "cyber-round-trip",
        "Enter, interact with, and exit a Cyber sequence",
        "cyber",
        "Covers nested Cyber execution and a clean return to the surrounding scene.",
        True,
    ),
    (
        "combat-encounter",
        "Complete a representative combat encounter",
        "combat",
        "Covers combat setup, player input, result handling, and scene return.",
        True,
    ),
    (
        "save-restore",
        "Save, quit, reload, and continue",
        "save-restore",
        "Establishes persistence of progression and engine state.",
        True,
    ),
    (
        "chapter-progression",
        "Cross a major chapter progression boundary",
        "game-progression",
        "Demonstrates that accumulated game state unlocks later progression.",
        True,
    ),
)


def scenario_units(profile: dict[str, Any]) -> list[dict[str, Any]]:
    """Return deterministic scenario units owned by the ScummVM RIPPER profile."""
    source = profile.get("source", {})
    if str(source.get("project", "")).lower() != "ripper":
        return []
    return [
        {
            "id": f"scummvm-ripper:scenario:{slug}",
            "kind": "behavioral_unit",
            "unit_type": "scenario",
            "subsystem": subsystem,
            "label": label,
            "player_impact": player_impact,
            "critical_progression": critical,
            "provider": "scummvm.ripper-scenarios",
            "source": {"kind": "adapter_catalog", "version": 1},
        }
        for slug, label, subsystem, player_impact, critical in RIPPER_SCENARIOS
    ]
