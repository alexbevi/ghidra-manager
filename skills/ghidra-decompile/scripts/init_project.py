#!/usr/bin/env python3
"""Compatibility wrapper; prefer ghidra-manager campaign."""
from ghidra_manager.campaign.init_project import main

if __name__ == "__main__":
    raise SystemExit(main())
