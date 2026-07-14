#!/usr/bin/env python3
"""Entry point: scan GitHub repositories and sync phantom dependencies to the platform.

Usage:
    python3 gbom_sync.py --config sync.yaml
    python3 gbom_sync.py --config-url http://127.0.0.1:8765/api/scanner/config
    python3 gbom_sync.py --config sync.yaml --dry-run
"""
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "supplydrift-sandbox" / "src"))
sys.path.insert(0, str(Path(__file__).parent / "src"))

from github_inventory.sync.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
