#!/usr/bin/env python3
"""
github-inventory: Detect shadow dependencies that traditional SCA tools miss

Usage:
    python scan.py scan .
    python scan.py scan /path/to/repo
    python scan.py scan https://github.com/org/repo
    python scan.py scan . --format json
    python scan.py scan . --severity high --fail-on critical
"""
import sys
from pathlib import Path

# Add src to Python path so we can import github_inventory without installation
sys.path.insert(0, str(Path(__file__).parent / "src"))

from github_inventory.cli import cli

if __name__ == "__main__":
    cli()
