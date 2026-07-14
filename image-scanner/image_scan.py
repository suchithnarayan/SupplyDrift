#!/usr/bin/env python3
"""image-scanner: container image SBOM extraction (SupplyDrift Vector 2).

Usage:
    python3 image_scan.py --config config.yaml
    python3 image_scan.py --config config.yaml --source prod-ecr
    python3 image_scan.py --config config.yaml --dry-run          # discover only
    python3 image_scan.py --config config.yaml --no-push -o out.json
"""
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "supplydrift-sandbox" / "src"))
sys.path.insert(0, str(Path(__file__).parent / "src"))

from image_scanner.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
