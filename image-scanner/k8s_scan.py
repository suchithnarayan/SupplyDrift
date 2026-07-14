#!/usr/bin/env python3
"""k8s-cartographer: Kubernetes cluster-wide dependency cartography (SupplyDrift Vector 3).

Usage:
    python3 k8s_scan.py --from-json cluster-dump.json
    python3 k8s_scan.py --manifests ./gitops/
    python3 k8s_scan.py --context prod-eks-1 --trusted-registry '123456789012.dkr.ecr.*'
    python3 k8s_scan.py --from-json dump.json --format json --push http://127.0.0.1:8765
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from k8s_cartographer.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
