#!/usr/bin/env python3
"""Explain an endpoint SBOM count gap (local scan N vs platform M).

The platform stores ONE component per unique identity:
    identity = purl   (if present)
             | ecosystem:name:version   (purl-less, e.g. syft 'binary' artifacts)
The endpoint collector uses the same basis and also merges duplicate OCCURRENCES
(the same package found in several files/paths/roots) into one package with an
occurrence_count. So the raw syft artifact count is >= the distinct-package count
the platform shows. This script makes that concrete for YOUR scan.

Usage
-----
# Point it at the consolidated JSON written by the collector's --output:
python3 platform/scripts/diag_endpoint_sync.py endpoint-inventory.json

# If you have the per-batch payloads instead, pass them all:
python3 platform/scripts/diag_endpoint_sync.py batch-*.json
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict


def load_packages(paths: list[str]) -> list[dict]:
    pkgs: list[dict] = []
    for p in paths:
        with open(p, encoding="utf-8") as fh:
            doc = json.load(fh)
        # consolidated --output, a raw batch, or {report:{components}}
        if isinstance(doc, dict):
            if isinstance(doc.get("packages"), list):
                pkgs += doc["packages"]
            elif isinstance(doc.get("components"), list):
                pkgs += doc["components"]
            elif isinstance(doc.get("report"), dict):
                pkgs += doc["report"].get("components", []) or []
        elif isinstance(doc, list):
            pkgs += doc
    return pkgs


def platform_identity(pkg: dict) -> tuple:
    """Mirror Store._upsert_component: stable_id basis = (purl|cpe|ecosystem, name, version)."""
    purl = (pkg.get("purl") or "").strip()
    cpe = (pkg.get("cpe") or "").strip()
    ecosystem = (pkg.get("ecosystem") or pkg.get("type") or "").strip()
    name = (pkg.get("name") or "").strip()
    version = (pkg.get("version") or "").strip()
    return (purl or cpe or ecosystem, name, version)


def collector_key(pkg: dict) -> str:
    purl = (pkg.get("purl") or "").strip()
    if purl:
        return purl
    return f"{(pkg.get('type') or pkg.get('ecosystem') or '').strip()}:{(pkg.get('name') or '').strip()}:{(pkg.get('version') or '').strip()}"


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 2
    pkgs = load_packages(argv)
    if not pkgs:
        print("no packages found in the given file(s) — is this the collector --output JSON?")
        return 1

    by_identity: dict[tuple, list[dict]] = defaultdict(list)
    for pk in pkgs:
        by_identity[platform_identity(pk)].append(pk)

    raw = len(pkgs)
    distinct_collector = len({collector_key(pk) for pk in pkgs})
    distinct_platform = len(by_identity)
    # occurrence-merged packages already carry occurrence_count in collector output
    occ_total = sum(int(pk.get("occurrence_count") or 1) for pk in pkgs)

    print(f"raw package entries in file:        {raw}")
    print(f"sum of occurrence_count:            {occ_total}   (syft's raw 'cataloged' figure)")
    print(f"distinct collector keys:            {distinct_collector}")
    print(f"DISTINCT platform identities:       {distinct_platform}   <- what the platform stores")
    print()

    merges = {k: v for k, v in by_identity.items() if len({collector_key(pk) for pk in v}) > 1}
    if merges:
        print(f"{len(merges)} platform identity(ies) absorb MORE THAN ONE collector key "
              f"(these explain the gap):")
        for (idbase, name, version), group in sorted(merges.items(), key=lambda kv: kv[0][1]):
            keys = sorted({collector_key(pk) for pk in group})
            print(f"  • {name}@{version}  -> merges {len(keys)} entries:")
            for k in keys:
                print(f"        {k}")
    else:
        print("No identity merges: every package maps to a UNIQUE platform identity.")
        print("=> If the platform shows fewer than the distinct-platform number above,")
        print("   the missing packages were DROPPED in transit (check sync auth / 4xx in")
        print("   the collector log), not merged. Otherwise the counts reconcile and")
        print("   the local 'N packages' line was syft's raw occurrence count.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
