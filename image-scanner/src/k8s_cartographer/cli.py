"""Command-line interface for the Kubernetes cartography scanner."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .analyzer import normalize_workloads
from .collector import (
    collect_from_cluster,
    collect_from_json_file,
    collect_from_manifests,
    detect_cluster_name,
)
from .payload import build_payload
from .publisher import push_to_platform
from .report import render_table, summarize

_SEVERITY_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "unknown": 0}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="k8s_scan.py",
        description=(
            "Kubernetes cluster-wide dependency cartography (SupplyDrift Vector 3). "
            "Enumerates workloads, resolves container images, and flags shadow "
            "deployments and mutable image references."
        ),
    )
    src = parser.add_argument_group("source (choose one; default is a live cluster via kubectl)")
    src.add_argument("--from-json", type=Path, metavar="FILE", help="Offline 'kubectl get ... -o json' dump")
    src.add_argument("--manifests", type=Path, metavar="DIR", help="Directory of YAML/JSON manifests")
    src.add_argument("--kubeconfig", help="Path to kubeconfig for a live scan")
    src.add_argument("--context", help="kubectl context to scan")
    src.add_argument("--namespace", help="Limit a live scan to one namespace")
    src.add_argument("--kubectl-bin", default="kubectl", help="kubectl binary (default: kubectl)")

    cfg = parser.add_argument_group("analysis")
    cfg.add_argument("--cluster-name", help="Cluster name (auto-detected for live scans)")
    cfg.add_argument("--provider", default="kubernetes", help="Cloud provider tag (e.g. aws, gcp)")
    cfg.add_argument("--environment", default="", help="Environment tag (e.g. production)")
    cfg.add_argument(
        "--trusted-registry",
        action="append",
        default=[],
        metavar="PATTERN",
        help="Approved registry (repeatable; supports globs like '*.corp.example.com')",
    )
    cfg.add_argument(
        "--include-owned",
        action="store_true",
        help="Inventory controller-owned children (ReplicaSets/Pods) too",
    )

    out = parser.add_argument_group("output")
    out.add_argument("--format", choices=["table", "json"], default="table")
    out.add_argument("-o", "--output", type=Path, help="Write output to a file")
    out.add_argument("--push", metavar="URL", help="POST the payload to a SupplyDrift platform base URL")
    out.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low"],
        help="Exit 1 if any finding is at or above this severity",
    )
    parser.add_argument("--version", action="version", version=f"k8s-cartographer {__version__}")
    return parser


def _collect(args: argparse.Namespace) -> tuple[list[dict], str]:
    if args.from_json:
        resources = collect_from_json_file(args.from_json)
        cluster = args.cluster_name or "kubernetes"
    elif args.manifests:
        resources = collect_from_manifests(args.manifests)
        cluster = args.cluster_name or "kubernetes"
    else:
        resources = collect_from_cluster(
            kubeconfig=args.kubeconfig,
            context=args.context,
            namespace=args.namespace,
            kubectl_bin=args.kubectl_bin,
        )
        cluster = args.cluster_name or detect_cluster_name(
            kubeconfig=args.kubeconfig, context=args.context, kubectl_bin=args.kubectl_bin
        )
    return resources, cluster


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        resources, cluster = _collect(args)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    workloads = normalize_workloads(resources, cluster, include_owned=args.include_owned)
    payload = build_payload(
        workloads,
        cluster_name=cluster,
        provider=args.provider,
        environment=args.environment,
        trusted_registries=args.trusted_registry,
        scanner_version=f"k8s-cartographer-{__version__}",
    )

    if args.format == "json":
        rendered = json.dumps(payload, indent=2)
    else:
        rendered = render_table(payload)

    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
        print(f"wrote {args.format} output to {args.output}", file=sys.stderr)
    else:
        print(rendered)

    if args.push:
        try:
            result = push_to_platform(args.push, payload)
            print(
                f"pushed to {args.push}{'' if args.format == 'json' else ''}: "
                f"HTTP {result['status']} {json.dumps(result['response'].get('summary', {}))}",
                file=sys.stderr,
            )
        except RuntimeError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if args.fail_on:
        threshold = _SEVERITY_ORDER[args.fail_on]
        summary = summarize(payload)
        worst = max(
            (_SEVERITY_ORDER.get(sev, 0) for sev in summary["findings_by_severity"]),
            default=0,
        )
        if worst >= threshold:
            return 1
    return 0
