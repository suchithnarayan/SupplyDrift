#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import sqlite3  # noqa: F401 — kept for type annotations (lazy via future-annotations)
import uuid
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine, event, text


APP_ROOT = Path(__file__).resolve().parent
FRONTEND_DIST = APP_ROOT / "frontend" / "dist"
STATIC_ROOT = FRONTEND_DIST if FRONTEND_DIST.exists() else APP_ROOT / "static"
DATA_ROOT = APP_ROOT / "data"
DEFAULT_DB = DATA_ROOT / "supplydrift.db"


# A runner polls /api/scan/runs/claim every ~15s even when idle, so a heartbeat
# within this window means a runner is connected and able to claim that job type.
RUNNER_LIVENESS_WINDOW_SECONDS = 60
# While a runner is mid-scan it STOPS polling, so its heartbeat goes stale even
# though it is alive and working. A job of the type that has been 'running' within
# this window means a runner is present but busy (it will claim the next queued
# job when it finishes). Past this window we assume the runner died/stuck and stop
# counting it, so the UI degrades back to "no runner connected".
RUNNER_BUSY_WINDOW_SECONDS = 1800
# A scan run claimed by a runner that then dies (crash, `docker compose down`
# mid-scan, OOM) stays 'running' forever — the runner never POSTs /complete, and
# a restarted runner only claims 'queued' jobs, so the source is stuck "Scanning…".
# Any 'running' run whose claim is older than this is treated as orphaned and
# reaped to 'failed'. Set generously so a legitimately long scan is not killed;
# override with SUPPLYDRIFT_SCAN_STALE_SECONDS. A genuine late /complete still wins
# (it overwrites the reaped 'failed' row), so reaping is safe even if the runner
# was merely slow rather than dead.
SCAN_STALE_TIMEOUT_SECONDS = int(os.environ.get("SUPPLYDRIFT_SCAN_STALE_SECONDS", "3600"))


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def stable_id(namespace: str, *parts: Any) -> str:
    raw = ":".join(str(p or "") for p in parts)
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"supplydrift:{namespace}:{raw}"))


def to_json(value: Any) -> str:
    return json.dumps(value if value is not None else {}, sort_keys=True)


def from_json(value: str | None, fallback: Any = None) -> Any:
    if not value:
        return {} if fallback is None else fallback
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return {} if fallback is None else fallback


def row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    out = dict(row)
    for key in (
        "tags",
        "raw_metadata",
        "scope",
        "config",
        "summary",
        "evidence",
        "hashes",
        "document",
        "raw_response",
    ):
        if key in out:
            out[key] = from_json(out[key], [] if key == "tags" else {})
    return out


SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "unknown": 0}
RANK_SEVERITY = {value: key for key, value in SEVERITY_RANK.items()}

# grype/CycloneDX severities normalized to the platform's vocabulary.
_SEVERITY_ALIASES = {"negligible": "low", "moderate": "medium", "none": "info", "": "info"}


def normalize_severity(value: Any) -> str:
    s = str(value or "").strip().lower()
    return _SEVERITY_ALIASES.get(s, s) or "info"

SYNC_SOURCES = {
    "repository": {
        "label": "Repository SBOM",
        "connector_type": "repo_scanner",
        "asset_type": "repository",
        "usage_source": "repo_sbom",
    },
    "registry": {
        "label": "Registry Image SBOM",
        "connector_type": "registry_scanner",
        "asset_type": "container_image",
        "usage_source": "registry_sbom",
    },
    "kubernetes": {
        "label": "Kubernetes Workload SBOM",
        "connector_type": "k8s_scanner",
        "asset_type": "k8s_workload",
        "usage_source": "k8s_sbom",
    },
    "cloud_workload": {
        "label": "Cloud Workload SBOM",
        "connector_type": "cloud_scanner",
        "asset_type": "cloud_workload",
        "usage_source": "cloud_sbom",
    },
    "endpoint": {
        "label": "Endpoint SBOM",
        "connector_type": "endpoint_scanner",
        "asset_type": "endpoint",
        "usage_source": "endpoint_sbom",
    },
}

SYNC_ENDPOINTS = {
    "repository": "repository",
    "repositories": "repository",
    "repository-dependencies": "repository",
    "repo-dependencies": "repository",
    "registry": "registry",
    "registries": "registry",
    "container-image": "registry",
    "container-images": "registry",
    "image": "registry",
    "images": "registry",
    "kubernetes": "kubernetes",
    "kubernetes-workload": "kubernetes",
    "kubernetes-workloads": "kubernetes",
    "k8s-workload": "kubernetes",
    "k8s-workloads": "kubernetes",
    "cloud-workload": "cloud_workload",
    "cloud-workloads": "cloud_workload",
    "ecs": "cloud_workload",
    "ecs-workload": "cloud_workload",
    "ecs-workloads": "cloud_workload",
    "endpoint": "endpoint",
    "endpoints": "endpoint",
    "laptop": "endpoint",
    "laptops": "endpoint",
    "device": "endpoint",
    "devices": "endpoint",
}

# Scanner source types configurable from the UI (stored in the connectors table).
# Connection.auth fields that are SECRETS — stored encrypted in connector_secrets,
# never in the connector config JSON, never returned to the browser.
SECRET_AUTH_FIELDS = ("password", "token", "secret")
# The mask the scanner-config API echoes back to the UI in place of a real secret
# value. Treated as "keep existing" on save so a form round-trip can't overwrite a
# stored credential with the mask.
SECRET_MASK = "***"
SECRET_ENV_REFERENCE_FIELDS = {"password_env", "token_env", "secret_env", "client_secret_env"}
SECRET_LIKE_FIELD_RE = re.compile(
    r"(^|_)(password|passwd|pwd|token|secret|api_key|access_key|private_key|client_secret)(_|$)",
    re.IGNORECASE,
)

REGISTRY_SOURCE_TYPES = {"dockerhub", "ghcr", "harbor", "ecr"}
SERVICE_SOURCE_TYPES = {"kubernetes", "eks", "ecs"}
REPO_SOURCE_TYPES = {"github"}
SCANNER_SOURCE_TYPES = REGISTRY_SOURCE_TYPES | SERVICE_SOURCE_TYPES | REPO_SOURCE_TYPES
PUBLIC_URL = os.environ.get("SUPPLYDRIFT_PUBLIC_URL", "http://127.0.0.1:8765").rstrip("/")


def first_value(*values: Any, default: str = "") -> str:
    for value in values:
        if value is not None and value != "":
            return str(value)
    return default


def _secret_like_connection_fields(value: Any, path: str = "connection") -> list[str]:
    """Return connector config paths that look like inline secrets.

    The UI intentionally supports a few direct credential fields under
    connection.auth; those are extracted separately into connector_secrets. Any
    other secret-shaped field should fail closed instead of being serialized into
    the visible connector config JSON.
    """
    bad: list[str] = []
    if isinstance(value, Mapping):
        for key, child in value.items():
            key_s = str(key)
            child_path = f"{path}.{key_s}"
            if path == "connection.auth" and key_s in SECRET_AUTH_FIELDS:
                continue
            if path == "connection.auth" and key_s in SECRET_ENV_REFERENCE_FIELDS:
                continue
            if SECRET_LIKE_FIELD_RE.search(key_s):
                bad.append(child_path)
            if key_s == "kubeconfig" and isinstance(child, str) and (
                "\n" in child or "apiVersion:" in child
            ):
                bad.append(child_path)
            bad.extend(_secret_like_connection_fields(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            bad.extend(_secret_like_connection_fields(child, f"{path}[{index}]"))
    return bad


def _int_param(params: dict[str, list[str]], key: str, default: int = 0) -> int:
    try:
        return int((params.get(key) or [default])[0] or default)
    except (ValueError, TypeError):
        return default


def paginate_params(
    params: dict[str, list[str]], default: int = 50, maximum: int = 200
) -> tuple[int, int, bool]:
    """Parse limit/offset/page. Returns (limit, offset, paginated).

    `paginated` is True only when the client asked for a page (limit/offset/page
    present) — otherwise list endpoints stay backward-compatible and return a
    plain list capped at the legacy limit.
    """
    paginated = any(k in params for k in ("limit", "offset", "page"))
    limit = max(1, min(maximum, _int_param(params, "limit", default)))
    offset = max(0, _int_param(params, "offset", 0))
    page = _int_param(params, "page", 0)
    if page > 0:
        offset = (page - 1) * limit
    return limit, offset, paginated


def cyclonedx_properties(value: dict[str, Any]) -> dict[str, Any]:
    props: dict[str, Any] = {}
    for prop in value.get("properties", []) or []:
        name = prop.get("name")
        if name:
            props[name] = prop.get("value", "")
    return props


def property_value(props: dict[str, Any], *names: str) -> str:
    for name in names:
        value = props.get(name)
        if value is not None and value != "":
            return str(value)
    return ""


def ecosystem_from_purl(purl: str, fallback: str = "") -> str:
    if purl.startswith("pkg:"):
        remainder = purl[4:]
        return remainder.split("/", 1)[0].split("@", 1)[0]
    return fallback


def severity_rank(value: str | None) -> int:
    return SEVERITY_RANK.get((value or "unknown").lower(), 0)


def license_from_cyclonedx(component: dict[str, Any]) -> str:
    licenses = component.get("licenses") or []
    if not licenses:
        return ""
    first = licenses[0]
    license_data = first.get("license") if isinstance(first, dict) else None
    if isinstance(license_data, dict):
        return first_value(license_data.get("id"), license_data.get("name"))
    if isinstance(first, str):
        return first
    return ""


def supplier_from_cyclonedx(component: dict[str, Any]) -> str:
    supplier = component.get("supplier")
    if isinstance(supplier, dict):
        return first_value(supplier.get("name"), supplier.get("url"))
    if isinstance(supplier, str):
        return supplier
    return ""


def hashes_from_cyclonedx(component: dict[str, Any]) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for item in component.get("hashes", []) or []:
        alg = item.get("alg")
        content = item.get("content")
        if alg and content:
            hashes[str(alg)] = str(content)
    return hashes


def cpe_from_cyclonedx(component: dict[str, Any]) -> str:
    cpe = component.get("cpe", "")
    if isinstance(cpe, list):
        return first_value(*(item for item in cpe))
    return str(cpe or "")


def unwrap_cyclonedx_payload(payload: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    if payload.get("bomFormat") == "CycloneDX":
        return payload, {}
    for key in ("cyclonedx", "bom", "sbom", "document"):
        document = payload.get(key)
        if isinstance(document, dict) and document.get("bomFormat") == "CycloneDX":
            return document, payload
    raise ValueError("expected a CycloneDX JSON document or a wrapper with cyclonedx/bom/sbom/document")


def asset_from_cyclonedx(
    source_type: str,
    document: dict[str, Any],
    wrapper: dict[str, Any],
) -> dict[str, Any]:
    source = SYNC_SOURCES[source_type]
    asset = dict(wrapper.get("asset") or {})
    metadata_component = document.get("metadata", {}).get("component") or {}
    metadata_props = cyclonedx_properties(metadata_component)
    asset_type = asset.get("asset_type") or source["asset_type"]
    external_id = first_value(
        asset.get("external_id"),
        asset.get("id"),
        property_value(metadata_props, "supplydrift:asset_id", "asset_id"),
        metadata_component.get("purl"),
        metadata_component.get("bom-ref"),
        metadata_component.get("name"),
        document.get("serialNumber"),
        default=f"{source_type}:{document.get('serialNumber', 'unknown')}",
    )
    display_name = first_value(
        asset.get("display_name"),
        asset.get("name"),
        property_value(metadata_props, "supplydrift:display_name", "display_name"),
        metadata_component.get("name"),
        external_id,
    )
    details = dict(asset.get("details") or {})
    details.update(
        {
            key.removeprefix("supplydrift:details."): value
            for key, value in metadata_props.items()
            if key.startswith("supplydrift:details.")
        }
    )
    return {
        "ref": "sync_asset",
        "asset_type": asset_type,
        "provider": first_value(asset.get("provider"), wrapper.get("provider"), source_type),
        "external_id": external_id,
        "display_name": display_name,
        "owner": first_value(asset.get("owner"), wrapper.get("owner")),
        "environment": first_value(asset.get("environment"), wrapper.get("environment")),
        "status": first_value(asset.get("status"), default="active"),
        "tags": asset.get("tags") or wrapper.get("tags") or [],
        "details": details,
        "raw_metadata": {
            **(asset.get("raw_metadata") or asset.get("metadata") or {}),
            **({"provenance": details["provenance"]} if details.get("provenance") else {}),
            "cyclonedx_serial_number": document.get("serialNumber", ""),
            "cyclonedx_version": document.get("version", ""),
            "sync_source": source_type,
        },
    }


def component_from_cyclonedx(component: dict[str, Any], index: int) -> dict[str, Any]:
    props = cyclonedx_properties(component)
    purl = component.get("purl", "")
    ecosystem = first_value(
        property_value(props, "supplydrift:ecosystem", "ecosystem"),
        ecosystem_from_purl(purl),
        component.get("type"),
    )
    component_ref = first_value(component.get("bom-ref"), purl, component.get("name"), default=f"component-{index}")
    return {
        "ref": component_ref,
        "name": first_value(component.get("name"), purl, component_ref, default=f"component-{index}"),
        "version": first_value(component.get("version")),
        "ecosystem": ecosystem,
        "package_manager": first_value(
            property_value(props, "supplydrift:package_manager", "package_manager"),
            ecosystem,
        ),
        "purl": purl,
        "cpe": cpe_from_cyclonedx(component),
        "supplier": supplier_from_cyclonedx(component),
        "license": license_from_cyclonedx(component),
        "hashes": hashes_from_cyclonedx(component),
    }


def usage_from_cyclonedx(
    source_type: str,
    component: dict[str, Any],
    component_ref: str,
) -> dict[str, Any]:
    props = cyclonedx_properties(component)
    evidence_path = property_value(
        props,
        "supplydrift:path",
        "supplydrift:evidence_path",
        "evidence_path",
        "path",
        "filePath",
        "location",
        "cdx:location:path",
        "syft:location:0:path",
    )
    return {
        "asset_ref": "sync_asset",
        "component_ref": component_ref,
        "source": SYNC_SOURCES[source_type]["usage_source"],
        "evidence_path": evidence_path,
        "package_manager": first_value(
            property_value(props, "supplydrift:package_manager", "package_manager"),
            ecosystem_from_purl(component.get("purl", "")),
        ),
        "evidence": {
            "bom_ref": component.get("bom-ref", ""),
            "type": component.get("type", ""),
            "scope": component.get("scope", ""),
            "group": component.get("group", ""),
        },
    }


def findings_from_cyclonedx(document: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for vulnerability in document.get("vulnerabilities", []) or []:
        ratings = vulnerability.get("ratings") or []
        severity = normalize_severity(ratings[0].get("severity") if ratings else None)
        affects = vulnerability.get("affects") or []
        refs = [item.get("ref") for item in affects if item.get("ref")] or [None]
        for ref in refs:
            findings.append(
                {
                    "asset_ref": "sync_asset",
                    "component_ref": ref,
                    "finding_type": "cve",
                    "severity": severity,
                    "title": first_value(vulnerability.get("id"), vulnerability.get("bom-ref"), default="Vulnerability"),
                    "description": vulnerability.get("description", ""),
                    "fix_recommendation": vulnerability.get("recommendation", ""),
                    "evidence": {
                        "source": vulnerability.get("source", {}),
                        "ratings": ratings,
                        "references": vulnerability.get("references", []),
                    },
                }
            )
    return findings


def endpoint_batch_to_ingest(payload: dict[str, Any]) -> dict[str, Any]:
    """Translate a syft endpoint-collector batch into the normalized ingest shape.

    The endpoint-dep-inventory collector posts batched
    ``{endpoint, scanner, source, packages[], dependency_edges[], batch_*}`` JSON
    (one POST per batch). Each maps to one ``endpoint`` asset plus its packages as
    components; batches accumulate on the same asset (upsert by endpoint id).
    """
    ep = payload.get("endpoint") or {}
    scanner = payload.get("scanner") or {}
    src = payload.get("source") if isinstance(payload.get("source"), dict) else {}
    endpoint_id = first_value(ep.get("id"), ep.get("hostname"), default="unknown-endpoint")

    asset = {
        "ref": "endpoint_asset",
        # Stable provider so syft (SBOM) and grype (vuln) batches map to ONE asset
        # — the scanner is recorded in scan_metadata, not the asset identity.
        "provider": "endpoint-collector",
        "asset_type": "endpoint",
        "external_id": f"endpoint:{endpoint_id}",
        "display_name": first_value(ep.get("hostname"), endpoint_id),
        "tags": ["developer"],
        "details": {
            "endpoint_id": endpoint_id,
            "hostname": ep.get("hostname", ""),
            "os_name": ep.get("os", ""),
            "os_version": ep.get("kernel", ""),
            "architecture": ep.get("arch", ""),
            "employee_id": ep.get("username", ""),
            "last_checkin_at": payload.get("scanned_at", ""),
        },
        "raw_metadata": {
            "collector_version": payload.get("collector_version"),
            "scan_policy_version": payload.get("scan_policy_version"),
            "scan_id": payload.get("scan_id"),
            "batch": {"index": payload.get("batch_index"), "count": payload.get("batch_count")},
            "scanner": scanner,
            "source": src,
        },
    }

    components: dict[str, dict[str, Any]] = {}
    usages: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []

    # SBOM batch: packages -> components (+ usages with evidence paths).
    for pkg in payload.get("packages") or []:
        purl = pkg.get("purl", "") or ""
        ref = first_value(
            purl, pkg.get("key"),
            default=f"{pkg.get('type', '')}:{pkg.get('name', '')}:{pkg.get('version', '')}",
        )
        licenses = pkg.get("licenses")
        manager = first_value(pkg.get("language"), pkg.get("type"))
        components[ref] = {
            "ref": ref,
            "name": pkg.get("name", ""),
            "version": pkg.get("version", ""),
            "ecosystem": pkg.get("type", ""),
            "package_manager": manager,
            "purl": purl,
            "license": ", ".join(licenses) if isinstance(licenses, list) else (licenses or ""),
        }
        locs = pkg.get("locations") or []
        usages.append({
            "asset_ref": "endpoint_asset",
            "component_ref": ref,
            "source": "endpoint_scan",
            "evidence_path": locs[0] if locs else "",
            "package_manager": manager,
            "evidence": {
                "found_by": pkg.get("found_by"),
                "dependency_kind": pkg.get("dependency_kind"),
                "occurrence_count": pkg.get("occurrence_count"),
                "locations": locs,
            },
        })

    # Vulnerability batch (grype): minimal {name, version, purl, id, severity, fix}
    # -> one CVE finding per vuln, linked to the (vulnerable) component by purl.
    for vuln in payload.get("vulnerabilities") or []:
        name = vuln.get("name", "")
        version = vuln.get("version", "")
        purl = vuln.get("purl", "") or ""
        ref = first_value(purl, default=f"{name}:{version}")
        if ref not in components:
            eco = purl[4:].split("/", 1)[0] if purl.startswith("pkg:") else ""
            components[ref] = {
                "ref": ref, "name": name, "version": version,
                "ecosystem": eco, "package_manager": eco, "purl": purl,
            }
        vid = first_value(vuln.get("id"), vuln.get("vulnerability"), default="UNKNOWN")
        fix = vuln.get("fix") or ""
        findings.append({
            "asset_ref": "endpoint_asset",
            "component_ref": ref,
            "finding_type": "cve",
            "severity": normalize_severity(vuln.get("severity", "")),
            "title": vid,
            "description": f"{vid} affects {name} {version}".strip(),
            "fix_recommendation": f"Upgrade {name} to {fix}" if fix else "",
            "evidence": {
                "vulnerability_id": vid, "package": name, "version": version,
                "fix": fix, "data_source": vuln.get("data_source"),
            },
        })

    return {
        "connector": {
            "name": first_value(src.get("name"), default="endpoint-collector"),
            "connector_type": SYNC_SOURCES["endpoint"]["connector_type"],
        },
        "scan_metadata": {
            "scanner_version": f"{first_value(scanner.get('name'), default='syft')} {scanner.get('version', '')}".strip(),
            "started_at": payload.get("scanned_at"),
            "scan_id": payload.get("scan_id"),
            "batch_index": payload.get("batch_index"),
            "component_count": len(components),
            "vulnerability_count": len(findings),
        },
        "assets": [asset],
        "components": list(components.values()),
        "component_usages": usages,
        "findings": findings,
    }


def cyclonedx_to_ingest_payload(source_type: str, payload: dict[str, Any]) -> dict[str, Any]:
    if source_type not in SYNC_SOURCES:
        raise ValueError(f"unsupported sync source: {source_type}")
    document, wrapper = unwrap_cyclonedx_payload(payload)
    source = SYNC_SOURCES[source_type]
    components: list[dict[str, Any]] = []
    usages: list[dict[str, Any]] = []
    for index, component in enumerate(document.get("components", []) or []):
        normalized = component_from_cyclonedx(component, index)
        components.append(normalized)
        usages.append(usage_from_cyclonedx(source_type, component, normalized["ref"]))
    return {
        "connector": {
            "name": first_value(wrapper.get("source_name"), wrapper.get("connector", {}).get("name"), source["label"]),
            "connector_type": first_value(
                wrapper.get("connector", {}).get("connector_type"),
                wrapper.get("connector_type"),
                source["connector_type"],
            ),
            "status": "manual",
            "scope": wrapper.get("scope") or wrapper.get("connector", {}).get("scope") or {},
            "config": {"sync_endpoint": f"/api/sync/{source_type}"},
        },
        "scan_metadata": {
            **(wrapper.get("scan_metadata") or {}),
            "status": "running",
            "started_at": wrapper.get("scan_metadata", {}).get("started_at", now_iso()),
        },
        "assets": [asset_from_cyclonedx(source_type, document, wrapper)],
        "components": components,
        "component_usages": usages,
        "findings": findings_from_cyclonedx(document),
        "raw_sboms": [
            {
                "asset_ref": "sync_asset",
                "format": "cyclonedx",
                "document": document,
            }
        ],
    }


# ── SQLAlchemy engine seam ──────────────────────────────────────────────────
# The data layer below was written against sqlite3 (`?` params, sqlite3.Row).
# We keep that exact surface but route it through a SQLAlchemy engine, so the same
# Store runs on SQLite (dev/tests) and MySQL (prod). `connect()` returns a small
# facade whose `.execute()` translates `?` -> named binds and yields rows that
# support both `row["col"]` and `row[0]`, like sqlite3.Row.
class _Row(Mapping):
    __slots__ = ("_m", "_v")

    def __init__(self, mapping: Mapping):
        self._m = dict(mapping)
        self._v = list(self._m.values())

    def __getitem__(self, key):
        return self._v[key] if isinstance(key, int) else self._m[key]

    def __iter__(self):
        return iter(self._m)

    def __len__(self):
        return len(self._m)

    def keys(self):
        return self._m.keys()

    def get(self, key, default=None):
        return self._m.get(key, default)


def _row_mapping(row) -> Mapping:
    mapping = getattr(row, "_mapping", None)
    if mapping is not None:
        return mapping
    keys = getattr(row, "keys", None)
    if keys is not None:
        return {key: row[key] for key in keys()}
    return {idx: value for idx, value in enumerate(row)}


class _Result:
    def __init__(self, cursor_result):
        self._r = cursor_result

    def fetchone(self):
        row = self._r.fetchone()
        return _Row(_row_mapping(row)) if row is not None else None

    def fetchall(self):
        return [_Row(_row_mapping(r)) for r in self._r.fetchall()]

    def __iter__(self):
        for r in self._r:
            yield _Row(_row_mapping(r))

    @property
    def rowcount(self):
        return self._r.rowcount


_ONCONFLICT_RE = re.compile(r"ON\s+CONFLICT\s*\([^)]*\)\s*DO\s+UPDATE\s+SET", re.IGNORECASE)
_EXCLUDED_RE = re.compile(r"\bexcluded\.(\w+)", re.IGNORECASE)


def _sqlite_upsert_to_mysql(sql: str) -> str:
    """`INSERT … ON CONFLICT(keys) DO UPDATE SET … excluded.X` (SQLite/Postgres)
    -> MySQL `INSERT … ON DUPLICATE KEY UPDATE … VALUES(X)`. The unique/primary key
    that MySQL conflicts on must exist in the schema (it does — that's why ON CONFLICT
    works on SQLite)."""
    sql = _ONCONFLICT_RE.sub("ON DUPLICATE KEY UPDATE", sql)
    return _EXCLUDED_RE.sub(r"VALUES(\1)", sql)


def _qmark_to_named(sql: str, params) -> tuple[str, dict]:
    """sqlite `?` positional placeholders -> SQLAlchemy `:pN` named binds (quote-aware)."""
    out: list[str] = []
    binds: dict[str, Any] = {}
    n = 0
    quote = None
    for ch in sql:
        if quote:
            out.append(ch)
            if ch == quote:
                quote = None
        elif ch in ("'", '"'):
            quote = ch
            out.append(ch)
        elif ch == "?":
            key = f"p{n}"
            out.append(":" + key)
            binds[key] = params[n]
            n += 1
        else:
            out.append(ch)
    return "".join(out), binds


class _StoreConn:
    """A sqlite3.Connection-compatible facade over a SQLAlchemy connection."""

    def __init__(self, engine):
        self._dialect = engine.dialect.name
        self._conn = engine.connect()
        self._tx = self._conn.begin()

    def execute(self, sql: str, params=()):
        if self._dialect != "sqlite" and "ON CONFLICT" in sql:
            sql = _sqlite_upsert_to_mysql(sql)
        if not params:
            stmt, binds = text(sql), {}
        elif isinstance(params, dict):
            stmt, binds = text(sql), params
        else:
            translated, binds = _qmark_to_named(sql, params)
            stmt = text(translated)
        return _Result(self._conn.execute(stmt, binds))

    def commit(self):
        self._tx.commit()
        self._tx = self._conn.begin()

    def rollback(self):
        self._tx.rollback()
        self._tx = self._conn.begin()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type is not None:
            self._tx.rollback()
        else:
            self._tx.commit()
        self._conn.close()
        return False


def make_engine(db_path: Path):
    """Engine from SUPPLYDRIFT_DATABASE_URL, else a SQLite file at db_path."""
    url = os.environ.get("SUPPLYDRIFT_DATABASE_URL")
    if url:
        engine = create_engine(url, pool_pre_ping=True, pool_recycle=1800)
    else:
        engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})

    @event.listens_for(engine, "connect")
    def _on_connect(dbapi_conn, _record):  # noqa: ANN001
        if engine.dialect.name == "sqlite":
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA foreign_keys=ON")
            cur.execute("PRAGMA busy_timeout=5000")  # wait on lock (runners poll concurrently)
            cur.close()

    return engine


class Store:
    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        if not os.environ.get("SUPPLYDRIFT_DATABASE_URL"):
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.engine = make_engine(self.db_path)
        self.dialect = self.engine.dialect.name
        self.init_db()

    def connect(self) -> "_StoreConn":
        return _StoreConn(self.engine)

    def _executescript(self, script: str) -> None:
        """Run a multi-statement script (schema / resets). SQLite uses its native
        executescript; other engines split on `;` (D3 overrides for MySQL DDL)."""
        raw = self.engine.raw_connection()
        try:
            driver = getattr(raw, "driver_connection", None) or raw.connection
            if hasattr(driver, "executescript"):  # sqlite3
                driver.executescript(script)
            else:
                cur = raw.cursor()
                for stmt in script.split(";"):
                    if stmt.strip():
                        cur.execute(stmt)
                cur.close()
            raw.commit()
        finally:
            raw.close()

    def init_db(self) -> None:
        if self.dialect == "sqlite":
            self._executescript(SCHEMA)
            with self.connect() as conn:
                self._migrate(conn)
        else:
            # Non-SQLite (MySQL): the raw SCHEMA string is SQLite-flavoured (TEXT keys,
            # CREATE INDEX IF NOT EXISTS). Materialize the canonical schema in a throwaway
            # in-memory SQLite, reflect it into portable metadata, widen indexed TEXT keys
            # to VARCHAR so the engine can index them, then create_all on the real engine.
            self._create_portable_schema()

    def _create_portable_schema(self) -> None:
        from sqlalchemy import MetaData, String, Text

        canon = create_engine("sqlite://")  # in-memory
        raw = canon.raw_connection()
        try:
            driver = getattr(raw, "driver_connection", None) or raw.connection
            driver.executescript(SCHEMA)
            raw.commit()
        finally:
            raw.close()
        with _StoreConn(canon) as conn:
            self._migrate(conn)

        md = MetaData()
        md.reflect(bind=canon)

        from sqlalchemy.dialects.mysql import MEDIUMTEXT

        # HARD keys (PK / unique / FK both ends) MUST be a bounded VARCHAR — these hold
        # ids/external_ids that fit. Columns in REGULAR indexes (e.g. components.purl,
        # components.name) can be arbitrarily long, so they STAY TEXT and the index uses
        # a fixed-length PREFIX — otherwise a single over-long purl fails the whole batch.
        hard: dict[str, set[str]] = {t: set() for t in md.tables}
        index_cols: dict[str, set[str]] = {t: set() for t in md.tables}
        for name, table in md.tables.items():
            hard[name] |= set(table.primary_key.columns.keys())
            for con in table.constraints:
                if con.__class__.__name__ == "UniqueConstraint":
                    hard[name] |= {c.name for c in con.columns}
            for fk in table.foreign_keys:
                hard[name].add(fk.parent.name)
                hard[fk.column.table.name].add(fk.column.name)
            for idx in table.indexes:
                index_cols[name] |= {c.name for c in idx.columns}

        # Large JSON/text columns stay TEXT — but MySQL TEXT cannot carry a DEFAULT, so
        # we drop it (the app always supplies these on INSERT). SBOM-sized blobs go to
        # MEDIUMTEXT (>64KB). Short defaulted enums (status/schedule/...) become VARCHAR.
        big_text = {"tags", "raw_metadata", "scope", "config", "summary", "evidence",
                    "hashes", "document", "raw_response", "details", "affected_asset_ids", "sources"}
        huge_text = {"document", "raw_response", "raw_metadata"}
        PREFIX = 191
        for name, table in md.tables.items():
            for col in table.columns:
                if not isinstance(col.type, Text):
                    continue
                if col.name in hard[name]:
                    col.type = String(PREFIX)              # key -> bounded VARCHAR
                elif col.name in big_text:
                    if col.name in huge_text:
                        col.type = MEDIUMTEXT()
                    col.server_default = None              # MySQL TEXT can't default
                    col.nullable = True
                elif col.server_default is not None:
                    col.type = String(255)                 # short enum w/ default -> VARCHAR (keeps default)
                # else (incl. index-only long text like purl/name, no default): stays TEXT
            # any index that still touches a TEXT column needs a prefix length on MySQL.
            for idx in table.indexes:
                lengths = {c.name: PREFIX for c in idx.columns if isinstance(c.type, Text)}
                if lengths:
                    idx.dialect_options["mysql"]["length"] = lengths

        md.create_all(self.engine)

    # Idempotent column additions so pre-existing data/*.db files keep working.
    _MIGRATIONS = {
        "container_image_assets": [("discovery_source", "TEXT"), ("source_reference", "TEXT")],
        "assets": [
            ("scan_status", "TEXT NOT NULL DEFAULT 'discovered'"),
            ("last_scanned_at", "TEXT"),
        ],
    }

    def _migrate(self, conn: sqlite3.Connection) -> None:
        freshly_added: set[tuple[str, str]] = set()
        for table, columns in self._MIGRATIONS.items():
            existing = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
            for name, coltype in columns:
                if name not in existing:
                    conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {coltype}")
                    freshly_added.add((table, name))
        # One-time backfill (only when scan_status is first added): every
        # pre-existing asset came from a scan, so mark them all 'scanned'. Gated so
        # later discovery-only stubs are never flipped on subsequent startups.
        if ("assets", "scan_status") in freshly_added:
            conn.execute(
                "UPDATE assets SET scan_status = 'scanned', "
                "last_scanned_at = COALESCE(last_scanned_at, last_seen_at)"
            )
        # Index created here (not in SCHEMA) so it runs after the column exists.
        conn.execute("CREATE INDEX IF NOT EXISTS idx_assets_scan_status ON assets(scan_status)")

    def reset(self) -> None:
        self._executescript(
            """
            DELETE FROM component_vulnerability_status;
            DELETE FROM raw_sboms;
            DELETE FROM findings;
            DELETE FROM asset_relationships;
            DELETE FROM asset_components;
            DELETE FROM components;
            DELETE FROM endpoint_assets;
            DELETE FROM repository_assets;
            DELETE FROM container_image_assets;
            DELETE FROM k8s_workload_assets;
            DELETE FROM cloud_workload_assets;
            DELETE FROM ami_assets;
            DELETE FROM assets;
            DELETE FROM scan_jobs;
            DELETE FROM connectors;
            """
        )

    def _payload_connector_id(self, connector: dict[str, Any]) -> str | None:
        """Resolve a sync payload connector without overwriting configured sources.

        UI-created connectors are the source of truth. Runners send their id back
        in sync payloads so assets/jobs attach to the configured source instead
        of creating generic "Registry Image SBOM" or "Kubernetes Cartographer"
        connectors. Legacy payloads without an id keep the old upsert behavior.
        """
        if not connector:
            return None
        connector_id = str(connector.get("id") or connector.get("connector_id") or "").strip()
        if connector_id:
            with self.connect() as conn:
                existing = conn.execute(
                    "SELECT id FROM connectors WHERE id = ?", (connector_id,)
                ).fetchone()
            if existing:
                return connector_id
            connector = {**connector, "id": connector_id}
        return self.upsert_connector(connector)

    def ingest(self, payload: dict[str, Any]) -> dict[str, Any]:
        connector = payload.get("connector") or {}
        connector_id = self._payload_connector_id(connector)
        job_id = payload.get("scan_metadata", {}).get("job_id") or stable_id(
            "scan_job",
            connector_id,
            payload.get("scan_metadata", {}).get("started_at") or now_iso(),
        )
        self.upsert_scan_job(job_id, connector_id, payload.get("scan_metadata") or {})

        asset_id_map: dict[str, str] = {}
        component_id_map: dict[str, str] = {}
        counters = {"assets": 0, "components": 0, "relationships": 0, "findings": 0, "raw_sboms": 0}

        # Any real scan marks its assets 'scanned' (even an empty SBOM — the scan
        # ran). Only an explicit discovery-only push leaves them 'discovered'.
        scanned = not bool(payload.get("discovery_only"))

        with self.connect() as conn:
            for asset in payload.get("assets", []):
                ref = asset.get("ref")
                asset_id = self._upsert_asset(conn, asset, connector_id, scanned=scanned)
                counters["assets"] += 1
                if ref:
                    asset_id_map[ref] = asset_id

            # Provenance linking runs after every asset exists so an image can link
            # to a workload/repo that appears later in the same payload.
            for asset in payload.get("assets", []):
                if asset.get("asset_type") == "container_image":
                    provenance = (asset.get("details") or {}).get("provenance") or {}
                    image_id = asset_id_map.get(asset.get("ref")) if asset.get("ref") else None
                    if image_id and provenance:
                        self._link_provenance(conn, image_id, provenance)

            component_purl_map: dict[str, str] = {}
            for component in payload.get("components", []):
                component_id = self._upsert_component(conn, component)
                counters["components"] += 1
                if component.get("ref"):
                    component_id_map[component["ref"]] = component_id
                if component.get("purl"):
                    purl = component["purl"]
                    # Index by full purl, package-id-stripped, and bare coordinates
                    # (before '?') so a vuln scanner's reworded purl still matches.
                    for key in (purl, purl.split("&package-id=")[0], purl.split("?")[0]):
                        component_purl_map.setdefault(key, component_id)

            for usage in payload.get("component_usages", []):
                asset_id = self._resolve_ref(usage.get("asset_id") or usage.get("asset_ref"), asset_id_map)
                component_id = self._resolve_ref(
                    usage.get("component_id") or usage.get("component_ref"),
                    component_id_map,
                )
                if asset_id and component_id:
                    self._upsert_asset_component(conn, asset_id, component_id, usage)

            for relationship in payload.get("relationships", []):
                source_id = self._resolve_ref(
                    relationship.get("source_asset_id") or relationship.get("source_ref"),
                    asset_id_map,
                )
                target_id = self._resolve_ref(
                    relationship.get("target_asset_id") or relationship.get("target_ref"),
                    asset_id_map,
                )
                if source_id and target_id:
                    self._upsert_relationship(conn, source_id, target_id, relationship)
                    self._sync_relationship_details(conn, source_id, target_id, relationship)
                    counters["relationships"] += 1

            vuln_by_component: dict[str, list[str]] = {}
            for finding in payload.get("findings", []):
                asset_id = self._resolve_ref(
                    finding.get("affected_asset_id") or finding.get("asset_ref"),
                    asset_id_map,
                )
                # Findings must reference a REAL component id (FK) or NULL. Grype
                # rewrites bom-refs, so fall back to matching by purl prefix.
                component_id = self._resolve_finding_component(
                    finding.get("component_id") or finding.get("component_ref"),
                    component_id_map,
                    component_purl_map,
                )
                self._upsert_finding(conn, finding, asset_id, component_id, connector_id)
                counters["findings"] += 1
                if component_id and finding.get("finding_type") == "cve":
                    vuln_by_component.setdefault(component_id, []).append(
                        normalize_severity(finding.get("severity"))
                    )

            # Roll up synced CVEs into per-package vulnerability status (the
            # Vulnerabilities screen), so grype-synced data shows without an OSV check.
            for component_id, sevs in vuln_by_component.items():
                self._upsert_vuln_status(
                    conn,
                    component_id,
                    provider="grype",
                    status="vulnerable",
                    vulnerability_count=len(sevs),
                    max_severity=max(sevs, key=lambda s: SEVERITY_RANK.get(s, 0)),
                )

            for sbom in payload.get("raw_sboms", []):
                asset_id = self._resolve_ref(sbom.get("asset_id") or sbom.get("asset_ref"), asset_id_map)
                if asset_id:
                    self._insert_raw_sbom(conn, asset_id, sbom)
                    counters["raw_sboms"] += 1

            conn.execute(
                """
                UPDATE scan_jobs
                SET status = 'completed', completed_at = ?, summary = ?
                WHERE id = ?
                """,
                (now_iso(), to_json(counters), job_id),
            )

        return {"connector_id": connector_id, "job_id": job_id, "summary": counters}

    def ingest_cyclonedx(self, source_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        return self.ingest(cyclonedx_to_ingest_payload(source_type, payload))

    def sync_source_payload(self, source_name: str, payload: dict[str, Any]) -> dict[str, Any]:
        source_type = SYNC_ENDPOINTS.get(source_name, source_name)
        if source_type not in SYNC_SOURCES:
            raise ValueError(f"unsupported sync source: {source_name}")
        if payload.get("bomFormat") == "CycloneDX" or any(
            isinstance(payload.get(key), dict) and payload[key].get("bomFormat") == "CycloneDX"
            for key in ("cyclonedx", "bom", "sbom", "document")
        ):
            return self.ingest_cyclonedx(source_type, payload)
        # Native endpoint-collector batch: syft SBOM ({packages[]}) or grype
        # vulnerabilities ({vulnerabilities[]}). Both carry the {endpoint} block.
        if source_type == "endpoint" and "assets" not in payload and (
            isinstance(payload.get("packages"), list) or isinstance(payload.get("vulnerabilities"), list)
        ):
            return self.ingest(endpoint_batch_to_ingest(payload))
        normalized = {
            **payload,
            "connector": {
                "name": SYNC_SOURCES[source_type]["label"],
                "connector_type": SYNC_SOURCES[source_type]["connector_type"],
                "status": "manual",
                **(payload.get("connector") or {}),
            },
            "scan_metadata": {
                "status": "running",
                "started_at": now_iso(),
                **(payload.get("scan_metadata") or {}),
            },
        }
        return self.ingest(normalized)

    def upsert_connector(self, connector: dict[str, Any]) -> str:
        connector_type = connector.get("connector_type") or connector.get("type") or "custom"
        name = connector.get("name") or connector_type
        connector_id = connector.get("id") or stable_id("connector", connector_type, name)
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO connectors (
                    id, name, connector_type, status, schedule, credentials_ref,
                    scope, config, last_sync_at, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    name = excluded.name,
                    connector_type = excluded.connector_type,
                    status = excluded.status,
                    schedule = excluded.schedule,
                    credentials_ref = excluded.credentials_ref,
                    scope = excluded.scope,
                    config = excluded.config,
                    last_sync_at = excluded.last_sync_at,
                    updated_at = excluded.updated_at
                """,
                (
                    connector_id,
                    name,
                    connector_type,
                    connector.get("status", "enabled"),
                    connector.get("schedule", "manual"),
                    connector.get("credentials_ref", ""),
                    to_json(connector.get("scope") or {}),
                    to_json(connector.get("config") or {}),
                    connector.get("last_sync_at"),
                    now_iso(),
                    now_iso(),
                ),
            )
        return connector_id

    def upsert_scan_job(self, job_id: str, connector_id: str | None, metadata: dict[str, Any]) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO scan_jobs (
                    id, connector_id, status, started_at, completed_at, summary, log
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    connector_id = excluded.connector_id,
                    status = excluded.status,
                    started_at = excluded.started_at,
                    summary = excluded.summary,
                    log = excluded.log
                """,
                (
                    job_id,
                    connector_id,
                    metadata.get("status", "running"),
                    metadata.get("started_at") or now_iso(),
                    metadata.get("completed_at"),
                    to_json(metadata.get("summary") or {}),
                    metadata.get("log", ""),
                ),
            )

    def summary(self) -> dict[str, Any]:
        with self.connect() as conn:
            asset_counts = {
                row["asset_type"]: row["count"]
                for row in conn.execute(
                    "SELECT asset_type, COUNT(*) AS count FROM assets GROUP BY asset_type ORDER BY asset_type"
                )
            }
            finding_counts = {
                row["severity"]: row["count"]
                for row in conn.execute(
                    "SELECT severity, COUNT(*) AS count FROM findings WHERE status != 'resolved' GROUP BY severity"
                )
            }
            total_components = conn.execute("SELECT COUNT(*) FROM components").fetchone()[0]
            total_connectors = conn.execute("SELECT COUNT(*) FROM connectors").fetchone()[0]
            total_assets = conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
            scan_counts = {
                row["scan_status"]: row["count"]
                for row in conn.execute(
                    "SELECT scan_status, COUNT(*) AS count FROM assets GROUP BY scan_status"
                )
            }
            vulnerability_status = row_to_dict(
                conn.execute(
                    """
                    SELECT
                        COUNT(*) AS checked_packages,
                        SUM(CASE WHEN status = 'vulnerable' THEN 1 ELSE 0 END) AS vulnerable_packages,
                        SUM(CASE WHEN status = 'clean' THEN 1 ELSE 0 END) AS clean_packages,
                        SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failed_packages,
                        MAX(checked_at) AS last_checked_at
                    FROM component_vulnerability_status
                    """
                ).fetchone()
            )
            stale_assets = conn.execute(
                "SELECT COUNT(*) FROM assets WHERE status IN ('inactive', 'deleted', 'unknown')"
            ).fetchone()[0]
            top_components = [
                row_to_dict(row)
                for row in conn.execute(
                    """
                    SELECT c.id, c.name, c.version, c.ecosystem, COUNT(ac.asset_id) AS asset_count
                    FROM components c
                    JOIN asset_components ac ON ac.component_id = c.id
                    GROUP BY c.id
                    ORDER BY asset_count DESC, c.name ASC
                    LIMIT 8
                    """
                )
            ]
            latest_findings = [
                row_to_dict(row)
                for row in conn.execute(
                    """
                    SELECT f.*, a.display_name AS asset_name, c.name AS component_name
                    FROM findings f
                    LEFT JOIN assets a ON a.id = f.affected_asset_id
                    LEFT JOIN components c ON c.id = f.component_id
                    ORDER BY
                        CASE f.severity
                            WHEN 'critical' THEN 1
                            WHEN 'high' THEN 2
                            WHEN 'medium' THEN 3
                            WHEN 'low' THEN 4
                            ELSE 5
                        END,
                        f.last_seen_at DESC
                    LIMIT 8
                    """
                )
            ]
            malware_active = conn.execute(
                "SELECT COUNT(*) FROM malware_alerts WHERE status = 'active'"
            ).fetchone()[0]
            # "Ghost" packages: repository dependencies the gbom scanner found via
            # NON-manifest means (asset_components.source = 'repo_scan') that syft's
            # SBOM did NOT declare ('repo_sbom'). This is the "what traditional SBOM
            # scanners miss" signal. Strict: a component counts as ghost only if it
            # has a repo_scan usage and NO repo_sbom usage anywhere.
            ghost = row_to_dict(
                conn.execute(
                    """
                    WITH repo_comp AS (
                        SELECT component_id,
                               MAX(CASE WHEN source = 'repo_scan' THEN 1 ELSE 0 END) AS has_scan,
                               MAX(CASE WHEN source = 'repo_sbom' THEN 1 ELSE 0 END) AS has_sbom
                        FROM asset_components
                        WHERE source IN ('repo_scan', 'repo_sbom')
                        GROUP BY component_id
                    )
                    SELECT COUNT(*) AS repo_packages,
                           SUM(CASE WHEN has_scan = 1 AND has_sbom = 0 THEN 1 ELSE 0 END) AS ghost_packages
                    FROM repo_comp
                    """
                ).fetchone()
            )
            repo_pkgs = ghost.get("repo_packages") or 0
            ghost_pkgs = ghost.get("ghost_packages") or 0
            ghost_pct = round(ghost_pkgs / repo_pkgs * 100, 1) if repo_pkgs else 0.0
        return {
            "assets": {"total": total_assets, "by_type": asset_counts, "stale": stale_assets},
            "components": {"total": total_components, "top": top_components},
            "findings": {"by_severity": finding_counts, "latest": latest_findings},
            "connectors": {"total": total_connectors},
            "scan": {
                "total": total_assets,
                "scanned": scan_counts.get("scanned", 0),
                "pending": scan_counts.get("discovered", 0) + scan_counts.get("scanning", 0),
                "failed": scan_counts.get("failed", 0),
                "by_status": scan_counts,
            },
            "malware": {"active": malware_active},
            "vulnerability_status": vulnerability_status,
            "ghost": {
                "repo_packages": repo_pkgs,
                "ghost_packages": ghost_pkgs,
                "percent": ghost_pct,
            },
        }

    def list_assets(self, params: dict[str, list[str]]) -> list[dict[str, Any]]:
        filters = []
        values: list[Any] = []
        if params.get("asset_type") and params["asset_type"][0]:
            filters.append("a.asset_type = ?")
            values.append(params["asset_type"][0])
        if params.get("search") and params["search"][0]:
            filters.append("(a.display_name LIKE ? OR a.external_id LIKE ? OR a.provider LIKE ?)")
            term = f"%{params['search'][0]}%"
            values.extend([term, term, term])
        if params.get("scan_status") and params["scan_status"][0]:
            filters.append("a.scan_status = ?")
            values.append(params["scan_status"][0])
        if params.get("provider") and params["provider"][0]:
            filters.append("a.provider = ?")
            values.append(params["provider"][0])
        # Endpoint-scoped filters via EXISTS so the COUNT(*) query (assets only) holds.
        if params.get("os") and params["os"][0]:
            filters.append("EXISTS (SELECT 1 FROM endpoint_assets e WHERE e.asset_id = a.id AND e.os_name LIKE ?)")
            values.append(f"%{params['os'][0]}%")
        if params.get("department") and params["department"][0]:
            filters.append("EXISTS (SELECT 1 FROM endpoint_assets e WHERE e.asset_id = a.id AND e.department LIKE ?)")
            values.append(f"%{params['department'][0]}%")
        if params.get("vulnerable") and params["vulnerable"][0] in ("true", "1", "yes"):
            filters.append(
                "EXISTS (SELECT 1 FROM findings f WHERE f.affected_asset_id = a.id "
                "AND f.finding_type = 'cve' AND f.status != 'resolved')"
            )
        where = f"WHERE {' AND '.join(filters)}" if filters else ""
        limit, offset, paginated = paginate_params(params)
        # Counts via index-backed correlated subqueries — NOT a JOIN of
        # asset_components × findings, which Cartesian-explodes for big images
        # (e.g. 9666 components × 1419 findings) before GROUP BY can collapse it.
        select = f"""
            SELECT
                a.*,
                co.name AS connector_name,
                ea.hostname AS endpoint_hostname,
                ea.os_name AS endpoint_os_name,
                ea.os_version AS endpoint_os_version,
                ea.employee_name AS endpoint_employee_name,
                ea.department AS endpoint_department,
                ea.last_checkin_at AS endpoint_last_checkin_at,
                (SELECT COUNT(*) FROM asset_components ac WHERE ac.asset_id = a.id) AS component_count,
                (SELECT COUNT(*) FROM findings f
                   WHERE f.affected_asset_id = a.id AND f.status != 'resolved') AS finding_count
            FROM assets a
            LEFT JOIN connectors co ON co.id = a.connector_id
            LEFT JOIN endpoint_assets ea ON ea.asset_id = a.id
            {where}
            ORDER BY a.last_seen_at DESC, a.display_name ASC
            """
        with self.connect() as conn:
            if paginated:
                total = conn.execute(f"SELECT COUNT(*) FROM assets a {where}", values).fetchone()[0]
                rows = [row_to_dict(r) for r in conn.execute(select + " LIMIT ? OFFSET ?", values + [limit, offset])]
                return {"items": rows, "total": total, "limit": limit, "offset": offset}
            return [row_to_dict(r) for r in conn.execute(select + " LIMIT 500", values)]

    def get_asset(self, asset_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            asset = conn.execute(
                """
                SELECT a.*, co.name AS connector_name
                FROM assets a
                LEFT JOIN connectors co ON co.id = a.connector_id
                WHERE a.id = ?
                """,
                (asset_id,),
            ).fetchone()
            if not asset:
                return None
            data = row_to_dict(asset)
            data["details"] = self._asset_details(conn, asset_id, data["asset_type"])
            # Counts only — the big component/finding lists are fetched paginated
            # via /api/assets/{id}/components and /api/assets/{id}/findings.
            data["component_count"] = conn.execute(
                "SELECT COUNT(*) FROM asset_components WHERE asset_id = ?", (asset_id,)
            ).fetchone()[0]
            data["finding_count"] = conn.execute(
                "SELECT COUNT(*) FROM findings WHERE affected_asset_id = ? AND status != 'resolved'", (asset_id,)
            ).fetchone()[0]
            # Split for the detail tabs: CVE vulnerabilities vs ghost/shadow findings.
            data["vuln_count"] = conn.execute(
                "SELECT COUNT(*) FROM findings WHERE affected_asset_id = ? "
                "AND finding_type = 'cve' AND status != 'resolved'", (asset_id,)
            ).fetchone()[0]
            data["ghost_finding_count"] = conn.execute(
                "SELECT COUNT(*) FROM findings WHERE affected_asset_id = ? "
                "AND finding_type != 'cve' AND status != 'resolved'", (asset_id,)
            ).fetchone()[0]
            data["relationships"] = self.relationships_for_asset(conn, asset_id)
            return data

    def asset_components(self, asset_id: str, params: dict[str, list[str]]) -> Any:
        """Paginated components for one asset, with the per-component finding count."""
        limit, offset, paginated = paginate_params(params)
        select = (
            "SELECT c.id, c.name, c.version, c.ecosystem, c.package_manager, c.purl, c.license, "
            "ac.source, ac.evidence_path, ac.layer_digest, "
            "(SELECT COUNT(*) FROM findings f WHERE f.affected_asset_id = ? "
            " AND f.component_id = c.id AND f.status != 'resolved') AS finding_count "
            "FROM asset_components ac JOIN components c ON c.id = ac.component_id "
            "WHERE ac.asset_id = ? "
            "ORDER BY finding_count DESC, c.ecosystem, c.name, c.version"
        )
        with self.connect() as conn:
            if paginated:
                total = conn.execute(
                    "SELECT COUNT(*) FROM asset_components WHERE asset_id = ?", (asset_id,)
                ).fetchone()[0]
                rows = [row_to_dict(r) for r in conn.execute(
                    select + " LIMIT ? OFFSET ?", (asset_id, asset_id, limit, offset))]
                return {"items": rows, "total": total, "limit": limit, "offset": offset}
            return [row_to_dict(r) for r in conn.execute(select + " LIMIT 500", (asset_id, asset_id))]

    def asset_findings(self, asset_id: str, params: dict[str, list[str]]) -> Any:
        """Paginated findings for one asset, joined to the affected package + fix."""
        limit, offset, paginated = paginate_params(params)
        where = "WHERE f.affected_asset_id = ?"
        values: list[Any] = [asset_id]
        ftype = (params.get("finding_type") or [""])[0]
        if ftype:
            where += " AND f.finding_type = ?"
            values.append(ftype)
        # kind splits the two classes the repo scanner emits: CVEs ('cve') vs the
        # ghost/shadow dependency detections (every other finding_type).
        kind = (params.get("kind") or [""])[0]
        if kind == "cve":
            where += " AND f.finding_type = 'cve'"
        elif kind == "ghost":
            where += " AND f.finding_type != 'cve'"
        select = (
            "SELECT f.id, f.finding_type, f.severity, f.title, f.description, f.fix_recommendation, "
            "f.evidence, f.last_seen_at, "
            "c.name AS component_name, c.version AS component_version, "
            "c.ecosystem AS component_ecosystem, c.purl AS component_purl "
            "FROM findings f LEFT JOIN components c ON c.id = f.component_id "
            f"{where} "
            "ORDER BY CASE f.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 "
            "WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END, f.last_seen_at DESC"
        )
        with self.connect() as conn:
            if paginated:
                total = conn.execute(f"SELECT COUNT(*) FROM findings f {where}", values).fetchone()[0]
                rows = [row_to_dict(r) for r in conn.execute(select + " LIMIT ? OFFSET ?", values + [limit, offset])]
                return {"items": rows, "total": total, "limit": limit, "offset": offset}
            return [row_to_dict(r) for r in conn.execute(select + " LIMIT 500", values)]

    def list_components(self, params: dict[str, list[str]]) -> list[dict[str, Any]]:
        filters = []
        values: list[Any] = []
        if params.get("search") and params["search"][0]:
            filters.append("(c.name LIKE ? OR c.version LIKE ? OR c.purl LIKE ? OR c.cpe LIKE ?)")
            term = f"%{params['search'][0]}%"
            values.extend([term, term, term, term])
        if params.get("ecosystem") and params["ecosystem"][0]:
            filters.append("c.ecosystem = ?")
            values.append(params["ecosystem"][0])
        where = f"WHERE {' AND '.join(filters)}" if filters else ""
        limit, offset, paginated = paginate_params(params)
        # Subqueries, not a ac×f join — same Cartesian-explosion avoidance as list_assets.
        select = f"""
            SELECT
                c.*,
                (SELECT COUNT(DISTINCT ac.asset_id) FROM asset_components ac WHERE ac.component_id = c.id) AS asset_count,
                (SELECT COUNT(*) FROM findings f
                   WHERE f.component_id = c.id AND f.status != 'resolved') AS finding_count
            FROM components c
            {where}
            ORDER BY asset_count DESC, c.name ASC
            """
        with self.connect() as conn:
            if paginated:
                total = conn.execute(f"SELECT COUNT(*) FROM components c {where}", values).fetchone()[0]
                rows = [row_to_dict(r) for r in conn.execute(select + " LIMIT ? OFFSET ?", values + [limit, offset])]
                return {"items": rows, "total": total, "limit": limit, "offset": offset}
            return [row_to_dict(r) for r in conn.execute(select + " LIMIT 500", values)]

    def sbom_packages(self, params: dict[str, list[str]]) -> list[dict[str, Any]]:
        search = (params.get("search") or params.get("q") or [""])[0]
        filters = []
        values: list[Any] = []
        if search:
            filters.append("(c.name LIKE ? OR c.purl LIKE ? OR c.cpe LIKE ?)")
            term = f"%{search}%"
            values.extend([term, term, term])
        where = f"WHERE {' AND '.join(filters)}" if filters else ""
        group_by = """
            GROUP BY
                lower(c.name),
                c.name,
                COALESCE(NULLIF(c.ecosystem, ''), 'unknown'),
                COALESCE(NULLIF(c.package_manager, ''), '')
            """
        limit, offset, paginated = paginate_params(params, default=50)
        select = f"""
            SELECT
                c.name,
                COALESCE(NULLIF(c.ecosystem, ''), 'unknown') AS ecosystem,
                COALESCE(NULLIF(c.package_manager, ''), '') AS package_manager,
                MIN(NULLIF(c.purl, '')) AS sample_purl,
                COUNT(DISTINCT c.id) AS component_count,
                COUNT(DISTINCT COALESCE(NULLIF(c.version, ''), 'unknown')) AS version_count,
                COUNT(DISTINCT ac.asset_id) AS asset_count
            FROM components c
            LEFT JOIN asset_components ac ON ac.component_id = c.id
            {where}
            {group_by}
            ORDER BY asset_count DESC, version_count DESC, c.name ASC
            """
        with self.connect() as conn:
            if paginated:
                total = conn.execute(
                    f"SELECT COUNT(*) FROM (SELECT 1 FROM components c {where} {group_by}) AS sub", values
                ).fetchone()[0]
                rows = [row_to_dict(r) for r in conn.execute(select + " LIMIT ? OFFSET ?", values + [limit, offset])]
                return {"items": rows, "total": total, "limit": limit, "offset": offset}
            return [row_to_dict(r) for r in conn.execute(select + " LIMIT 100", values)]

    def sbom_versions(self, params: dict[str, list[str]]) -> list[dict[str, Any]]:
        name = (params.get("name") or [""])[0]
        if not name:
            return []
        filters = ["lower(c.name) = lower(?)"]
        values: list[Any] = [name]
        ecosystem = (params.get("ecosystem") or [""])[0]
        package_manager = (params.get("package_manager") or [""])[0]
        if ecosystem and ecosystem != "unknown":
            filters.append("c.ecosystem = ?")
            values.append(ecosystem)
        if package_manager:
            filters.append("c.package_manager = ?")
            values.append(package_manager)
        where = f"WHERE {' AND '.join(filters)}"
        limit, offset, paginated = paginate_params(params, default=50)
        select = f"""
            SELECT
                COALESCE(NULLIF(c.version, ''), 'unknown') AS version,
                COUNT(DISTINCT c.id) AS component_count,
                COUNT(DISTINCT ac.asset_id) AS asset_count,
                COUNT(DISTINCT f.id) AS finding_count,
                MAX(c.last_seen_at) AS last_seen_at,
                MIN(NULLIF(c.purl, '')) AS sample_purl
            FROM components c
            LEFT JOIN asset_components ac ON ac.component_id = c.id
            LEFT JOIN findings f ON f.component_id = c.id AND f.status != 'resolved'
            {where}
            GROUP BY COALESCE(NULLIF(c.version, ''), 'unknown')
            ORDER BY asset_count DESC, version ASC
            """
        with self.connect() as conn:
            if paginated:
                total = conn.execute(
                    f"SELECT COUNT(*) FROM (SELECT 1 FROM components c {where} "
                    f"GROUP BY COALESCE(NULLIF(c.version, ''), 'unknown')) AS sub", values
                ).fetchone()[0]
                rows = [row_to_dict(r) for r in conn.execute(select + " LIMIT ? OFFSET ?", values + [limit, offset])]
                return {"items": rows, "total": total, "limit": limit, "offset": offset}
            return [row_to_dict(r) for r in conn.execute(select + " LIMIT 200", values)]

    def sbom_assets(self, params: dict[str, list[str]]) -> list[dict[str, Any]]:
        name = (params.get("name") or [""])[0]
        version = (params.get("version") or [""])[0]
        if not name or not version:
            return []
        filters = ["lower(c.name) = lower(?)", "COALESCE(NULLIF(c.version, ''), 'unknown') = ?"]
        values: list[Any] = [name, version]
        ecosystem = (params.get("ecosystem") or [""])[0]
        package_manager = (params.get("package_manager") or [""])[0]
        if ecosystem and ecosystem != "unknown":
            filters.append("c.ecosystem = ?")
            values.append(ecosystem)
        if package_manager:
            filters.append("c.package_manager = ?")
            values.append(package_manager)
        where = f"WHERE {' AND '.join(filters)}"
        limit, offset, paginated = paginate_params(params)
        select = f"""
            SELECT
                a.id,
                a.asset_type,
                a.provider,
                a.external_id,
                a.display_name,
                a.owner,
                a.environment,
                c.name AS component_name,
                c.version AS component_version,
                c.ecosystem,
                c.package_manager,
                c.purl,
                ac.source,
                ac.evidence_path,
                ac.layer_digest,
                ac.evidence,
                ac.last_seen_at AS usage_last_seen_at,
                (
                    SELECT COUNT(*)
                    FROM findings f
                    WHERE f.affected_asset_id = a.id
                      AND f.component_id = c.id
                      AND f.status != 'resolved'
                ) AS finding_count
            FROM asset_components ac
            JOIN assets a ON a.id = ac.asset_id
            JOIN components c ON c.id = ac.component_id
            {where}
            ORDER BY a.asset_type, a.display_name, ac.evidence_path
            """
        with self.connect() as conn:
            if paginated:
                total = conn.execute(
                    f"SELECT COUNT(*) FROM asset_components ac "
                    f"JOIN assets a ON a.id = ac.asset_id JOIN components c ON c.id = ac.component_id {where}",
                    values,
                ).fetchone()[0]
                rows = [row_to_dict(r) for r in conn.execute(select + " LIMIT ? OFFSET ?", values + [limit, offset])]
                return {"items": rows, "total": total, "limit": limit, "offset": offset}
            return [row_to_dict(r) for r in conn.execute(select + " LIMIT 500", values)]

    def list_vulnerability_status(self, params: dict[str, list[str]]) -> list[dict[str, Any]]:
        filters = []
        values: list[Any] = []
        search = (params.get("search") or params.get("q") or [""])[0]
        if search:
            filters.append("(c.name LIKE ? OR c.purl LIKE ? OR c.cpe LIKE ?)")
            term = f"%{search}%"
            values.extend([term, term, term])
        status = (params.get("status") or [""])[0]
        if status:
            filters.append("COALESCE(vs.status, 'unknown') = ?")
            values.append(status)
        where = f"WHERE {' AND '.join(filters)}" if filters else ""
        with self.connect() as conn:
            return [
                row_to_dict(row)
                for row in conn.execute(
                    f"""
                    SELECT
                        c.id AS component_id,
                        c.name,
                        c.version,
                        c.ecosystem,
                        c.package_manager,
                        c.purl,
                        COUNT(DISTINCT ac.asset_id) AS target_count,
                        COALESCE(vs.status, 'unknown') AS vulnerability_status,
                        COALESCE(vs.vulnerability_count, 0) AS vulnerability_count,
                        COALESCE(vs.max_severity, 'unknown') AS max_severity,
                        vs.checked_at,
                        vs.error
                    FROM components c
                    LEFT JOIN asset_components ac ON ac.component_id = c.id
                    LEFT JOIN component_vulnerability_status vs ON vs.component_id = c.id
                    {where}
                    GROUP BY c.id
                    ORDER BY
                        CASE COALESCE(vs.max_severity, 'unknown')
                            WHEN 'critical' THEN 1
                            WHEN 'high' THEN 2
                            WHEN 'medium' THEN 3
                            WHEN 'low' THEN 4
                            WHEN 'info' THEN 5
                            ELSE 6
                        END,
                        vulnerability_count DESC,
                        target_count DESC,
                        c.name ASC
                    LIMIT 500
                    """,
                    values,
                )
            ]

    def _upsert_vuln_status(
        self,
        conn: sqlite3.Connection,
        component_id: str,
        provider: str,
        status: str,
        vulnerability_count: int,
        max_severity: str,
        error: str = "",
        raw_response: dict[str, Any] | None = None,
    ) -> None:
        """Upsert per-component vulnerability status on an existing connection."""
        conn.execute(
            """
            INSERT INTO component_vulnerability_status (
                component_id, provider, status, vulnerability_count, max_severity,
                checked_at, error, raw_response
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(component_id, provider) DO UPDATE SET
                status = excluded.status,
                vulnerability_count = excluded.vulnerability_count,
                max_severity = excluded.max_severity,
                checked_at = excluded.checked_at,
                error = excluded.error,
                raw_response = excluded.raw_response
            """,
            (
                component_id,
                provider,
                status,
                vulnerability_count,
                max_severity,
                now_iso(),
                error,
                to_json(raw_response or {}),
            ),
        )

    def list_findings(self, params: dict[str, list[str]]) -> list[dict[str, Any]]:
        filters = []
        values: list[Any] = []
        if params.get("severity") and params["severity"][0]:
            filters.append("f.severity = ?")
            values.append(params["severity"][0])
        if params.get("finding_type") and params["finding_type"][0]:
            filters.append("f.finding_type = ?")
            values.append(params["finding_type"][0])
        if params.get("status") and params["status"][0]:
            filters.append("f.status = ?")
            values.append(params["status"][0])
        where = f"WHERE {' AND '.join(filters)}" if filters else ""
        with self.connect() as conn:
            return [
                row_to_dict(row)
                for row in conn.execute(
                    f"""
                    SELECT
                        f.*,
                        a.display_name AS asset_name,
                        a.asset_type,
                        c.name AS component_name,
                        c.version AS component_version,
                        co.name AS connector_name
                    FROM findings f
                    LEFT JOIN assets a ON a.id = f.affected_asset_id
                    LEFT JOIN components c ON c.id = f.component_id
                    LEFT JOIN connectors co ON co.id = f.source_connector_id
                    {where}
                    ORDER BY
                        CASE f.severity
                            WHEN 'critical' THEN 1
                            WHEN 'high' THEN 2
                            WHEN 'medium' THEN 3
                            WHEN 'low' THEN 4
                            ELSE 5
                        END,
                        f.last_seen_at DESC
                    LIMIT 500
                    """,
                    values,
                )
            ]

    def list_vulnerabilities(self, params: dict[str, list[str]]) -> list[dict[str, Any]]:
        """The single Vulnerabilities view: CVE findings joined to package + asset.

        Replaces both the old per-component status list and the Findings page for
        vulnerabilities. Filters: severity, search (CVE id / package name / purl).
        """
        filters = ["f.finding_type = 'cve'"]
        values: list[Any] = []
        if params.get("severity") and params["severity"][0]:
            filters.append("f.severity = ?")
            values.append(params["severity"][0])
        search = (params.get("search") or params.get("q") or [""])[0]
        if search:
            filters.append("(f.title LIKE ? OR c.name LIKE ? OR c.purl LIKE ?)")
            term = f"%{search}%"
            values.extend([term, term, term])
        if params.get("ecosystem") and params["ecosystem"][0]:
            filters.append("c.ecosystem = ?")
            values.append(params["ecosystem"][0])
        if params.get("asset_type") and params["asset_type"][0]:
            filters.append("a.asset_type = ?")
            values.append(params["asset_type"][0])
        where = f"WHERE {' AND '.join(filters)}"
        limit, offset, paginated = paginate_params(params)
        select = f"""
            SELECT
                f.id, f.finding_type, f.severity, f.title, f.description,
                f.fix_recommendation, f.evidence, f.first_seen_at, f.last_seen_at,
                a.id AS asset_id,
                a.display_name AS asset_name,
                a.asset_type,
                c.name AS component_name,
                c.version AS component_version,
                c.ecosystem AS component_ecosystem,
                c.purl AS component_purl
            FROM findings f
            LEFT JOIN assets a ON a.id = f.affected_asset_id
            LEFT JOIN components c ON c.id = f.component_id
            {where}
            ORDER BY
                CASE f.severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                END,
                f.last_seen_at DESC
            """
        with self.connect() as conn:
            if paginated:
                total = conn.execute(
                    "SELECT COUNT(*) FROM findings f "
                    "LEFT JOIN components c ON c.id = f.component_id "
                    f"LEFT JOIN assets a ON a.id = f.affected_asset_id {where}",
                    values,
                ).fetchone()[0]
                rows = [row_to_dict(r) for r in conn.execute(select + " LIMIT ? OFFSET ?", values + [limit, offset])]
                return {"items": rows, "total": total, "limit": limit, "offset": offset}
            return [row_to_dict(r) for r in conn.execute(select + " LIMIT 500", values)]

    def list_connectors(self) -> list[dict[str, Any]]:
        with self.connect() as conn:
            connectors = [
                row_to_dict(row)
                for row in conn.execute(
                    """
                    SELECT
                        co.*,
                        COUNT(DISTINCT a.id) AS asset_count,
                        COUNT(DISTINCT sj.id) AS job_count
                    FROM connectors co
                    LEFT JOIN assets a ON a.connector_id = co.id
                    LEFT JOIN scan_jobs sj ON sj.connector_id = co.id
                    GROUP BY co.id
                    ORDER BY co.updated_at DESC
                    """
                )
            ]
            secret_fields: dict[str, list[str]] = {}
            for r in conn.execute("SELECT connector_id, field FROM connector_secrets"):
                secret_fields.setdefault(r["connector_id"], []).append(r["field"])
        for c in connectors:
            c["secrets_configured"] = secret_fields.get(c["id"], [])
        return connectors

    def get_connector(self, connector_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT
                    co.*,
                    COUNT(DISTINCT a.id) AS asset_count,
                    COUNT(DISTINCT sj.id) AS job_count
                FROM connectors co
                LEFT JOIN assets a ON a.connector_id = co.id
                LEFT JOIN scan_jobs sj ON sj.connector_id = co.id
                WHERE co.id = ?
                GROUP BY co.id
                """,
                (connector_id,),
            ).fetchone()
        if row is None:
            return None
        out = row_to_dict(row)
        out["secrets_configured"] = self.configured_secret_fields(connector_id)
        return out

    def save_connector(self, body: dict[str, Any], connector_id: str | None = None) -> dict[str, Any]:
        """Create/update a scanner source (registry or service) from the UI."""
        source_type = str(body.get("source_type") or "").lower()
        if source_type and source_type not in SCANNER_SOURCE_TYPES and source_type != "endpoint":
            raise ValueError(
                f"unknown source_type '{source_type}'. Valid: {', '.join(sorted(SCANNER_SOURCE_TYPES))}"
            )
        kind = body.get("kind") or (
            "registry" if source_type in REGISTRY_SOURCE_TYPES
            else "repo" if source_type in REPO_SOURCE_TYPES
            else "service"
        )
        name = body.get("name") or source_type or "source"
        connector_id = connector_id or body.get("id") or stable_id("connector", source_type, name)

        # Pull credential values out of connection.auth: they are stored ENCRYPTED in
        # connector_secrets, never in the config JSON. A provided value replaces the
        # stored one; an empty/omitted field keeps the existing secret (write-only UX).
        connection = dict(body.get("connection") or {})
        auth = dict(connection.get("auth") or {})
        # A provided value replaces the stored secret; an empty/omitted field — or the
        # "***" mask the API echoes to the UI — keeps the existing secret, so a form
        # round-trip can't clobber a real credential with the mask.
        secrets = {
            f: str(auth[f]) for f in SECRET_AUTH_FIELDS
            if auth.get(f) and str(auth[f]) != SECRET_MASK
        }
        for f in SECRET_AUTH_FIELDS:
            auth.pop(f, None)  # never persist a secret field in the config
        if secrets:
            import crypto
            if not crypto.key_present():
                raise ValueError("SUPPLYDRIFT_SECRET_KEY is required to store credentials")
        if auth:
            connection["auth"] = auth
        elif "auth" in connection:
            connection.pop("auth")
        unsafe_fields = sorted(set(_secret_like_connection_fields(connection)))
        if unsafe_fields:
            raise ValueError(
                "secret-like connector fields must use connection.auth password/token/secret "
                "or *_env references: " + ", ".join(unsafe_fields)
            )

        config = {
            "kind": kind,
            "source_type": source_type,
            "connection": connection,
            "scan": body.get("scan") or {},
            "discovery": body.get("discovery") or {},
            "enabled": bool(body.get("enabled", True)),
        }
        connector_type = f"{kind}:{source_type}" if source_type else kind
        now = now_iso()
        with self.connect() as conn:
            existing = conn.execute(
                "SELECT created_at FROM connectors WHERE id = ?", (connector_id,)
            ).fetchone()
            created = existing["created_at"] if existing else now
            conn.execute(
                """
                INSERT INTO connectors (
                    id, name, connector_type, status, schedule, credentials_ref,
                    scope, config, last_sync_at, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    name = excluded.name,
                    connector_type = excluded.connector_type,
                    status = excluded.status,
                    schedule = excluded.schedule,
                    credentials_ref = excluded.credentials_ref,
                    scope = excluded.scope,
                    config = excluded.config,
                    updated_at = excluded.updated_at
                """,
                (
                    connector_id,
                    name,
                    connector_type,
                    body.get("status", "enabled"),
                    body.get("schedule", "manual"),
                    body.get("credentials_ref", ""),
                    to_json(body.get("scope") or {}),
                    to_json(config),
                    body.get("last_sync_at"),
                    created,
                    now,
                ),
            )
            for field, value in secrets.items():
                conn.execute(
                    "INSERT INTO connector_secrets (connector_id, field, ciphertext, updated_at) "
                    "VALUES (?, ?, ?, ?) ON CONFLICT(connector_id, field) "
                    "DO UPDATE SET ciphertext = excluded.ciphertext, updated_at = excluded.updated_at",
                    (connector_id, field, crypto.encrypt(value), now))
        return self.get_connector(connector_id)

    def delete_connector(self, connector_id: str) -> bool:
        with self.connect() as conn:
            cur = conn.execute("DELETE FROM connectors WHERE id = ?", (connector_id,))
            return cur.rowcount > 0

    # ── connector credentials (encrypted at rest) ───────────────────────────
    def configured_secret_fields(self, connector_id: str) -> list[str]:
        with self.connect() as conn:
            return [r["field"] for r in conn.execute(
                "SELECT field FROM connector_secrets WHERE connector_id = ?", (connector_id,))]

    def get_connector_secrets(self, connector_id: str) -> dict[str, str]:
        """Decrypted secrets for a connector (runner config only — never to the UI)."""
        import crypto
        out: dict[str, str] = {}
        with self.connect() as conn:
            for r in conn.execute(
                    "SELECT field, ciphertext FROM connector_secrets WHERE connector_id = ?", (connector_id,)):
                value = crypto.decrypt(r["ciphertext"])
                if value is not None:
                    out[r["field"]] = value
        return out

    def scanner_config(self, include_secrets: bool = False,
                       only_connector_id: str | None = None) -> dict[str, Any]:
        """Assemble enabled connectors into the scanner config schema.

        Serves every runner: the image-scanner reads ``registries``/``services``,
        the GitHub runner reads ``github`` — one feed, each runner takes its section.

        ``include_secrets`` controls whether decrypted credential *values* are inlined.
        Only bearer-authed runner tokens get real secrets; human callers
        (the Sources UI) get the same structure with secret values masked, matching the
        UI contract of showing field *names, never values*.

        ``only_connector_id`` scopes secret disclosure to a single connector: the
        topology of every connector is still returned, but real secret values are
        inlined ONLY for the requested one (all others masked). A runner passes the
        connector_id of the job it just claimed, so a runner process compromised while
        scanning an untrusted target only holds the secret it is actively using — not
        every connector's credentials.
        """
        registries: list[dict[str, Any]] = []
        services: list[dict[str, Any]] = []
        github: list[dict[str, Any]] = []
        with self.connect() as conn:
            rows = conn.execute("SELECT id, name, config FROM connectors").fetchall()
        for row in rows:
            cfg = from_json(row["config"], {})
            if not cfg.get("enabled", True):
                continue
            source_type = cfg.get("source_type")
            if source_type not in SCANNER_SOURCE_TYPES:
                continue
            # Inject decrypted credentials inline as provider:static — the runner uses
            # them directly. This is the ONLY place stored secrets leave the platform
            # (to a bearer-authed runner over the internal network).
            connection = dict(cfg.get("connection") or {})
            secrets = self.get_connector_secrets(row["id"])
            if secrets:
                auth = dict(connection.get("auth") or {})
                reveal = include_secrets and (
                    only_connector_id is None or row["id"] == only_connector_id
                )
                if reveal:
                    auth.update(secrets)
                else:
                    # Mask values but keep field names so the UI (and runners scoped to a
                    # different connector) still see structure without the secret value.
                    auth.update({k: SECRET_MASK for k in secrets})
                auth["provider"] = "static"
                connection["auth"] = auth
            block: dict[str, Any] = {
                "id": row["id"],
                "connector_id": row["id"],
                "name": row["name"],
                "type": source_type,
                "connection": connection,
            }
            kind = cfg.get("kind")
            if kind == "registry":
                if cfg.get("scan"):
                    block["scan"] = cfg["scan"]
                registries.append(block)
            elif kind == "repo":
                if cfg.get("scan"):
                    block["scan"] = cfg["scan"]
                github.append(block)
            else:
                if cfg.get("discovery"):
                    block["discovery"] = cfg["discovery"]
                services.append(block)
        return {
            "version": 2,
            "platform": {"url": PUBLIC_URL, "push": True},
            "registries": registries,
            "services": services,
            "github": github,
        }

    def graph(self, params: dict[str, list[str]]) -> dict[str, Any]:
        # Clamp so a client can't request an unbounded result set (DoS).
        limit = max(1, min(5000, _int_param(params, "limit", 500)))
        with self.connect() as conn:
            assets = conn.execute(
                """
                SELECT a.id, a.display_name, a.asset_type, a.provider, a.environment, a.owner,
                    COUNT(DISTINCT f.id) AS finding_count
                FROM assets a
                LEFT JOIN findings f ON f.affected_asset_id = a.id
                GROUP BY a.id
                ORDER BY a.asset_type, a.display_name
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            edges = conn.execute(
                "SELECT source_asset_id, target_asset_id, relationship_type FROM asset_relationships"
            ).fetchall()
        ids = {a["id"] for a in assets}
        nodes = [
            {
                "id": a["id"],
                "label": a["display_name"],
                "asset_type": a["asset_type"],
                "provider": a["provider"],
                "environment": a["environment"],
                "owner": a["owner"],
                "finding_count": a["finding_count"],
            }
            for a in assets
        ]
        edge_list = [
            {"source": e["source_asset_id"], "target": e["target_asset_id"], "type": e["relationship_type"]}
            for e in edges
            if e["source_asset_id"] in ids and e["target_asset_id"] in ids
        ]
        return {"nodes": nodes, "edges": edge_list}

    def blast_radius(self, params: dict[str, list[str]]) -> dict[str, Any]:
        component_id = params.get("component_id", [""])[0]
        query = params.get("q", [""])[0]
        with self.connect() as conn:
            component = None
            if component_id:
                component = conn.execute("SELECT * FROM components WHERE id = ?", (component_id,)).fetchone()
            elif query:
                component = conn.execute(
                    """
                    SELECT * FROM components
                    WHERE name LIKE ? OR purl LIKE ? OR cpe LIKE ?
                    ORDER BY name ASC
                    LIMIT 1
                    """,
                    (f"%{query}%", f"%{query}%", f"%{query}%"),
                ).fetchone()
            if not component:
                return {"component": None, "assets": [], "findings": [], "relationships": []}
            component_data = row_to_dict(component)
            assets = [
                row_to_dict(row)
                for row in conn.execute(
                    """
                    SELECT a.*, ac.source, ac.evidence_path, ac.package_manager AS usage_package_manager
                    FROM asset_components ac
                    JOIN assets a ON a.id = ac.asset_id
                    WHERE ac.component_id = ?
                    ORDER BY a.asset_type, a.display_name
                    """,
                    (component_data["id"],),
                )
            ]
            findings = [
                row_to_dict(row)
                for row in conn.execute(
                    """
                    SELECT f.*, a.display_name AS asset_name, a.asset_type
                    FROM findings f
                    LEFT JOIN assets a ON a.id = f.affected_asset_id
                    WHERE f.component_id = ?
                    ORDER BY
                        CASE f.severity
                            WHEN 'critical' THEN 1
                            WHEN 'high' THEN 2
                            WHEN 'medium' THEN 3
                            WHEN 'low' THEN 4
                            ELSE 5
                        END
                    """,
                    (component_data["id"],),
                )
            ]
            asset_ids = [a["id"] for a in assets]
            relationships = []
            if asset_ids:
                placeholders = ",".join("?" for _ in asset_ids)
                relationships = [
                    row_to_dict(row)
                    for row in conn.execute(
                        f"""
                        SELECT
                            ar.*,
                            s.display_name AS source_name,
                            s.asset_type AS source_type,
                            t.display_name AS target_name,
                            t.asset_type AS target_type
                        FROM asset_relationships ar
                        JOIN assets s ON s.id = ar.source_asset_id
                        JOIN assets t ON t.id = ar.target_asset_id
                        WHERE ar.source_asset_id IN ({placeholders})
                           OR ar.target_asset_id IN ({placeholders})
                        ORDER BY source_name, relationship_type, target_name
                        """,
                        asset_ids + asset_ids,
                    )
                ]
            return {"component": component_data, "assets": assets, "findings": findings, "relationships": relationships}

    def relationships_for_asset(self, conn: sqlite3.Connection, asset_id: str) -> list[dict[str, Any]]:
        return [
            row_to_dict(row)
            for row in conn.execute(
                """
                SELECT
                    ar.*,
                    s.display_name AS source_name,
                    s.asset_type AS source_type,
                    t.display_name AS target_name,
                    t.asset_type AS target_type
                FROM asset_relationships ar
                JOIN assets s ON s.id = ar.source_asset_id
                JOIN assets t ON t.id = ar.target_asset_id
                WHERE ar.source_asset_id = ? OR ar.target_asset_id = ?
                ORDER BY source_name, relationship_type, target_name
                """,
                (asset_id, asset_id),
            )
        ]

    def _resolve_ref(self, value: str | None, ref_map: dict[str, str]) -> str | None:
        if not value:
            return None
        return ref_map.get(value, value)

    def _resolve_finding_component(
        self,
        value: str | None,
        id_map: dict[str, str],
        purl_map: dict[str, str],
    ) -> str | None:
        """Resolve a finding's component to a REAL component id, or None.

        Never returns an unmapped ref (would violate the findings FK). Falls back
        to purl matching because vulnerability scanners (grype) rewrite bom-refs
        but keep the purl — the ``&package-id=`` qualifier is stripped to match.
        """
        if not value:
            return None
        if value in id_map:
            return id_map[value]
        v = str(value)
        for key in (v, v.split("&package-id=")[0], v.split("?")[0]):
            if key in purl_map:
                return purl_map[key]
        return None

    def _upsert_asset(
        self, conn: sqlite3.Connection, asset: dict[str, Any], connector_id: str | None, scanned: bool = True
    ) -> str:
        asset_type = asset["asset_type"]
        provider = asset.get("provider", "custom")
        external_id = asset.get("external_id") or asset.get("id") or asset.get("display_name")
        asset_id = asset.get("id") or stable_id("asset", asset_type, provider, external_id)
        timestamp = now_iso()
        scan_status = "scanned" if scanned else "discovered"
        last_scanned_at = timestamp if scanned else None
        conn.execute(
            """
            INSERT INTO assets (
                id, asset_type, provider, external_id, display_name, connector_id,
                owner, environment, status, scan_status, last_scanned_at,
                first_seen_at, last_seen_at, tags, raw_metadata
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                asset_type = excluded.asset_type,
                provider = excluded.provider,
                external_id = excluded.external_id,
                display_name = excluded.display_name,
                connector_id = COALESCE(excluded.connector_id, assets.connector_id),
                owner = excluded.owner,
                environment = excluded.environment,
                status = excluded.status,
                -- a scan upgrades to 'scanned'; a discovery-only re-sync never downgrades.
                scan_status = CASE WHEN excluded.scan_status = 'scanned' THEN 'scanned' ELSE assets.scan_status END,
                last_scanned_at = CASE WHEN excluded.scan_status = 'scanned'
                                       THEN excluded.last_scanned_at ELSE assets.last_scanned_at END,
                last_seen_at = excluded.last_seen_at,
                tags = excluded.tags,
                raw_metadata = excluded.raw_metadata
            """,
            (
                asset_id,
                asset_type,
                provider,
                external_id,
                asset.get("display_name") or external_id,
                connector_id,
                asset.get("owner", ""),
                asset.get("environment", ""),
                asset.get("status", "active"),
                scan_status,
                last_scanned_at,
                asset.get("first_seen_at", timestamp),
                asset.get("last_seen_at", timestamp),
                to_json(asset.get("tags") or []),
                to_json(asset.get("raw_metadata") or asset.get("metadata") or {}),
            ),
        )
        self._upsert_asset_details(conn, asset_id, asset_type, asset.get("details") or {})
        return asset_id

    def _upsert_asset_details(
        self,
        conn: sqlite3.Connection,
        asset_id: str,
        asset_type: str,
        details: dict[str, Any],
    ) -> None:
        if asset_type == "endpoint":
            conn.execute(
                """
                INSERT INTO endpoint_assets (
                    asset_id, endpoint_id, hostname, serial_number, os_name, os_version,
                    architecture, device_type, mdm_id, employee_id, employee_email,
                    employee_name, department, location, last_checkin_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(asset_id) DO UPDATE SET
                    endpoint_id = excluded.endpoint_id,
                    hostname = excluded.hostname,
                    serial_number = excluded.serial_number,
                    os_name = excluded.os_name,
                    os_version = excluded.os_version,
                    architecture = excluded.architecture,
                    device_type = excluded.device_type,
                    mdm_id = excluded.mdm_id,
                    employee_id = excluded.employee_id,
                    employee_email = excluded.employee_email,
                    employee_name = excluded.employee_name,
                    department = excluded.department,
                    location = excluded.location,
                    last_checkin_at = excluded.last_checkin_at
                """,
                (
                    asset_id,
                    details.get("endpoint_id", ""),
                    details.get("hostname", ""),
                    details.get("serial_number", ""),
                    details.get("os_name", ""),
                    details.get("os_version", ""),
                    details.get("architecture", ""),
                    details.get("device_type", ""),
                    details.get("mdm_id", ""),
                    details.get("employee_id", ""),
                    details.get("employee_email", ""),
                    details.get("employee_name", ""),
                    details.get("department", ""),
                    details.get("location", ""),
                    details.get("last_checkin_at", ""),
                ),
            )
        elif asset_type == "repository":
            conn.execute(
                """
                INSERT INTO repository_assets (
                    asset_id, git_provider, org_name, repo_name, full_name, repo_url,
                    default_branch, visibility, owner_team, last_commit_sha, last_commit_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(asset_id) DO UPDATE SET
                    git_provider = excluded.git_provider,
                    org_name = excluded.org_name,
                    repo_name = excluded.repo_name,
                    full_name = excluded.full_name,
                    repo_url = excluded.repo_url,
                    default_branch = excluded.default_branch,
                    visibility = excluded.visibility,
                    owner_team = excluded.owner_team,
                    last_commit_sha = excluded.last_commit_sha,
                    last_commit_at = excluded.last_commit_at
                """,
                (
                    asset_id,
                    details.get("git_provider", details.get("provider", "")),
                    details.get("org_name", ""),
                    details.get("repo_name", ""),
                    details.get("full_name", ""),
                    details.get("repo_url", ""),
                    details.get("default_branch", ""),
                    details.get("visibility", ""),
                    details.get("owner_team", ""),
                    details.get("last_commit_sha", ""),
                    details.get("last_commit_at", ""),
                ),
            )
        elif asset_type == "container_image":
            provenance = details.get("provenance") or {}
            conn.execute(
                """
                INSERT INTO container_image_assets (
                    asset_id, registry_type, registry_url, account_id, project_id,
                    repository, image_name, tag, digest, architecture, os, pushed_at, pulled_at,
                    discovery_source, source_reference
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(asset_id) DO UPDATE SET
                    registry_type = excluded.registry_type,
                    registry_url = excluded.registry_url,
                    account_id = excluded.account_id,
                    project_id = excluded.project_id,
                    repository = excluded.repository,
                    image_name = excluded.image_name,
                    tag = excluded.tag,
                    digest = excluded.digest,
                    architecture = excluded.architecture,
                    os = excluded.os,
                    pushed_at = excluded.pushed_at,
                    pulled_at = excluded.pulled_at,
                    discovery_source = excluded.discovery_source,
                    source_reference = excluded.source_reference
                """,
                (
                    asset_id,
                    details.get("registry_type", ""),
                    details.get("registry_url", ""),
                    details.get("account_id", ""),
                    details.get("project_id", ""),
                    details.get("repository", ""),
                    details.get("image_name", ""),
                    details.get("tag", ""),
                    details.get("digest", ""),
                    details.get("architecture", ""),
                    details.get("os", ""),
                    details.get("pushed_at", ""),
                    details.get("pulled_at", ""),
                    first_value(provenance.get("discovery_source"), details.get("discovery_source")),
                    first_value(
                        provenance.get("source_repository"),
                        provenance.get("discovered_in"),
                        details.get("source_reference"),
                    ),
                ),
            )
        elif asset_type == "k8s_workload":
            conn.execute(
                """
                INSERT INTO k8s_workload_assets (
                    asset_id, cluster_asset_id, cloud_provider, account_id, project_id,
                    region, cluster_name, namespace, workload_kind, workload_name,
                    pod_name, container_name, service_account, image_asset_id,
                    image_reference, image_digest, node_name
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(asset_id) DO UPDATE SET
                    cluster_asset_id = excluded.cluster_asset_id,
                    cloud_provider = excluded.cloud_provider,
                    account_id = excluded.account_id,
                    project_id = excluded.project_id,
                    region = excluded.region,
                    cluster_name = excluded.cluster_name,
                    namespace = excluded.namespace,
                    workload_kind = excluded.workload_kind,
                    workload_name = excluded.workload_name,
                    pod_name = excluded.pod_name,
                    container_name = excluded.container_name,
                    service_account = excluded.service_account,
                    image_asset_id = excluded.image_asset_id,
                    image_reference = excluded.image_reference,
                    image_digest = excluded.image_digest,
                    node_name = excluded.node_name
                """,
                (
                    asset_id,
                    details.get("cluster_asset_id", ""),
                    details.get("cloud_provider", ""),
                    details.get("account_id", ""),
                    details.get("project_id", ""),
                    details.get("region", ""),
                    details.get("cluster_name", ""),
                    details.get("namespace", ""),
                    details.get("workload_kind", ""),
                    details.get("workload_name", ""),
                    details.get("pod_name", ""),
                    details.get("container_name", ""),
                    details.get("service_account", ""),
                    details.get("image_asset_id", ""),
                    details.get("image_reference", ""),
                    details.get("image_digest", ""),
                    details.get("node_name", ""),
                ),
            )
        elif asset_type in {"ecs_service", "gcp_workload", "cloud_workload"}:
            conn.execute(
                """
                INSERT INTO cloud_workload_assets (
                    asset_id, platform, account_id, project_id, region, cluster_name,
                    service_name, task_definition_arn, task_arn, revision,
                    namespace, container_name, image_asset_id, image_reference, image_digest
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(asset_id) DO UPDATE SET
                    platform = excluded.platform,
                    account_id = excluded.account_id,
                    project_id = excluded.project_id,
                    region = excluded.region,
                    cluster_name = excluded.cluster_name,
                    service_name = excluded.service_name,
                    task_definition_arn = excluded.task_definition_arn,
                    task_arn = excluded.task_arn,
                    revision = excluded.revision,
                    namespace = excluded.namespace,
                    container_name = excluded.container_name,
                    image_asset_id = excluded.image_asset_id,
                    image_reference = excluded.image_reference,
                    image_digest = excluded.image_digest
                """,
                (
                    asset_id,
                    details.get("platform", asset_type),
                    details.get("account_id", ""),
                    details.get("project_id", ""),
                    details.get("region", ""),
                    details.get("cluster_name", ""),
                    details.get("service_name", ""),
                    details.get("task_definition_arn", ""),
                    details.get("task_arn", ""),
                    details.get("revision", ""),
                    details.get("namespace", ""),
                    details.get("container_name", ""),
                    details.get("image_asset_id", ""),
                    details.get("image_reference", ""),
                    details.get("image_digest", ""),
                ),
            )
        elif asset_type == "ami":
            conn.execute(
                """
                INSERT INTO ami_assets (
                    asset_id, account_id, region, ami_id, ami_name, owner_id,
                    creation_date, base_os, architecture, state
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(asset_id) DO UPDATE SET
                    account_id = excluded.account_id,
                    region = excluded.region,
                    ami_id = excluded.ami_id,
                    ami_name = excluded.ami_name,
                    owner_id = excluded.owner_id,
                    creation_date = excluded.creation_date,
                    base_os = excluded.base_os,
                    architecture = excluded.architecture,
                    state = excluded.state
                """,
                (
                    asset_id,
                    details.get("account_id", ""),
                    details.get("region", ""),
                    details.get("ami_id", ""),
                    details.get("ami_name", ""),
                    details.get("owner_id", ""),
                    details.get("creation_date", ""),
                    details.get("base_os", ""),
                    details.get("architecture", ""),
                    details.get("state", ""),
                ),
            )

    def _asset_details(self, conn: sqlite3.Connection, asset_id: str, asset_type: str) -> dict[str, Any]:
        table_by_type = {
            "endpoint": "endpoint_assets",
            "repository": "repository_assets",
            "container_image": "container_image_assets",
            "k8s_workload": "k8s_workload_assets",
            "ecs_service": "cloud_workload_assets",
            "gcp_workload": "cloud_workload_assets",
            "cloud_workload": "cloud_workload_assets",
            "ami": "ami_assets",
        }
        table = table_by_type.get(asset_type)
        if not table:
            return {}
        row = conn.execute(f"SELECT * FROM {table} WHERE asset_id = ?", (asset_id,)).fetchone()
        return row_to_dict(row) if row else {}

    def _upsert_component(self, conn: sqlite3.Connection, component: dict[str, Any]) -> str:
        purl = component.get("purl", "")
        cpe = component.get("cpe", "")
        name = component.get("name", "")
        version = component.get("version", "")
        ecosystem = component.get("ecosystem", "")
        component_id = component.get("id") or stable_id("component", purl or cpe or ecosystem, name, version)
        conn.execute(
            """
            INSERT INTO components (
                id, purl, cpe, name, version, ecosystem, package_manager,
                supplier, license, hashes, first_seen_at, last_seen_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                purl = excluded.purl,
                cpe = excluded.cpe,
                name = excluded.name,
                version = excluded.version,
                ecosystem = excluded.ecosystem,
                package_manager = excluded.package_manager,
                supplier = excluded.supplier,
                license = excluded.license,
                hashes = excluded.hashes,
                last_seen_at = excluded.last_seen_at
            """,
            (
                component_id,
                purl,
                cpe,
                name,
                version,
                ecosystem,
                component.get("package_manager", ""),
                component.get("supplier", ""),
                component.get("license", ""),
                to_json(component.get("hashes") or {}),
                component.get("first_seen_at", now_iso()),
                component.get("last_seen_at", now_iso()),
            ),
        )
        return component_id

    def _upsert_asset_component(
        self,
        conn: sqlite3.Connection,
        asset_id: str,
        component_id: str,
        usage: dict[str, Any],
    ) -> None:
        usage_id = usage.get("id") or stable_id(
            "asset_component",
            asset_id,
            component_id,
            usage.get("source", ""),
            usage.get("evidence_path", ""),
            usage.get("layer_digest", ""),
        )
        conn.execute(
            """
            INSERT INTO asset_components (
                id, asset_id, component_id, source, evidence_path, layer_digest,
                package_manager, evidence, first_seen_at, last_seen_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                source = excluded.source,
                evidence_path = excluded.evidence_path,
                layer_digest = excluded.layer_digest,
                package_manager = excluded.package_manager,
                evidence = excluded.evidence,
                last_seen_at = excluded.last_seen_at
            """,
            (
                usage_id,
                asset_id,
                component_id,
                usage.get("source", ""),
                usage.get("evidence_path", ""),
                usage.get("layer_digest", ""),
                usage.get("package_manager", ""),
                to_json(usage.get("evidence") or {}),
                usage.get("first_seen_at", now_iso()),
                usage.get("last_seen_at", now_iso()),
            ),
        )

    def _link_provenance(
        self,
        conn: sqlite3.Connection,
        image_asset_id: str,
        provenance: dict[str, Any],
    ) -> None:
        """Best-effort: link a container image to its source repo / runtime workload.

        Resolves ``source_repository`` and ``discovered_in`` (external_id or
        display_name of an already-known asset) and records a relationship. No-op
        when the referenced asset is not in the inventory yet.
        """
        if not provenance:
            return
        links = [
            (provenance.get("source_repository"), "built_from"),
            (provenance.get("discovered_in"), "discovered_in"),
        ]
        for ref, rel_type in links:
            if not ref:
                continue
            row = conn.execute(
                "SELECT id FROM assets WHERE external_id = ? OR display_name = ? LIMIT 1",
                (str(ref), str(ref)),
            ).fetchone()
            if not row or row["id"] == image_asset_id:
                continue
            self._upsert_relationship(
                conn,
                image_asset_id,
                row["id"],
                {"relationship_type": rel_type, "evidence": {"provenance": True, "ref": ref}},
            )

    def _upsert_relationship(
        self,
        conn: sqlite3.Connection,
        source_id: str,
        target_id: str,
        relationship: dict[str, Any],
    ) -> None:
        rel_type = relationship.get("relationship_type") or relationship.get("type") or "related_to"
        relationship_id = relationship.get("id") or stable_id("relationship", source_id, rel_type, target_id)
        conn.execute(
            """
            INSERT INTO asset_relationships (
                id, source_asset_id, relationship_type, target_asset_id,
                evidence, first_seen_at, last_seen_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                evidence = excluded.evidence,
                last_seen_at = excluded.last_seen_at
            """,
            (
                relationship_id,
                source_id,
                rel_type,
                target_id,
                to_json(relationship.get("evidence") or {}),
                relationship.get("first_seen_at", now_iso()),
                relationship.get("last_seen_at", now_iso()),
            ),
        )

    def _sync_relationship_details(
        self,
        conn: sqlite3.Connection,
        source_id: str,
        target_id: str,
        relationship: dict[str, Any],
    ) -> None:
        """Mirror graph edges into denormalized workload detail columns.

        The graph is canonical, but detail panes and API clients also read
        k8s_workload_assets.image_asset_id / cluster_asset_id. Keep those fields
        current whenever topology payloads provide image->workload or
        workload->cluster relationships.
        """
        rel_type = relationship.get("relationship_type") or relationship.get("type") or "related_to"
        if rel_type == "runs_in":
            conn.execute(
                "UPDATE k8s_workload_assets SET image_asset_id = ? WHERE asset_id = ?",
                (source_id, target_id),
            )
            conn.execute(
                "UPDATE cloud_workload_assets SET image_asset_id = ? WHERE asset_id = ?",
                (source_id, target_id),
            )
        elif rel_type == "belongs_to":
            conn.execute(
                "UPDATE k8s_workload_assets SET cluster_asset_id = ? WHERE asset_id = ?",
                (target_id, source_id),
            )

    def _upsert_finding(
        self,
        conn: sqlite3.Connection,
        finding: dict[str, Any],
        asset_id: str | None,
        component_id: str | None,
        connector_id: str | None,
    ) -> None:
        finding_type = finding.get("finding_type", "observation")
        title = finding.get("title", finding_type)
        finding_id = finding.get("id") or stable_id("finding", finding_type, asset_id, component_id, title)
        conn.execute(
            """
            INSERT INTO findings (
                id, finding_type, severity, title, description, affected_asset_id,
                component_id, source_connector_id, status, first_seen_at, last_seen_at,
                fix_recommendation, evidence
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                severity = excluded.severity,
                title = excluded.title,
                description = excluded.description,
                affected_asset_id = excluded.affected_asset_id,
                component_id = excluded.component_id,
                source_connector_id = excluded.source_connector_id,
                status = excluded.status,
                last_seen_at = excluded.last_seen_at,
                fix_recommendation = excluded.fix_recommendation,
                evidence = excluded.evidence
            """,
            (
                finding_id,
                finding_type,
                finding.get("severity", "info"),
                title,
                finding.get("description", ""),
                asset_id,
                component_id,
                connector_id,
                finding.get("status", "open"),
                finding.get("first_seen_at", now_iso()),
                finding.get("last_seen_at", now_iso()),
                finding.get("fix_recommendation", ""),
                to_json(finding.get("evidence") or {}),
            ),
        )

    def _insert_raw_sbom(self, conn: sqlite3.Connection, asset_id: str, sbom: dict[str, Any]) -> None:
        conn.execute(
            """
            INSERT INTO raw_sboms (id, asset_id, format, document, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                sbom.get("id") or str(uuid.uuid4()),
                asset_id,
                sbom.get("format", "internal"),
                to_json(sbom.get("document") or {}),
                sbom.get("created_at", now_iso()),
            ),
        )

    # ── OSV malware monitoring ──────────────────────────────────────────────
    _MALWARE_DEFAULTS = {
        "malware_enabled": "false",          # master switch for OSV malware analysis
        "platform_alerts_enabled": "true",   # in-app alerts (on by default when malware is enabled)
        "slack_enabled": "false",            # optional Slack notification on top
        "slack_webhook_env": "SUPPLYDRIFT_SLACK_WEBHOOK",
        "slack_channel": "",
        "malware_interval_minutes": "60",
        "malware_first_run_lookback_minutes": "1440",
        "malware_last_run_at": "",
    }

    def _set_setting(self, conn: sqlite3.Connection, key: str, value: Any) -> None:
        conn.execute(
            "INSERT INTO app_settings (`key`, value, updated_at) VALUES (?, ?, ?) "
            "ON CONFLICT(`key`) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            (key, str(value), now_iso()),
        )

    def get_malware_settings(self) -> dict[str, Any]:
        with self.connect() as conn:
            rows = {r["key"]: r["value"] for r in conn.execute("SELECT `key`, value FROM app_settings")}
        s = {k: rows.get(k, v) for k, v in self._MALWARE_DEFAULTS.items()}
        interval = int(s["malware_interval_minutes"] or 60)
        last_run = s["malware_last_run_at"]
        # Estimated next scheduled analysis = last run + interval (the platform enqueues
        # one per interval; the runner advances last_run when it completes).
        next_run = ""
        if last_run and s["malware_enabled"] == "true":
            from datetime import timedelta

            import osv_malware as osv
            base = osv.parse_iso(last_run)
            if base is not None:
                next_run = (base + timedelta(minutes=interval)).isoformat()
        return {
            "malware_enabled": s["malware_enabled"] == "true",
            "platform_alerts_enabled": s["platform_alerts_enabled"] == "true",
            "slack_enabled": s["slack_enabled"] == "true",
            "slack_webhook_env": s["slack_webhook_env"],
            "slack_channel": s["slack_channel"],
            "malware_interval_minutes": interval,
            "malware_first_run_lookback_minutes": int(s["malware_first_run_lookback_minutes"] or 1440),
            "malware_last_run_at": last_run,
            "malware_next_run_at": next_run,
            # whether the named env var actually holds a webhook (never the value itself)
            "slack_webhook_configured": bool(os.environ.get(s["slack_webhook_env"] or "")),
        }

    def update_malware_settings(self, body: dict[str, Any]) -> dict[str, Any]:
        allowed = {"malware_enabled", "platform_alerts_enabled",
                   "slack_enabled", "slack_webhook_env", "slack_channel",
                   "malware_interval_minutes", "malware_first_run_lookback_minutes"}
        with self.connect() as conn:
            for key in allowed:
                if key in body:
                    value = body[key]
                    if isinstance(value, bool):
                        value = "true" if value else "false"
                    self._set_setting(conn, key, value)
        return self.get_malware_settings()

    def _decode_alert(self, row: dict[str, Any]) -> dict[str, Any]:
        row["sources"] = json.loads(row.get("sources") or "[]")
        row["affected_asset_ids"] = json.loads(row.get("affected_asset_ids") or "[]")
        return row

    def list_alerts(self, params: dict[str, list[str]]) -> Any:
        status = (params.get("status") or [""])[0]
        where, values = "", []
        if status:
            where = "WHERE status = ?"
            values.append(status)
        limit, offset, paginated = paginate_params(params)
        select = f"SELECT * FROM malware_alerts {where} ORDER BY first_alerted_at DESC, package ASC"
        with self.connect() as conn:
            if paginated:
                total = conn.execute(f"SELECT COUNT(*) FROM malware_alerts {where}", values).fetchone()[0]
                rows = [self._decode_alert(row_to_dict(r))
                        for r in conn.execute(select + " LIMIT ? OFFSET ?", values + [limit, offset])]
                return {"items": rows, "total": total, "limit": limit, "offset": offset}
            return [self._decode_alert(row_to_dict(r)) for r in conn.execute(select + " LIMIT 500", values)]

    def malware_cursor(self, *, now: str | None = None) -> dict[str, Any]:
        """The delta window the runner should fetch: OSV MAL-* advisories modified
        since the last run (or now - first-run lookback). Returns ISO strings."""
        from datetime import timedelta

        import osv_malware as osv

        now = now or now_iso()
        settings = self.get_malware_settings()
        last_run = settings["malware_last_run_at"]
        if last_run:
            since = last_run
        else:
            base = osv.parse_iso(now)
            since = (
                (base - timedelta(minutes=settings["malware_first_run_lookback_minutes"])).isoformat()
                if base is not None else ""
            )
        return {"since": since, "now": now}

    def scan_malware_delta(self, *, now: str | None = None, fetch=None, slack_send=None) -> dict[str, Any]:
        """In-process path (tests / fallback): fetch the OSV MAL-* delta, then match.
        The runner does the fetch off-platform and POSTs to match_malware_specs instead."""
        import osv_malware as osv

        now = now or now_iso()
        cur = self.malware_cursor(now=now)
        cutoff = osv.parse_iso(cur["since"]) if cur["since"] else None
        fetch = fetch or osv.fetch_recent_malicious
        specs, advisory_count = fetch(cutoff)
        summary = self.match_malware_specs(specs, scanned_at=now, slack_send=slack_send)
        summary["advisories_scanned"] = advisory_count
        return summary

    def match_malware_specs(self, specs: list, scanned_at: str | None = None,
                            *, slack_send=None) -> dict[str, Any]:
        """Match OSV MAL-* specs against ingested components; upsert alerts + malware
        findings (when platform alerts are enabled), dispatch Slack for NEW alerts, and
        advance the cursor. `specs` are MaliciousSpec objects (the route rebuilds them)."""
        import osv_malware as osv

        now = scanned_at or now_iso()
        settings = self.get_malware_settings()
        platform_alerts = settings["platform_alerts_enabled"]

        new_alerts: list[dict[str, Any]] = []
        updated_alerts: list[dict[str, Any]] = []
        matched = 0
        with self.connect() as conn:
            if specs and platform_alerts:
                names = sorted({s.package_name for s in specs})
                placeholders = ",".join("?" * len(names))
                comp_rows = [row_to_dict(r) for r in conn.execute(
                    f"SELECT id, name, version, ecosystem, purl FROM components WHERE name IN ({placeholders})",
                    names)]
                hits = osv.match_specs_to_components(specs, comp_rows)

                grouped: dict[tuple, dict[str, Any]] = {}
                for h in hits:
                    key = (h["advisory_id"], h["package"], h["version"], h["ecosystem"])
                    g = grouped.setdefault(key, {"hit": h, "component_ids": set()})
                    if h.get("component_id"):
                        g["component_ids"].add(h["component_id"])
                matched = len(grouped)

                for (advisory_id, package, version, ecosystem), g in grouped.items():
                    h = g["hit"]
                    asset_ids: set[str] = set()
                    for cid in g["component_ids"]:
                        for r in conn.execute(
                                "SELECT DISTINCT asset_id FROM asset_components WHERE component_id = ?", (cid,)):
                            asset_ids.add(r[0])
                            self._upsert_finding(conn, {
                                "finding_type": "malware",
                                "severity": "critical",
                                "title": advisory_id,
                                "description": f"Malicious package {package}@{version} flagged by OSV ({advisory_id})",
                                "fix_recommendation": (
                                    f"Remove or replace {package}; flagged malicious by OSV"
                                    + (f" via {', '.join(h['sources'])}" if h["sources"] else "")),
                                "first_seen_at": now, "last_seen_at": now,
                                "evidence": {"advisory_id": advisory_id, "advisory_url": h["advisory_url"],
                                             "sources": h["sources"], "package": package, "version": version},
                            }, r[0], cid, None)
                    asset_list = sorted(asset_ids)
                    alert_id = stable_id("malware_alert", advisory_id, package, version, ecosystem)
                    alert = {"advisory_id": advisory_id, "package": package, "version": version,
                             "ecosystem": ecosystem, "advisory_url": h["advisory_url"], "sources": h["sources"],
                             "asset_count": len(asset_list), "affected_asset_ids": asset_list}
                    existing = conn.execute(
                        "SELECT id FROM malware_alerts WHERE id = ?", (alert_id,)).fetchone()
                    if existing is None:
                        conn.execute(
                            """INSERT INTO malware_alerts
                               (id, advisory_id, package, version, ecosystem, advisory_url, sources, status,
                                asset_count, affected_asset_ids, alert_count, first_alerted_at, last_seen_at,
                                created_at, updated_at)
                               VALUES (?,?,?,?,?,?,?, 'active', ?,?, 1, ?,?,?,?)""",
                            (alert_id, advisory_id, package, version, ecosystem, h["advisory_url"],
                             to_json(h["sources"]), len(asset_list), to_json(asset_list), now, now, now, now))
                        new_alerts.append(alert)
                    else:
                        conn.execute(
                            """UPDATE malware_alerts SET status='active', asset_count=?, affected_asset_ids=?,
                               alert_count = alert_count + 1, last_seen_at=?, updated_at=? WHERE id=?""",
                            (len(asset_list), to_json(asset_list), now, now, alert_id))
                        updated_alerts.append(alert)

            self._set_setting(conn, "malware_last_run_at", now)
            active_total = conn.execute(
                "SELECT COUNT(*) FROM malware_alerts WHERE status='active'").fetchone()[0]

        dispatched = 0
        if new_alerts:
            send = slack_send if slack_send is not None else self._send_slack
            try:
                dispatched = send(new_alerts, settings) or 0
            except Exception:  # noqa: BLE001 — alerting must never fail the scan
                dispatched = 0
        return {"specs_checked": len(specs), "matched": matched, "new": len(new_alerts),
                "updated": len(updated_alerts), "active_total": active_total,
                "slack_dispatched": dispatched, "ran_at": now}

    def _send_slack(self, alerts: list[dict[str, Any]], settings: dict[str, Any]) -> int:
        if not settings.get("slack_enabled"):
            return 0
        webhook = os.environ.get(settings.get("slack_webhook_env") or "", "")
        if not webhook:
            return 0
        # Anti-SSRF: only post to a real Slack webhook host over TLS. The env-var
        # indirection keeps the URL out of the DB, but its value is still operator-
        # influenced, so validate scheme + host before fetching.
        from urllib.parse import urlparse
        parsed = urlparse(webhook)
        if parsed.scheme != "https" or parsed.hostname != "hooks.slack.com":
            return 0  # not a Slack webhook over TLS -> refuse
        import urllib.request
        def _slk(v: object) -> str:
            # Strip Slack mrkdwn control chars so alert fields (package/advisory names
            # derived from feed/scan data) can't inject link or formatting syntax.
            return re.sub(r"[<>|\r\n]", "", str(v))

        lines = [f":rotating_light: *Malware detected in SBOM* — {len(alerts)} new alert(s)"]
        for a in alerts[:20]:
            adv_id = _slk(a["advisory_id"])
            url = str(a.get("advisory_url") or "")
            link = f"<{url}|{adv_id}>" if re.match(r"(?i)^https?://", url) else adv_id
            lines.append(
                f"• `{_slk(a['package'])}@{_slk(a['version'])}` ({_slk(a['ecosystem'])}) — "
                f"{link} · {a['asset_count']} asset(s)")
        payload: dict[str, Any] = {"text": "\n".join(lines)}
        if settings.get("slack_channel"):
            payload["channel"] = settings["slack_channel"]
        req = urllib.request.Request(
            webhook, data=to_json(payload).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        urllib.request.urlopen(req, timeout=10)  # raises on failure -> caught by caller
        return len(alerts)

    # ── Scan job queue (UI Scan button -> runners) ──────────────────────────
    @staticmethod
    def _job_type_for(source_type: str) -> str:
        return "github" if (source_type or "").lower() in REPO_SOURCE_TYPES else "image"

    def _decode_run(self, row: dict[str, Any]) -> dict[str, Any]:
        run = dict(row)  # row_to_dict already parses the `summary` JSON column
        connector_config = run.pop("connector_config", None)
        connector_type = run.pop("connector_type", None)

        # Public API aliases: the table stores claim fields as claimed_by/claimed_at,
        # while the UI speaks in runner/start terms.
        run["runner_id"] = run.get("claimed_by")
        run["started_at"] = run.get("claimed_at")

        source_type = run.get("source_type")
        if not source_type and isinstance(connector_config, dict):
            source_type = connector_config.get("source_type")
        if not source_type and connector_type:
            source_type = str(connector_type).split(":", 1)[-1]
        run["source_type"] = source_type or None
        return run

    @staticmethod
    def _scan_run_select(where: str = "") -> str:
        return (
            "SELECT sr.*, co.connector_type AS connector_type, co.config AS connector_config "
            "FROM scan_runs sr LEFT JOIN connectors co ON co.id = sr.connector_id "
            f"{where}"
        )

    def _enqueue_connector_run(self, connector_id: str, action: str) -> dict[str, Any]:
        """Queue source work for a connector; reuses any active run for that source."""
        connector = self.get_connector(connector_id)
        if connector is None:
            raise ValueError("connector not found")
        action = "refresh" if action == "refresh" else "scan"
        config = connector.get("config") if isinstance(connector.get("config"), dict) else {}
        source_type = config.get("source_type") or connector.get("connector_type") or ""
        source_name = connector.get("name") or source_type
        job_type = self._job_type_for(source_type)
        now = now_iso()
        with self.connect() as conn:
            existing = conn.execute(
                "SELECT * FROM scan_runs WHERE connector_id = ? AND status IN ('queued','running') "
                "ORDER BY requested_at DESC LIMIT 1", (connector_id,)).fetchone()
            if existing:
                run = self._decode_run(row_to_dict(existing))
            else:
                run_id = str(uuid.uuid4())
                conn.execute(
                    "INSERT INTO scan_runs "
                    "(id, connector_id, source_name, job_type, status, requested_at, summary) "
                    "VALUES (?, ?, ?, ?, 'queued', ?, ?)",
                    (run_id, connector_id, source_name, job_type, now, to_json({"action": action})))
                run = self._decode_run(row_to_dict(
                    conn.execute("SELECT * FROM scan_runs WHERE id = ?", (run_id,)).fetchone()))
                run["source_type"] = source_type or None
        run["source_type"] = run.get("source_type") or source_type or None
        return self._with_runner_status(run, job_type)

    def enqueue_scan(self, connector_id: str) -> dict[str, Any]:
        """Queue a component scan for a connector."""
        return self._enqueue_connector_run(connector_id, "scan")

    def enqueue_refresh(self, connector_id: str) -> dict[str, Any]:
        """Queue an inventory refresh for a connector.

        Refresh connects to the source, discovers inventory/topology, and marks
        discovered assets as pending. A later scan upgrades those assets to
        scanned with component/CVE results.
        """
        return self._enqueue_connector_run(connector_id, "refresh")

    def enqueue_malware_scan(self) -> dict[str, Any]:
        """Queue a global OSV malware-analysis job (dedupe if one is already pending)."""
        now = now_iso()
        with self.connect() as conn:
            existing = conn.execute(
                "SELECT * FROM scan_runs WHERE job_type = 'malware' AND status IN ('queued','running') "
                "ORDER BY requested_at DESC LIMIT 1").fetchone()
            if existing:
                return self._decode_run(row_to_dict(existing))
            run_id = str(uuid.uuid4())
            conn.execute(
                "INSERT INTO scan_runs (id, connector_id, source_name, job_type, status, requested_at) "
                "VALUES (?, NULL, 'OSV malware feed', 'malware', 'queued', ?)",
                (run_id, now))
            row = conn.execute(
                self._scan_run_select("WHERE sr.id = ?"), (run_id,)
            ).fetchone()
        return self._decode_run(row_to_dict(row))

    def list_scan_runs(self, params: dict[str, list[str]]) -> Any:
        self.reap_stale_scan_runs()  # self-heal orphaned 'running' runs before listing
        filters: list[str] = []
        values: list[Any] = []
        if params.get("connector_id") and params["connector_id"][0]:
            filters.append("sr.connector_id = ?")
            values.append(params["connector_id"][0])
        if params.get("status") and params["status"][0]:
            filters.append("sr.status = ?")
            values.append(params["status"][0])
        if params.get("job_type") and params["job_type"][0]:
            filters.append("sr.job_type = ?")
            values.append(params["job_type"][0])
        where = f"WHERE {' AND '.join(filters)}" if filters else ""
        limit, offset, paginated = paginate_params(params)
        select = self._scan_run_select(where) + " ORDER BY sr.requested_at DESC"
        with self.connect() as conn:
            if paginated:
                total = conn.execute(
                    f"SELECT COUNT(*) FROM scan_runs sr {where}", values
                ).fetchone()[0]
                rows = [self._decode_run(row_to_dict(r))
                        for r in conn.execute(select + " LIMIT ? OFFSET ?", values + [limit, offset])]
                return {"items": rows, "total": total, "limit": limit, "offset": offset}
            return [self._decode_run(row_to_dict(r)) for r in conn.execute(select + " LIMIT 200", values)]

    def latest_scan_run(self, connector_id: str) -> dict[str, Any] | None:
        self.reap_stale_scan_runs()  # self-heal orphaned 'running' runs on each poll
        with self.connect() as conn:
            row = conn.execute(
                self._scan_run_select("WHERE sr.connector_id = ?")
                + " ORDER BY sr.requested_at DESC LIMIT 1",
                (connector_id,)).fetchone()
        if row is None:
            return None
        run = self._decode_run(row_to_dict(row))
        # A still-queued run carries runner status so the UI keeps showing whether
        # anything will pick it up — idle, busy (waits its turn), or absent. The
        # card polls this endpoint, so the message updates as runners free up.
        if run.get("status") == "queued":
            run = self._with_runner_status(run, run.get("job_type", ""))
        return run

    def claim_scan_run(self, job_type: str, runner_id: str) -> dict[str, Any] | None:
        """Atomically claim the oldest queued run of job_type (None if the queue is empty).

        Every poll — even one that claims nothing — records a runner heartbeat, so
        the platform can tell whether any runner is alive for a job type (used to
        warn when a scan is enqueued with no runner to claim it). See has_live_runner.
        """
        now = now_iso()
        with self.connect() as conn:
            conn.execute(
                """INSERT INTO runner_heartbeats (runner_id, job_type, last_seen_at)
                   VALUES (?, ?, ?)
                   ON CONFLICT(runner_id, job_type)
                   DO UPDATE SET last_seen_at = excluded.last_seen_at""",
                (runner_id or "unknown", job_type, now))
            # Dialect-agnostic atomic claim (no RETURNING / FOR UPDATE): pick the oldest
            # queued run, then compare-and-set status='queued'->'running'. If another
            # runner won the race the UPDATE matches 0 rows and we return None (the
            # poller retries). SQLite serializes writers; MySQL row-locks the UPDATE.
            pick = conn.execute(
                "SELECT id FROM scan_runs WHERE status = 'queued' AND job_type = ? "
                "ORDER BY requested_at LIMIT 1", (job_type,)).fetchone()
            if pick is None:
                return None
            run_id = pick["id"]
            claimed = conn.execute(
                "UPDATE scan_runs SET status = 'running', claimed_at = ?, claimed_by = ? "
                "WHERE id = ? AND status = 'queued'", (now, runner_id, run_id))
            if claimed.rowcount == 0:
                return None
            row = conn.execute(
                self._scan_run_select("WHERE sr.id = ?"), (run_id,)
            ).fetchone()
        return self._decode_run(row_to_dict(row)) if row else None

    def runner_presence(self, job_type: str,
                        within_seconds: int = RUNNER_LIVENESS_WINDOW_SECONDS) -> tuple[bool, bool]:
        """Return ``(available, busy)`` for a job type.

        ``busy``      — a job of this type is currently 'running' (claimed within the
                        busy window): a runner is present but occupied, so queued jobs
                        WILL be picked up once it finishes.
        ``available`` — a runner exists at all: a recent idle heartbeat OR busy.

        An idle runner heartbeats every poll; a busy runner stops polling mid-scan,
        so the 'running' job is what proves it's still there. Timestamps are
        fixed-width UTC ISO strings, so lexical >= compares are chronological.
        """
        now = datetime.now(timezone.utc)
        hb_cutoff = (now - timedelta(seconds=within_seconds)).replace(microsecond=0).isoformat()
        busy_cutoff = (now - timedelta(seconds=RUNNER_BUSY_WINDOW_SECONDS)).replace(microsecond=0).isoformat()
        with self.connect() as conn:
            heartbeat = conn.execute(
                "SELECT 1 FROM runner_heartbeats WHERE job_type = ? AND last_seen_at >= ? LIMIT 1",
                (job_type, hb_cutoff)).fetchone() is not None
            busy = conn.execute(
                "SELECT 1 FROM scan_runs WHERE job_type = ? AND status = 'running' "
                "AND claimed_at >= ? LIMIT 1",
                (job_type, busy_cutoff)).fetchone() is not None
        return (heartbeat or busy), busy

    def has_live_runner(self, job_type: str,
                        within_seconds: int = RUNNER_LIVENESS_WINDOW_SECONDS) -> bool:
        """True if a runner for job_type is connected (idle heartbeat or busy)."""
        return self.runner_presence(job_type, within_seconds)[0]

    def _with_runner_status(self, run: dict[str, Any], job_type: str) -> dict[str, Any]:
        """Annotate an enqueue/latest response with runner availability.

        Three states: a runner is idle and will claim immediately; a runner is
        present but busy on another scan (this job waits its turn, FIFO); or no
        runner is connected at all (only then do we warn).
        """
        available, busy = self.runner_presence(job_type)
        run["runner_available"] = available
        run["runner_busy"] = busy
        if not available:
            label = {"image": "image", "github": "repository", "malware": "malware"}.get(job_type, job_type)
            action = (run.get("summary") or {}).get("action") if isinstance(run.get("summary"), dict) else ""
            noun = "refresh" if action == "refresh" else "scan"
            run["warning"] = (
                f"No active {label} runner is connected. The {noun} is queued and will run "
                f"as soon as a runner starts polling (e.g. `docker compose up -d`)."
            )
        return run

    def complete_scan_run(self, run_id: str, status: str,
                          summary: dict[str, Any] | None = None, error: str = "",
                          runner_id: str | None = None) -> dict[str, Any] | None:
        if status not in ("succeeded", "failed", "canceled"):
            status = "failed"
        finished_at = now_iso()
        with self.connect() as conn:
            # Ownership: only the runner that CLAIMED a run may complete it. Runner
            # tokens lack READ, so an attacker holding a stray QUEUE token cannot read
            # claimed_by (GET /api/scan/runs needs READ) to spoof it — this bounds run
            # poisoning to the actual claimer. Enforced only when both sides supply a
            # runner id, so a late/legacy complete without one still works.
            if runner_id:
                owner = conn.execute(
                    "SELECT claimed_by FROM scan_runs WHERE id = ?", (run_id,)).fetchone()
                claimed_by = owner["claimed_by"] if owner else None
                if claimed_by and claimed_by not in ("", "unknown") and claimed_by != runner_id:
                    return None
            conn.execute(
                "UPDATE scan_runs SET status = ?, finished_at = ?, summary = ?, error = ? WHERE id = ?",
                (status, finished_at, to_json(summary or {}), error or None, run_id))
            if status == "succeeded":
                conn.execute(
                    "UPDATE connectors SET last_sync_at = ?, updated_at = ? "
                    "WHERE id = (SELECT connector_id FROM scan_runs WHERE id = ?)",
                    (finished_at, finished_at, run_id),
                )
            row = conn.execute(
                self._scan_run_select("WHERE sr.id = ?"), (run_id,)
            ).fetchone()
        return self._decode_run(row_to_dict(row)) if row else None

    def reap_stale_scan_runs(self, timeout_seconds: int = SCAN_STALE_TIMEOUT_SECONDS) -> int:
        """Fail any 'running' run whose claim is older than ``timeout_seconds``.

        A runner that dies mid-scan (crash / `docker compose down`) never POSTs
        /complete, so its run stays 'running' and the source is stuck "Scanning…".
        This marks such orphans 'failed' so the UI clears and the scan can be re-run.
        Returns the number reaped. Called lazily on status reads and once at startup;
        a genuine late /complete still overwrites the row, so slow != killed.
        """
        cutoff = (datetime.now(timezone.utc) - timedelta(seconds=timeout_seconds)
                  ).replace(microsecond=0).isoformat()
        now = now_iso()
        msg = ("Scan interrupted by a platform restart — the runner is no longer "
               "working on it. Re-run the scan." if timeout_seconds == 0 else
               f"Runner stopped responding — scan orphaned and reaped after "
               f"{timeout_seconds // 60} min. Re-run the scan.")
        with self.connect() as conn:
            result = conn.execute(
                "UPDATE scan_runs SET status = 'failed', finished_at = ?, error = ? "
                "WHERE status = 'running' AND claimed_at IS NOT NULL AND claimed_at < ?",
                (now, msg, cutoff))
            return result.rowcount or 0

    def cancel_scan_run(self, run_id: str) -> dict[str, Any] | None:
        """Cancel a queued/running run (the UI 'Stop' button). No-op if already done.

        For a queued run no runner has it yet, so cancel is clean. For a 'running'
        run the runner can't be signalled mid-scan (it isn't polling), so this just
        clears the stuck state; if that runner is in fact alive and later POSTs
        /complete, its result overwrites the canceled row."""
        with self.connect() as conn:
            conn.execute(
                "UPDATE scan_runs SET status = 'canceled', finished_at = ?, "
                "error = 'Canceled by user' WHERE id = ? AND status IN ('queued','running')",
                (now_iso(), run_id))
            row = conn.execute("SELECT * FROM scan_runs WHERE id = ?", (run_id,)).fetchone()
        return self._decode_run(row_to_dict(row)) if row else None

    def cancel_connector_scan(self, connector_id: str) -> dict[str, Any] | None:
        """Cancel the active (queued or running) run for a connector, if any."""
        with self.connect() as conn:
            row = conn.execute(
                "SELECT id FROM scan_runs WHERE connector_id = ? AND status IN ('queued','running') "
                "ORDER BY requested_at DESC LIMIT 1", (connector_id,)).fetchone()
        if row is None:
            return None
        return self.cancel_scan_run(row["id"])

    # ── Authentication: users, sessions, API tokens ─────────────────────────
    SESSION_TTL_HOURS = 12
    # Enforced in the Store (not just the UI/routes) so no caller can create or
    # rotate to a trivially guessable password.
    PASSWORD_MIN_LENGTH = 8
    LOGIN_MAX_FAILS = 5
    LOGIN_WINDOW_SECONDS = 300
    # Per-source-IP failure cap (in addition to the per-username cap above) to slow
    # password-spraying from one host. Deliberately generous so a shared NAT/proxy
    # doesn't lock out legitimate users; behind a reverse proxy this keys on the
    # proxy IP, so also rate-limit at the proxy. Set to 0 to disable.
    LOGIN_IP_MAX_FAILS = int(os.environ.get("SUPPLYDRIFT_LOGIN_IP_MAX_FAILS", "50"))

    @staticmethod
    def _public_user(row: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": row["id"], "username": row["username"], "role": row["role"],
            "disabled": bool(row["disabled"]), "created_at": row["created_at"],
            "last_login_at": row.get("last_login_at"),
        }

    def count_users(self) -> int:
        with self.connect() as conn:
            return conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]

    def create_user(self, username: str, password: str, role: str = "member") -> dict[str, Any]:
        import auth
        username = (username or "").strip().lower()
        if not username:
            raise ValueError("username required")
        if role not in auth.ROLES:
            raise ValueError(f"invalid role '{role}'")
        if len(password or "") < self.PASSWORD_MIN_LENGTH:
            raise ValueError(f"password must be at least {self.PASSWORD_MIN_LENGTH} characters")
        with self.connect() as conn:
            if conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
                raise ValueError(f"user '{username}' already exists")
            uid = str(uuid.uuid4())
            conn.execute(
                "INSERT INTO users (id, username, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
                (uid, username, auth.hash_password(password), role, now_iso()))
            row = conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
        return self._public_user(dict(row))

    def bootstrap_admin(self, username: str, password: str) -> dict[str, Any] | None:
        """Create the first admin from env on a fresh install (no-op if any user exists)."""
        if self.count_users() > 0:
            return None
        return self.create_user(username, password, role="admin")

    # Decoy hash (computed once, on first miss) so a login attempt for an unknown
    # or disabled username burns the same scrypt work as a real verify — response
    # timing then doesn't reveal which usernames exist.
    _decoy_hash: str | None = None

    def verify_login(self, username: str, password: str) -> dict[str, Any] | None:
        import auth
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM users WHERE username = ?", ((username or "").strip().lower(),)).fetchone()
        if row is None or row["disabled"]:
            if Store._decoy_hash is None:
                Store._decoy_hash = auth.hash_password("supplydrift-timing-decoy")
            auth.verify_password(password, Store._decoy_hash)
            return None
        if not auth.verify_password(password, row["password_hash"]):
            return None
        return self._public_user(dict(row))

    # ── Login throttle (DB-backed, per-username) ────────────────────────────
    def login_throttled(self, username: str, max_fails: int | None = None) -> bool:
        # `username` is the throttle KEY: a real username, or an "ip:<addr>" key for
        # the per-source-IP limit. max_fails defaults to the per-username cap.
        cap = self.LOGIN_MAX_FAILS if max_fails is None else max_fails
        if cap <= 0:
            return False  # limit disabled
        username = (username or "").strip().lower()
        nowep = int(datetime.now(timezone.utc).timestamp())
        with self.connect() as conn:
            row = conn.execute(
                "SELECT fail_count, window_start FROM login_attempts WHERE username = ?",
                (username,)).fetchone()
        if row is None or nowep - row["window_start"] > self.LOGIN_WINDOW_SECONDS:
            return False  # no record, or the window has elapsed
        return row["fail_count"] >= cap

    def record_login_failure(self, username: str) -> None:
        username = (username or "").strip().lower()
        nowep = int(datetime.now(timezone.utc).timestamp())
        with self.connect() as conn:
            row = conn.execute(
                "SELECT fail_count, window_start FROM login_attempts WHERE username = ?",
                (username,)).fetchone()
            if row is None:
                conn.execute(
                    "INSERT INTO login_attempts (username, fail_count, window_start) VALUES (?, 1, ?)",
                    (username, nowep))
            elif nowep - row["window_start"] > self.LOGIN_WINDOW_SECONDS:
                conn.execute(
                    "UPDATE login_attempts SET fail_count = 1, window_start = ? WHERE username = ?",
                    (nowep, username))
            else:
                conn.execute(
                    "UPDATE login_attempts SET fail_count = fail_count + 1 WHERE username = ?",
                    (username,))

    def clear_login_attempts(self, username: str) -> None:
        username = (username or "").strip().lower()
        with self.connect() as conn:
            conn.execute("DELETE FROM login_attempts WHERE username = ?", (username,))

    def list_users(self) -> list[dict[str, Any]]:
        with self.connect() as conn:
            return [self._public_user(dict(r)) for r in conn.execute("SELECT * FROM users ORDER BY created_at")]

    def update_user(self, user_id: str, *, role: str | None = None,
                    disabled: bool | None = None, password: str | None = None) -> dict[str, Any] | None:
        import auth
        # Never lock the org out: refuse to demote or disable the last active admin.
        if (role is not None and role != "admin") or disabled:
            with self.connect() as conn:
                target = conn.execute(
                    "SELECT role, disabled FROM users WHERE id = ?", (user_id,)).fetchone()
                admins = conn.execute(
                    "SELECT COUNT(*) AS n FROM users WHERE role = 'admin' AND disabled = 0"
                ).fetchone()["n"]
            if target and target["role"] == "admin" and not target["disabled"] and admins <= 1:
                raise ValueError("cannot remove the last admin")
        sets, vals = [], []
        if role is not None:
            if role not in auth.ROLES:
                raise ValueError(f"invalid role '{role}'")
            sets.append("role = ?"); vals.append(role)
        if disabled is not None:
            sets.append("disabled = ?"); vals.append(1 if disabled else 0)
        if password:
            if len(password) < self.PASSWORD_MIN_LENGTH:
                raise ValueError(f"password must be at least {self.PASSWORD_MIN_LENGTH} characters")
            sets.append("password_hash = ?"); vals.append(auth.hash_password(password))
        if not sets:
            return self.get_user_by_id(user_id)
        with self.connect() as conn:
            conn.execute(f"UPDATE users SET {', '.join(sets)} WHERE id = ?", (*vals, user_id))
            if disabled or password:  # revoke sessions on disable OR password change
                conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
            row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return self._public_user(dict(row)) if row else None

    def get_user_by_id(self, user_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return self._public_user(dict(row)) if row else None

    def delete_user(self, user_id: str) -> bool:
        with self.connect() as conn:
            cur = conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        return cur.rowcount > 0

    # -- sessions (cookie auth) --
    def create_session(self, user_id: str) -> dict[str, Any]:
        import auth
        now = now_iso()
        sid = auth.new_session_id()
        csrf = auth.new_csrf_token()
        expires = (datetime.now(timezone.utc).replace(microsecond=0)
                   + timedelta(hours=self.SESSION_TTL_HOURS)).isoformat()
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO sessions (id, user_id, csrf_token, created_at, expires_at, last_seen_at) "
                "VALUES (?, ?, ?, ?, ?, ?)", (sid, user_id, csrf, now, expires, now))
            conn.execute("UPDATE users SET last_login_at = ? WHERE id = ?", (now, user_id))
        return {"session_id": sid, "csrf_token": csrf, "expires_at": expires}

    def get_session_principal(self, session_id: str) -> dict[str, Any] | None:
        """Return {user, csrf_token} for a live session, else None. Touches last_seen."""
        if not session_id:
            return None
        now = now_iso()
        with self.connect() as conn:
            row = conn.execute(
                "SELECT s.csrf_token, s.expires_at, u.* FROM sessions s "
                "JOIN users u ON u.id = s.user_id WHERE s.id = ?", (session_id,)).fetchone()
            if row is None:
                return None
            if row["expires_at"] <= now or row["disabled"]:
                conn.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
                return None
            conn.execute("UPDATE sessions SET last_seen_at = ? WHERE id = ?", (now, session_id))
        d = dict(row)
        return {"user": self._public_user(d), "csrf_token": d["csrf_token"]}

    def delete_session(self, session_id: str) -> None:
        with self.connect() as conn:
            conn.execute("DELETE FROM sessions WHERE id = ?", (session_id,))

    # -- API tokens (bearer auth) --
    def create_token(self, name: str, scope: str, created_by: str = "") -> dict[str, Any]:
        """Mint a token; returns the plaintext ONCE (only its hash is stored)."""
        import auth
        if scope not in auth.TOKEN_SCOPES:
            raise ValueError(f"invalid scope '{scope}'")
        plaintext = auth.new_token()
        tid = str(uuid.uuid4())
        now = now_iso()
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO api_tokens (id, name, token_hash, scope, created_by, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)", (tid, name or scope, auth.hash_token(plaintext), scope, created_by, now))
        return {"id": tid, "name": name or scope, "scope": scope, "created_at": now, "token": plaintext}

    def resolve_token(self, plaintext: str) -> dict[str, Any] | None:
        """Return {id, name, scope} for a live token, else None. Touches last_used."""
        import auth
        if not plaintext:
            return None
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM api_tokens WHERE token_hash = ? AND revoked_at IS NULL",
                (auth.hash_token(plaintext),)).fetchone()
            if row is None:
                return None
            conn.execute("UPDATE api_tokens SET last_used_at = ? WHERE id = ?", (now_iso(), row["id"]))
        return {"id": row["id"], "name": row["name"], "scope": row["scope"]}

    def list_tokens(self) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT id, name, scope, created_by, created_at, last_used_at, revoked_at "
                "FROM api_tokens ORDER BY created_at DESC")
            return [dict(r) for r in rows]

    def revoke_token(self, token_id: str) -> bool:
        with self.connect() as conn:
            cur = conn.execute(
                "UPDATE api_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
                (now_iso(), token_id))
        return cur.rowcount > 0

    def ensure_runner_token(self, plaintext: str) -> None:
        """Idempotently register a known token value as the bundled `runner` token.

        Used at startup with the value the platform generates on the shared volume —
        so the co-located runners authenticate with zero human intervention."""
        import auth
        if not plaintext:
            return
        digest = auth.hash_token(plaintext)
        with self.connect() as conn:
            if conn.execute("SELECT 1 FROM api_tokens WHERE token_hash = ?", (digest,)).fetchone():
                conn.execute("UPDATE api_tokens SET revoked_at = NULL WHERE token_hash = ?", (digest,))
                return
            conn.execute(
                "INSERT INTO api_tokens (id, name, token_hash, scope, created_by, created_at) "
                "VALUES (?, 'bundled-runners', ?, 'runner', 'system', ?)",
                (str(uuid.uuid4()), digest, now_iso()))


SCHEMA = """
CREATE TABLE IF NOT EXISTS connectors (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    connector_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'enabled',
    schedule TEXT NOT NULL DEFAULT 'manual',
    credentials_ref TEXT,
    scope TEXT NOT NULL DEFAULT '{}',
    config TEXT NOT NULL DEFAULT '{}',
    last_sync_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_jobs (
    id TEXT PRIMARY KEY,
    connector_id TEXT,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    summary TEXT NOT NULL DEFAULT '{}',
    log TEXT,
    FOREIGN KEY(connector_id) REFERENCES connectors(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS assets (
    id TEXT PRIMARY KEY,
    asset_type TEXT NOT NULL,
    provider TEXT NOT NULL,
    external_id TEXT NOT NULL,
    display_name TEXT NOT NULL,
    connector_id TEXT,
    owner TEXT,
    environment TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    scan_status TEXT NOT NULL DEFAULT 'discovered',
    last_scanned_at TEXT,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    tags TEXT NOT NULL DEFAULT '[]',
    raw_metadata TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY(connector_id) REFERENCES connectors(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_assets_type ON assets(asset_type);
CREATE INDEX IF NOT EXISTS idx_assets_external ON assets(provider, external_id);
CREATE INDEX IF NOT EXISTS idx_assets_seen ON assets(last_seen_at);

CREATE TABLE IF NOT EXISTS endpoint_assets (
    asset_id TEXT PRIMARY KEY,
    endpoint_id TEXT,
    hostname TEXT,
    serial_number TEXT,
    os_name TEXT,
    os_version TEXT,
    architecture TEXT,
    device_type TEXT,
    mdm_id TEXT,
    employee_id TEXT,
    employee_email TEXT,
    employee_name TEXT,
    department TEXT,
    location TEXT,
    last_checkin_at TEXT,
    FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS repository_assets (
    asset_id TEXT PRIMARY KEY,
    git_provider TEXT,
    org_name TEXT,
    repo_name TEXT,
    full_name TEXT,
    repo_url TEXT,
    default_branch TEXT,
    visibility TEXT,
    owner_team TEXT,
    last_commit_sha TEXT,
    last_commit_at TEXT,
    FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS container_image_assets (
    asset_id TEXT PRIMARY KEY,
    registry_type TEXT,
    registry_url TEXT,
    account_id TEXT,
    project_id TEXT,
    repository TEXT,
    image_name TEXT,
    tag TEXT,
    digest TEXT,
    architecture TEXT,
    os TEXT,
    pushed_at TEXT,
    pulled_at TEXT,
    discovery_source TEXT,
    source_reference TEXT,
    FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS k8s_workload_assets (
    asset_id TEXT PRIMARY KEY,
    cluster_asset_id TEXT,
    cloud_provider TEXT,
    account_id TEXT,
    project_id TEXT,
    region TEXT,
    cluster_name TEXT,
    namespace TEXT,
    workload_kind TEXT,
    workload_name TEXT,
    pod_name TEXT,
    container_name TEXT,
    service_account TEXT,
    image_asset_id TEXT,
    image_reference TEXT,
    image_digest TEXT,
    node_name TEXT,
    FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS cloud_workload_assets (
    asset_id TEXT PRIMARY KEY,
    platform TEXT,
    account_id TEXT,
    project_id TEXT,
    region TEXT,
    cluster_name TEXT,
    service_name TEXT,
    task_definition_arn TEXT,
    task_arn TEXT,
    revision TEXT,
    namespace TEXT,
    container_name TEXT,
    image_asset_id TEXT,
    image_reference TEXT,
    image_digest TEXT,
    FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS ami_assets (
    asset_id TEXT PRIMARY KEY,
    account_id TEXT,
    region TEXT,
    ami_id TEXT,
    ami_name TEXT,
    owner_id TEXT,
    creation_date TEXT,
    base_os TEXT,
    architecture TEXT,
    state TEXT,
    FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS components (
    id TEXT PRIMARY KEY,
    purl TEXT,
    cpe TEXT,
    name TEXT NOT NULL,
    version TEXT,
    ecosystem TEXT,
    package_manager TEXT,
    supplier TEXT,
    license TEXT,
    hashes TEXT NOT NULL DEFAULT '{}',
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_components_name ON components(name);
CREATE INDEX IF NOT EXISTS idx_components_purl ON components(purl);

CREATE TABLE IF NOT EXISTS asset_components (
    id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL,
    component_id TEXT NOT NULL,
    source TEXT,
    evidence_path TEXT,
    layer_digest TEXT,
    package_manager TEXT,
    evidence TEXT NOT NULL DEFAULT '{}',
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE CASCADE,
    FOREIGN KEY(component_id) REFERENCES components(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_asset_components_asset ON asset_components(asset_id);
CREATE INDEX IF NOT EXISTS idx_asset_components_component ON asset_components(component_id);

CREATE TABLE IF NOT EXISTS asset_relationships (
    id TEXT PRIMARY KEY,
    source_asset_id TEXT NOT NULL,
    relationship_type TEXT NOT NULL,
    target_asset_id TEXT NOT NULL,
    evidence TEXT NOT NULL DEFAULT '{}',
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    FOREIGN KEY(source_asset_id) REFERENCES assets(id) ON DELETE CASCADE,
    FOREIGN KEY(target_asset_id) REFERENCES assets(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_relationship_source ON asset_relationships(source_asset_id);
CREATE INDEX IF NOT EXISTS idx_relationship_target ON asset_relationships(target_asset_id);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    finding_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    affected_asset_id TEXT,
    component_id TEXT,
    source_connector_id TEXT,
    status TEXT NOT NULL DEFAULT 'open',
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    fix_recommendation TEXT,
    evidence TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY(affected_asset_id) REFERENCES assets(id) ON DELETE SET NULL,
    FOREIGN KEY(component_id) REFERENCES components(id) ON DELETE SET NULL,
    FOREIGN KEY(source_connector_id) REFERENCES connectors(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_asset ON findings(affected_asset_id);
CREATE INDEX IF NOT EXISTS idx_findings_component ON findings(component_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);

CREATE TABLE IF NOT EXISTS component_vulnerability_status (
    component_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'unknown',
    vulnerability_count INTEGER NOT NULL DEFAULT 0,
    max_severity TEXT NOT NULL DEFAULT 'unknown',
    checked_at TEXT NOT NULL,
    error TEXT,
    raw_response TEXT NOT NULL DEFAULT '{}',
    PRIMARY KEY(component_id, provider),
    FOREIGN KEY(component_id) REFERENCES components(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_vuln_status_status ON component_vulnerability_status(status);
CREATE INDEX IF NOT EXISTS idx_vuln_status_checked ON component_vulnerability_status(checked_at);

CREATE TABLE IF NOT EXISTS raw_sboms (
    id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL,
    format TEXT NOT NULL,
    document TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE CASCADE
);

-- OSV malware monitoring: one alert per (advisory, package, version) hit.
CREATE TABLE IF NOT EXISTS malware_alerts (
    id TEXT PRIMARY KEY,
    advisory_id TEXT NOT NULL,
    package TEXT NOT NULL,
    version TEXT,
    ecosystem TEXT,
    advisory_url TEXT,
    sources TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'active',
    asset_count INTEGER NOT NULL DEFAULT 0,
    affected_asset_ids TEXT NOT NULL DEFAULT '[]',
    alert_count INTEGER NOT NULL DEFAULT 1,
    first_alerted_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_malware_alerts_status ON malware_alerts(status);
CREATE INDEX IF NOT EXISTS idx_malware_alerts_advisory ON malware_alerts(advisory_id);

-- Simple key/value settings (Slack config, malware interval + last-run state).
CREATE TABLE IF NOT EXISTS app_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL
);

-- Scan job queue: UI enqueues a run per connection; runners claim + execute it.
CREATE TABLE IF NOT EXISTS scan_runs (
    id TEXT PRIMARY KEY,
    connector_id TEXT,
    source_name TEXT NOT NULL,
    job_type TEXT NOT NULL,                     -- 'image' | 'github'
    status TEXT NOT NULL DEFAULT 'queued',      -- queued | running | succeeded | failed | canceled
    requested_at TEXT NOT NULL,
    claimed_at TEXT,
    claimed_by TEXT,
    finished_at TEXT,
    summary TEXT NOT NULL DEFAULT '{}',
    error TEXT,
    FOREIGN KEY(connector_id) REFERENCES connectors(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_scan_runs_claim ON scan_runs(status, job_type, requested_at);
CREATE INDEX IF NOT EXISTS idx_scan_runs_connector ON scan_runs(connector_id, requested_at);

-- Liveness of scan runners. Every claim poll (even an idle one) upserts a row,
-- so a recent last_seen_at means a runner is connected for that job_type.
CREATE TABLE IF NOT EXISTS runner_heartbeats (
    runner_id TEXT NOT NULL,
    job_type TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    PRIMARY KEY (runner_id, job_type)
);
CREATE INDEX IF NOT EXISTS idx_runner_heartbeats_type ON runner_heartbeats(job_type, last_seen_at);

-- Authentication: human users (cookie sessions) + machine API tokens (bearer).
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'member',     -- admin | member | viewer
    disabled INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    last_login_at TEXT
);
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    csrf_token TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE TABLE IF NOT EXISTS api_tokens (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    scope TEXT NOT NULL,                      -- runner | ingest | readonly
    created_by TEXT,
    created_at TEXT NOT NULL,
    last_used_at TEXT,
    revoked_at TEXT
);

-- Login throttle, keyed by username so it survives across workers/restarts and
-- can't be bypassed by rotating source IPs. fail_count resets when the window
-- elapses (see Store.LOGIN_* constants).
CREATE TABLE IF NOT EXISTS login_attempts (
    username TEXT PRIMARY KEY,
    fail_count INTEGER NOT NULL DEFAULT 0,
    window_start INTEGER NOT NULL DEFAULT 0   -- epoch seconds
);

-- Connector credentials, encrypted at rest (Fernet under SUPPLYDRIFT_SECRET_KEY).
-- Kept OUT of the connector config JSON so they are never returned to the browser;
-- resolved only into /api/scanner/config for authenticated runners.
CREATE TABLE IF NOT EXISTS connector_secrets (
    connector_id TEXT NOT NULL,
    field TEXT NOT NULL,                      -- e.g. password | token | secret
    ciphertext TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (connector_id, field),
    FOREIGN KEY(connector_id) REFERENCES connectors(id) ON DELETE CASCADE
);
"""


def demo_payload() -> dict[str, Any]:
    return {
        "connector": {
            "name": "Demo SBOM Sync",
            "connector_type": "demo_multi_source",
            "status": "manual",
            "scope": {
                "github_orgs": ["acme"],
                "aws_accounts": ["123456789012"],
                "kubernetes_clusters": ["prod-eks-1"],
            },
        },
        "scan_metadata": {
            "status": "running",
            "started_at": now_iso(),
            "scanner_version": "mvp-demo-1",
        },
        "assets": [
            {
                "ref": "repo_payments",
                "asset_type": "repository",
                "provider": "github",
                "external_id": "github.com/acme/payments-api",
                "display_name": "acme/payments-api",
                "owner": "payments-platform",
                "environment": "production",
                "tags": ["pci", "tier-1"],
                "details": {
                    "git_provider": "github",
                    "org_name": "acme",
                    "repo_name": "payments-api",
                    "full_name": "acme/payments-api",
                    "repo_url": "https://github.com/acme/payments-api",
                    "default_branch": "main",
                    "visibility": "private",
                    "owner_team": "payments-platform",
                    "last_commit_sha": "8f7a8d9d9d33c4e5a0a4c0f0123456789abcdef0",
                    "last_commit_at": "2026-05-25T09:20:00+00:00",
                },
            },
            {
                "ref": "image_payments",
                "asset_type": "container_image",
                "provider": "aws_ecr",
                "external_id": "123456789012.dkr.ecr.us-east-1.amazonaws.com/payments-api@sha256:9c2d",
                "display_name": "payments-api@sha256:9c2d",
                "owner": "payments-platform",
                "environment": "production",
                "tags": ["pci", "runtime"],
                "raw_metadata": {
                    "provenance": {
                        "discovery_source": "kubernetes",
                        "source_repository": "github.com/acme/payments-api",
                        "discovered_in": "prod-eks-1/payments/Deployment/payments-api/payments",
                        "context": {"connector": "eks", "cluster": "prod-eks-1", "namespace": "payments"},
                    }
                },
                "details": {
                    "registry_type": "ecr",
                    "registry_url": "123456789012.dkr.ecr.us-east-1.amazonaws.com",
                    "account_id": "123456789012",
                    "repository": "payments-api",
                    "image_name": "payments-api",
                    "tag": "prod-2026-05-25",
                    "digest": "sha256:9c2d8bb9e8b91f2c4e5f6a7b8c9d0e1f",
                    "architecture": "amd64",
                    "os": "linux",
                    "pushed_at": "2026-05-25T09:41:00+00:00",
                    "provenance": {
                        "discovery_source": "kubernetes",
                        "source_repository": "github.com/acme/payments-api",
                        "discovered_in": "prod-eks-1/payments/Deployment/payments-api/payments",
                        "context": {"connector": "eks", "cluster": "prod-eks-1", "namespace": "payments"},
                    },
                },
            },
            {
                "ref": "cluster_prod",
                "asset_type": "k8s_cluster",
                "provider": "aws_eks",
                "external_id": "arn:aws:eks:us-east-1:123456789012:cluster/prod-eks-1",
                "display_name": "prod-eks-1",
                "owner": "platform",
                "environment": "production",
                "raw_metadata": {"account_id": "123456789012", "region": "us-east-1"},
            },
            {
                "ref": "workload_payments",
                "asset_type": "k8s_workload",
                "provider": "aws_eks",
                "external_id": "prod-eks-1/payments/Deployment/payments-api/payments",
                "display_name": "payments/payments-api",
                "owner": "payments-platform",
                "environment": "production",
                "details": {
                    "cluster_name": "prod-eks-1",
                    "cloud_provider": "aws",
                    "account_id": "123456789012",
                    "region": "us-east-1",
                    "namespace": "payments",
                    "workload_kind": "Deployment",
                    "workload_name": "payments-api",
                    "pod_name": "payments-api-67bb5f9f68-24x9k",
                    "container_name": "payments",
                    "service_account": "payments-api",
                    "image_reference": "123456789012.dkr.ecr.us-east-1.amazonaws.com/payments-api:prod-2026-05-25",
                    "image_digest": "sha256:9c2d8bb9e8b91f2c4e5f6a7b8c9d0e1f",
                    "node_name": "ip-10-16-44-91.ec2.internal",
                },
            },
            {
                "ref": "workload_shadow",
                "asset_type": "k8s_workload",
                "provider": "aws_eks",
                "external_id": "prod-eks-1/default/CronJob/data-migration/runner",
                "display_name": "default/data-migration",
                "owner": "unknown",
                "environment": "production",
                "tags": ["shadow-deployment"],
                "details": {
                    "cluster_name": "prod-eks-1",
                    "cloud_provider": "aws",
                    "account_id": "123456789012",
                    "region": "us-east-1",
                    "namespace": "default",
                    "workload_kind": "CronJob",
                    "workload_name": "data-migration",
                    "container_name": "runner",
                    "service_account": "default",
                    "image_reference": "docker.io/library/python:latest",
                    "image_digest": "",
                },
            },
            {
                "ref": "endpoint_laptop",
                "asset_type": "endpoint",
                "provider": "kandji",
                "external_id": "endpoint:LT-ACME-0421",
                "display_name": "LT-ACME-0421 (j.rivera)",
                "owner": "j.rivera@acme.com",
                "environment": "corp",
                "tags": ["developer", "macos"],
                "details": {
                    "endpoint_id": "LT-ACME-0421",
                    "hostname": "lt-acme-0421.local",
                    "serial_number": "C02X1234JGH7",
                    "os_name": "macOS",
                    "os_version": "15.4",
                    "architecture": "arm64",
                    "device_type": "laptop",
                    "mdm_id": "kandji:7f3a",
                    "employee_id": "E2291",
                    "employee_email": "j.rivera@acme.com",
                    "employee_name": "Jordan Rivera",
                    "department": "Payments Engineering",
                    "location": "Remote / US-East",
                    "last_checkin_at": "2026-06-05T22:10:00+00:00",
                },
            },
        ],
        "components": [
            {
                "ref": "openssl_111",
                "name": "openssl",
                "version": "1.1.1f-1ubuntu2.18",
                "ecosystem": "deb",
                "package_manager": "dpkg",
                "purl": "pkg:deb/ubuntu/openssl@1.1.1f-1ubuntu2.18?arch=amd64",
                "license": "OpenSSL",
            },
            {
                "ref": "openssl_302",
                "name": "openssl",
                "version": "3.0.2-0ubuntu1.12",
                "ecosystem": "deb",
                "package_manager": "dpkg",
                "purl": "pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.12?arch=amd64",
                "license": "OpenSSL",
            },
            {
                "ref": "glibc",
                "name": "glibc",
                "version": "2.35-0ubuntu3.6",
                "ecosystem": "deb",
                "package_manager": "dpkg",
                "purl": "pkg:deb/ubuntu/glibc@2.35-0ubuntu3.6?arch=amd64",
            },
            {
                "ref": "requests",
                "name": "requests",
                "version": "2.31.0",
                "ecosystem": "pypi",
                "package_manager": "pip",
                "purl": "pkg:pypi/requests@2.31.0",
                "license": "Apache-2.0",
            },
            {
                "ref": "github_action",
                "name": "goreleaser/goreleaser-action",
                "version": "v5",
                "ecosystem": "github-actions",
                "package_manager": "github-actions",
                "purl": "pkg:githubactions/goreleaser/goreleaser-action@v5",
            },
            {
                "ref": "repo_curl_install",
                "name": "curl https://raw.githubusercontent.com/acme/tools/main/install.sh | bash",
                "ecosystem": "generic",
                "package_manager": "generic",
                "purl": "pkg:generic/install.sh",
            },
            {
                "ref": "node_endpoint",
                "name": "node",
                "version": "18.16.0",
                "ecosystem": "generic",
                "package_manager": "homebrew",
                "purl": "pkg:generic/node@18.16.0",
            },
        ],
        "component_usages": [
            {"asset_ref": "repo_payments", "component_ref": "github_action", "source": "repo_scan", "evidence_path": ".github/workflows/release.yml:14"},
            {"asset_ref": "repo_payments", "component_ref": "repo_curl_install", "source": "repo_scan", "evidence_path": ".github/workflows/ci.yml:22"},
            {"asset_ref": "repo_payments", "component_ref": "requests", "source": "repo_scan", "evidence_path": "requirements.txt"},
            {"asset_ref": "image_payments", "component_ref": "openssl_111", "source": "image_scan", "evidence_path": "/var/lib/dpkg/status", "package_manager": "dpkg", "layer_digest": "sha256:layer-os"},
            {"asset_ref": "image_payments", "component_ref": "glibc", "source": "image_scan", "evidence_path": "/var/lib/dpkg/status", "package_manager": "dpkg", "layer_digest": "sha256:layer-os"},
            {"asset_ref": "image_payments", "component_ref": "requests", "source": "image_scan", "evidence_path": "/usr/local/lib/python/site-packages/requests-2.31.0.dist-info"},
            {"asset_ref": "workload_payments", "component_ref": "openssl_111", "source": "runtime_scan", "evidence_path": "image sha256:9c2d"},
            {"asset_ref": "workload_shadow", "component_ref": "openssl_302", "source": "runtime_scan", "evidence_path": "/usr/lib/x86_64-linux-gnu/libssl.so.3"},
            {"asset_ref": "endpoint_laptop", "component_ref": "node_endpoint", "source": "endpoint_scan", "evidence_path": "/opt/homebrew/bin/node", "package_manager": "homebrew"},
            {"asset_ref": "endpoint_laptop", "component_ref": "requests", "source": "endpoint_scan", "evidence_path": "/Users/j.rivera/.venv/lib/python3.12/site-packages/requests"},
        ],
        "relationships": [
            {"source_ref": "repo_payments", "relationship_type": "builds", "target_ref": "image_payments", "evidence": {"commit_sha": "8f7a8d9d9d33c4e5a0a4c0f0123456789abcdef0"}},
            {"source_ref": "image_payments", "relationship_type": "runs_in", "target_ref": "workload_payments", "evidence": {"image_digest": "sha256:9c2d8bb9e8b91f2c4e5f6a7b8c9d0e1f"}},
            {"source_ref": "workload_payments", "relationship_type": "belongs_to", "target_ref": "cluster_prod"},
            {"source_ref": "workload_shadow", "relationship_type": "belongs_to", "target_ref": "cluster_prod"},
        ],
        "findings": [
            {
                "asset_ref": "repo_payments",
                "component_ref": "github_action",
                "finding_type": "cicd-tool",
                "severity": "high",
                "title": "cicd-tool: goreleaser/goreleaser-action@v5",
                "description": "goreleaser/goreleaser-action@v5 is mutable and can drift at workflow runtime.",
                "fix_recommendation": "Pin the action to a full commit SHA and review transitive action dependencies.",
                "evidence": {"file": ".github/workflows/release.yml", "line": 14, "category": "cicd-tool"},
            },
            {
                "asset_ref": "repo_payments",
                "component_ref": "repo_curl_install",
                "finding_type": "script-installation",
                "severity": "critical",
                "title": "script-installation: curl … | bash",
                "description": "CI downloads and executes a remote script (curl | bash) — invisible to lockfile SCA.",
                "fix_recommendation": "Vendor the script or pin it to a verified checksum instead of piping a live URL to bash.",
                "evidence": {"file": ".github/workflows/ci.yml", "line": 22, "category": "script-installation"},
            },
            {
                "asset_ref": "image_payments",
                "component_ref": "openssl_111",
                "finding_type": "cve",
                "severity": "critical",
                "title": "Critical OpenSSL exposure in shipped image",
                "description": "The runtime image contains an OpenSSL package that was not visible from lockfile-only SCA.",
                "fix_recommendation": "Rebuild from a patched base image and redeploy all dependent workloads.",
                "evidence": {"source": "registry_sbom", "image_digest": "sha256:9c2d8bb9e8b91f2c4e5f6a7b8c9d0e1f"},
            },
            {
                "asset_ref": "workload_shadow",
                "finding_type": "shadow_deployment",
                "severity": "critical",
                "title": "Workload has no repository or approved delivery path",
                "description": "The data-migration CronJob is running in production but has no mapped repo, CI job, or GitOps source.",
                "fix_recommendation": "Move the workload into the approved deployment pipeline or remove it.",
                "evidence": {"cluster": "prod-eks-1", "namespace": "default", "kind": "CronJob"},
            },
            {
                "asset_ref": "workload_shadow",
                "finding_type": "unpinned_image",
                "severity": "high",
                "title": "Runtime workload uses a mutable image tag",
                "description": "docker.io/library/python:latest can resolve to different content over time.",
                "fix_recommendation": "Use a digest-pinned image reference from an approved registry.",
                "evidence": {"image": "docker.io/library/python:latest"},
            },
            {
                "asset_ref": "endpoint_laptop",
                "component_ref": "node_endpoint",
                "finding_type": "endpoint_eol_runtime",
                "severity": "medium",
                "title": "End-of-life Node.js on a developer laptop",
                "description": "Node 18.16.0 is installed via Homebrew on a developer machine and is past its support window.",
                "fix_recommendation": "Upgrade to an active LTS Node release via the managed toolchain.",
                "evidence": {"path": "/opt/homebrew/bin/node", "device": "LT-ACME-0421"},
            },
        ],
        "raw_sboms": [
            {
                "asset_ref": "image_payments",
                "format": "cyclonedx",
                "document": {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.5",
                    "components": [
                        {
                            "name": "openssl",
                            "version": "1.1.1f-1ubuntu2.18",
                            "type": "library",
                            "properties": [{"name": "supplydrift:path", "value": "/var/lib/dpkg/status"}],
                        },
                        {
                            "name": "requests",
                            "version": "2.31.0",
                            "type": "library",
                            "properties": [
                                {
                                    "name": "supplydrift:path",
                                    "value": "/usr/local/lib/python/site-packages/requests-2.31.0.dist-info",
                                }
                            ],
                        },
                    ],
                },
            }
        ],
    }
