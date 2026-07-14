"""Load and validate the YAML scanner config.

The config is the single source of truth for what to scan and how. Two top-level
sections describe the two kinds of source:

* ``registries`` — registry accounts to enumerate directly (Docker Hub, GHCR,
  Harbor, ECR). These are *config-scoped*: you cannot scan every repo/tag, so a
  per-registry ``scan`` template narrows the surface.
* ``services`` — running container platforms to enumerate exhaustively
  (Kubernetes, ECS, EKS). Every image in every cluster is collected; pull
  credentials fall back to the configured ``registries``.

A top-level ``defaults.scan`` block is deep-merged into every source's filters.
AWS-backed sources (ECR/ECS/EKS) carry an ``aws_auth`` block resolved into a
shared :class:`~image_scanner.auth.aws.AwsSession`.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .auth.aws import AwsSession
from .models import ImageFilter

REGISTRY_TYPES = {"dockerhub", "ghcr", "harbor", "ecr"}
SERVICE_TYPES = {"kubernetes", "eks", "ecs"}

_REGISTRY_ALIASES = {
    "docker_hub": "dockerhub",
    "docker-hub": "dockerhub",
    "github": "ghcr",
    "github_container_registry": "ghcr",
    "aws_ecr": "ecr",
}
_SERVICE_ALIASES = {
    "k8s": "kubernetes",
    "aws_eks": "eks",
    "aws_ecs": "ecs",
}


@dataclass
class PlatformConfig:
    url: str = "http://127.0.0.1:8765"
    push: bool = True

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "PlatformConfig":
        data = data or {}
        return cls(url=str(data.get("url", cls.url)), push=bool(data.get("push", True)))


@dataclass
class ScannerConfig:
    extractor: str = "syft"
    syft_bin: str = "syft"
    grype_bin: str = "grype"
    scan_vulnerabilities: bool = True  # run grype over the SBOM to attach CVEs
    concurrency: int = 4
    cache_dir: str = ".image-scan-cache"
    timeout: int = 600

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "ScannerConfig":
        data = data or {}
        return cls(
            extractor=str(data.get("extractor", "syft")).lower(),
            syft_bin=str(data.get("syft_bin", "syft")),
            grype_bin=str(data.get("grype_bin", "grype")),
            scan_vulnerabilities=bool(data.get("scan_vulnerabilities", True)),
            concurrency=int(data.get("concurrency", 4)),
            cache_dir=str(data.get("cache_dir", ".image-scan-cache")),
            timeout=int(data.get("timeout", 600)),
        )


@dataclass
class RegistryConfig:
    name: str
    type: str
    source_id: str = ""
    enabled: bool = True
    connection: dict[str, Any] = field(default_factory=dict)
    discovery: dict[str, Any] = field(default_factory=dict)
    filters: ImageFilter = field(default_factory=ImageFilter)
    aws_session: AwsSession | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    category = "registry"


@dataclass
class ServiceConfig:
    name: str
    type: str
    source_id: str = ""
    enabled: bool = True
    connection: dict[str, Any] = field(default_factory=dict)
    discovery: dict[str, Any] = field(default_factory=dict)
    filters: ImageFilter = field(default_factory=ImageFilter)
    aws_session: AwsSession | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    category = "service"


@dataclass
class Config:
    version: int
    platform: PlatformConfig
    scanner: ScannerConfig
    registries: list[RegistryConfig]
    services: list[ServiceConfig]

    def all_sources(self) -> list[Any]:
        return [*self.registries, *self.services]

    def source(self, name: str) -> Any | None:
        for src in self.all_sources():
            if src.name == name:
                return src
        return None


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


def _aws_auth_block(connection: dict[str, Any]) -> dict[str, Any]:
    """Collect an ``aws_auth`` block, folding in any top-level AWS keys."""
    block = dict(connection.get("aws_auth") or {})
    for key in (
        "profile",
        "access_key_id",
        "secret_access_key",
        "session_token",
        "role_arn",
        "external_id",
        "region",
        "regions",
    ):
        if key in connection and key not in block:
            block[key] = connection[key]
    return block


def _registry_connection(rtype: str, raw: dict[str, Any]) -> dict[str, Any]:
    conn = copy.deepcopy(raw.get("connection") or {})
    # Allow a few common keys at the source level for convenience.
    for key in ("auth", "namespace", "namespaces", "owner", "owner_type", "url", "registry", "account_id", "images"):
        if raw.get(key) is not None and key not in conn:
            conn[key] = copy.deepcopy(raw[key])
    if rtype == "ghcr":
        conn.setdefault("registry", "ghcr.io")
    if rtype == "harbor":
        url = conn.get("url") or conn.get("registry") or ""
        if not url:
            raise ValueError("harbor registry requires connection.url (e.g. https://harbor.example.io)")
        split = urlsplit(url if "://" in url else f"https://{url}")
        host = split.netloc or split.path
        conn["url"] = f"{split.scheme or 'https'}://{host}".rstrip("/") if host else url
        conn["registry"] = host
    return conn


def _service_connection(stype: str, raw: dict[str, Any]) -> dict[str, Any]:
    conn = copy.deepcopy(raw.get("connection") or {})
    for key in ("kubeconfig", "contexts", "context", "clusters", "aws_auth"):
        if raw.get(key) is not None and key not in conn:
            conn[key] = copy.deepcopy(raw[key])
    return conn


def _resolve_type(raw: dict[str, Any], *, valid: set[str], aliases: dict[str, str], kind: str, index: int) -> str:
    rtype = str(raw.get("type") or raw.get("provider") or "").lower()
    rtype = aliases.get(rtype, rtype)
    if rtype not in valid:
        raise ValueError(
            f"{kind}s[{index}] '{raw.get('name', '?')}' has unknown type '{raw.get('type')}'. "
            f"Valid {kind} types: {', '.join(sorted(valid))}"
        )
    return rtype


def _canon_scan(data: dict[str, Any] | None) -> dict[str, Any]:
    """Collapse filter aliases to canonical keys so defaults/source merge cleanly."""
    out = dict(data or {})
    cap = out.pop("max_images_per_repo", None)
    cap = cap if cap is not None else out.pop("latest_versions", None)
    cap = cap if cap is not None else out.pop("max_tags_per_image", None)
    out.pop("latest_versions", None)
    out.pop("max_tags_per_image", None)
    if cap is not None:
        out["max_images_per_repo"] = cap
    return out


def _merged_filters(raw: dict[str, Any], default_filters: dict[str, Any], *, registry: bool) -> ImageFilter:
    scan = raw.get("scan") or raw.get("filters") or {}
    merged = _deep_merge(_canon_scan(default_filters), _canon_scan(scan))
    if registry and "max_images_per_repo" not in merged:
        merged["max_images_per_repo"] = 1  # default: latest version per repo only
    return ImageFilter.from_dict(merged)


def _registry_from_raw(raw: dict[str, Any], *, index: int, default_filters: dict[str, Any]) -> RegistryConfig:
    if not isinstance(raw, dict):
        raise ValueError(f"registries[{index}] must be a mapping")
    name = raw.get("name")
    if not name:
        raise ValueError(f"registries[{index}] requires 'name'")
    rtype = _resolve_type(raw, valid=REGISTRY_TYPES, aliases=_REGISTRY_ALIASES, kind="registrie", index=index)
    conn = _registry_connection(rtype, raw)
    aws_session = AwsSession.from_config(_aws_auth_block(conn)) if rtype == "ecr" else None
    return RegistryConfig(
        name=str(name),
        type=rtype,
        source_id=str(raw.get("connector_id") or raw.get("id") or ""),
        enabled=bool(raw.get("enabled", True)),
        connection=conn,
        discovery=raw.get("discovery") or {},
        filters=_merged_filters(raw, default_filters, registry=True),
        aws_session=aws_session,
        raw=raw,
    )


def _service_from_raw(raw: dict[str, Any], *, index: int, default_filters: dict[str, Any]) -> ServiceConfig:
    if not isinstance(raw, dict):
        raise ValueError(f"services[{index}] must be a mapping")
    name = raw.get("name")
    if not name:
        raise ValueError(f"services[{index}] requires 'name'")
    stype = _resolve_type(raw, valid=SERVICE_TYPES, aliases=_SERVICE_ALIASES, kind="service", index=index)
    conn = _service_connection(stype, raw)
    aws_session = AwsSession.from_config(_aws_auth_block(conn)) if stype in ("eks", "ecs") else None
    return ServiceConfig(
        name=str(name),
        type=stype,
        source_id=str(raw.get("connector_id") or raw.get("id") or ""),
        enabled=bool(raw.get("enabled", True)),
        connection=conn,
        discovery=raw.get("discovery") or {},
        filters=_merged_filters(raw, default_filters, registry=False),
        aws_session=aws_session,
        raw=raw,
    )


def parse_config(data: dict[str, Any]) -> Config:
    if not isinstance(data, dict):
        raise ValueError("config root must be a mapping")
    defaults = data.get("defaults") or {}
    default_filters = defaults.get("scan") or defaults.get("filters") or {}

    registries = [
        _registry_from_raw(raw, index=i, default_filters=default_filters)
        for i, raw in enumerate(data.get("registries") or [])
    ]
    services = [
        _service_from_raw(raw, index=i, default_filters=default_filters)
        for i, raw in enumerate(data.get("services") or [])
    ]

    names = [s.name for s in (*registries, *services)]
    duplicates = {n for n in names if names.count(n) > 1}
    if duplicates:
        raise ValueError(f"duplicate source names: {', '.join(sorted(duplicates))}")

    return Config(
        version=int(data.get("version", 2)),
        platform=PlatformConfig.from_dict(data.get("platform")),
        scanner=ScannerConfig.from_dict(data.get("scanner")),
        registries=registries,
        services=services,
    )


def load_config(path: str | Path) -> Config:
    try:
        import yaml
    except ImportError as exc:  # pragma: no cover - depends on env
        raise RuntimeError("PyYAML is required to read the config (pip install pyyaml)") from exc
    text = Path(path).read_text(encoding="utf-8")
    data = yaml.safe_load(text) or {}
    return parse_config(data)


# fetcher(url) -> JSON text. Injectable so tests never touch the network.
Fetcher = "Callable[[str], str]"


def runner_token() -> str | None:
    """The runner's bearer token for the platform: explicit env override, else the
    shared-volume file the platform self-generates (zero-touch in compose)."""
    import os
    from pathlib import Path

    env_tok = os.environ.get("SUPPLYDRIFT_RUNNER_TOKEN")
    if env_tok:
        return env_tok.strip()
    path = Path(os.environ.get("SUPPLYDRIFT_RUNNER_TOKEN_FILE", "/run/supplydrift/runner.token"))
    try:
        return (path.read_text(encoding="utf-8").strip() or None) if path.exists() else None
    except OSError:
        return None


def auth_headers() -> dict[str, str]:
    tok = runner_token()
    return {"Authorization": f"Bearer {tok}"} if tok else {}


def load_config_from_url(url: str, fetcher: Any = None) -> Config:
    """Fetch the scanner config from the platform (``GET /api/scanner/config``).

    The platform assembles UI-managed connectors into the same
    ``{registries, services}`` document that :func:`parse_config` understands, so
    the file and platform paths share one parser. Auth is expressed as env-var
    references, so no secrets travel over the wire.
    """
    if fetcher is None:
        import json
        from urllib.request import Request, urlopen

        # Only fetch over http(s); reject file://, ftp://, gopher://, etc. so a
        # config-url can't be pointed at the local filesystem or another scheme.
        scheme = urlsplit(url).scheme.lower()
        if scheme not in ("http", "https"):
            raise RuntimeError(
                f"--config-url must be an http(s) URL (got scheme '{scheme}')"
            )

        def fetcher(target: str) -> str:  # type: ignore[misc]
            request = Request(target, headers={"Accept": "application/json", **auth_headers()})
            with urlopen(request, timeout=30) as response:
                return response.read().decode("utf-8")

    import json

    raw = fetcher(url)
    try:
        data = json.loads(raw or "{}")
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"platform config at {url} was not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise RuntimeError(f"platform config at {url} must be a JSON object")
    return parse_config(data)
