"""Config for the GitHub repository sync — mirror of the image-scanner config.

Reads GitHub sources from a YAML file (``sources:``) or from the platform's
``GET /api/scanner/config`` feed (``github:`` array). Auth is optional: omit the
``auth`` block (or list explicit public ``repositories``) to scan public repos
anonymously, exactly like the image-scanner registries.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

GITHUB_TYPES = {"github", "github_repo", "repo"}


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
    concurrency: int = 2
    clone_timeout: int = 120
    # Declared-dependency SBOM (syft) + CVEs (grype) alongside phantom-deps.
    # On by default; degrades gracefully when the binaries are absent.
    scan_sbom: bool = True
    scan_vulnerabilities: bool = True
    syft_bin: str = "syft"
    grype_bin: str = "grype"
    scan_timeout: int = 600

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "ScannerConfig":
        data = data or {}
        return cls(
            concurrency=int(data.get("concurrency", 2)),
            clone_timeout=int(data.get("clone_timeout", 120)),
            scan_sbom=bool(data.get("scan_sbom", True)),
            scan_vulnerabilities=bool(data.get("scan_vulnerabilities", True)),
            syft_bin=str(data.get("syft_bin", "syft")),
            grype_bin=str(data.get("grype_bin", "grype")),
            scan_timeout=int(data.get("scan_timeout", 600)),
        )


@dataclass
class SourceFilters:
    repositories: list[str] = field(default_factory=lambda: ["*"])
    include_archived: bool = False
    max_repos: int | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "SourceFilters":
        data = data or {}
        return cls(
            repositories=list(data.get("repositories", ["*"])) or ["*"],
            include_archived=bool(data.get("include_archived", False)),
            max_repos=data.get("max_repos"),
        )

    def repo_allowed(self, name: str, full_name: str = "") -> bool:
        # A pattern with "/" matches the owner/repo full name; a bare pattern
        # matches just the repo name (so "a*" doesn't match every "acme/*").
        for pat in self.repositories:
            target = full_name if ("/" in pat and full_name) else name
            if fnmatch(target, pat):
                return True
        return False


@dataclass
class SourceConfig:
    name: str
    type: str
    source_id: str = ""
    enabled: bool = True
    connection: dict[str, Any] = field(default_factory=dict)
    filters: SourceFilters = field(default_factory=SourceFilters)
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class Config:
    version: int
    platform: PlatformConfig
    scanner: ScannerConfig
    sources: list[SourceConfig]

    def source(self, name: str) -> SourceConfig | None:
        for src in self.sources:
            if src.name == name:
                return src
        return None


def _source_from_raw(raw: dict[str, Any], index: int) -> SourceConfig:
    if not isinstance(raw, dict):
        raise ValueError(f"sources[{index}] must be a mapping")
    name = raw.get("name")
    if not name:
        raise ValueError(f"sources[{index}] requires 'name'")
    stype = str(raw.get("type") or raw.get("provider") or "github").lower()
    if stype not in GITHUB_TYPES:
        raise ValueError(f"sources[{index}] '{name}': unknown type '{raw.get('type')}' (expected github)")
    return SourceConfig(
        name=str(name),
        type="github",
        source_id=str(raw.get("connector_id") or raw.get("id") or ""),
        enabled=bool(raw.get("enabled", True)),
        connection=raw.get("connection") or {},
        filters=SourceFilters.from_dict(raw.get("scan") or raw.get("filters")),
        raw=raw,
    )


def parse_config(data: dict[str, Any]) -> Config:
    if not isinstance(data, dict):
        raise ValueError("config root must be a mapping")
    # File config uses `sources:`; the platform feed uses `github:`.
    raw_sources = data.get("sources") or data.get("github") or []
    sources = [_source_from_raw(raw, i) for i, raw in enumerate(raw_sources)]
    names = [s.name for s in sources]
    duplicates = {n for n in names if names.count(n) > 1}
    if duplicates:
        raise ValueError(f"duplicate source names: {', '.join(sorted(duplicates))}")
    return Config(
        version=int(data.get("version", 1)),
        platform=PlatformConfig.from_dict(data.get("platform")),
        scanner=ScannerConfig.from_dict(data.get("scanner")),
        sources=sources,
    )


def load_config(path: str | Path) -> Config:
    import yaml

    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    return parse_config(data)


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
    """Fetch config from the platform (``GET /api/scanner/config``)."""
    if fetcher is None:
        from urllib.parse import urlsplit
        from urllib.request import Request, urlopen

        # Only fetch over http(s); reject file://, ftp://, gopher://, etc. so a
        # config-url can't be pointed at the local filesystem or another scheme
        # (mirrors image_scanner.config.load_config_from_url).
        scheme = urlsplit(url).scheme.lower()
        if scheme not in ("http", "https"):
            raise RuntimeError(
                f"--config-url must be an http(s) URL (got scheme '{scheme}')"
            )

        def fetcher(target: str) -> str:  # type: ignore[misc]
            request = Request(target, headers={"Accept": "application/json", **auth_headers()})
            with urlopen(request, timeout=30) as response:
                return response.read().decode("utf-8")

    raw = fetcher(url)
    try:
        data = json.loads(raw or "{}")
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"platform config at {url} was not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise RuntimeError(f"platform config at {url} must be a JSON object")
    return parse_config(data)
