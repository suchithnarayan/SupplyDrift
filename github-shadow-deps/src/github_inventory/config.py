from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path
from typing import Optional

import regex

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore[assignment]


MAX_IGNORE_RULES = 100
MAX_IGNORE_PATTERN_LENGTH = 512
IGNORE_MATCH_TIMEOUT_SECONDS = 0.025
_CONFIG_KEYS = {
    "version",
    "ignore",
    "exclude_paths",
    "severity_overrides",
    "trusted_registries",
}
_IGNORE_KEYS = {"pattern", "reason"}
_SEVERITY_OVERRIDE_KEYS = {"severity"}


@dataclass
class IgnoreRule:
    pattern: str
    reason: str = ""
    _compiled: Optional[regex.Pattern] = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.pattern, str) or not self.pattern:
            raise ValueError("ignore rule pattern must be a non-empty string")
        if len(self.pattern) > MAX_IGNORE_PATTERN_LENGTH:
            raise ValueError(
                f"ignore rule pattern exceeds {MAX_IGNORE_PATTERN_LENGTH} characters"
            )
        if not isinstance(self.reason, str):
            raise ValueError("ignore rule reason must be a string")
        try:
            self._compiled = regex.compile(self.pattern)
        except regex.error as exc:
            raise ValueError("invalid ignore rule pattern") from exc

    @property
    def compiled(self) -> regex.Pattern:
        if self._compiled is None:
            # Defensive fallback for deserialized/legacy instances.
            self.__post_init__()
        assert self._compiled is not None
        return self._compiled

    def matches(self, text: str) -> bool:
        try:
            return bool(self.compiled.search(text, timeout=IGNORE_MATCH_TIMEOUT_SECONDS))
        except TimeoutError as exc:
            raise ValueError("ignore rule evaluation exceeded the 25 ms limit") from exc


@dataclass
class Config:
    ignore: list[IgnoreRule] = field(default_factory=list)
    exclude_paths: list[str] = field(default_factory=list)
    severity_overrides: dict[str, str] = field(default_factory=dict)
    trusted_registries: list[str] = field(default_factory=list)

    # Runtime-only flags driven by CLI (not loaded from .github-inventory.yml).
    # Keep AI features OFF by default — the regex scanner must work without
    # the optional runtime AI SDK installed.
    ai_enabled: bool = False
    ai_model: str = "claude-sonnet-4-6"
    ai_max_files: int = 20
    enrich_enabled: bool = False
    deep_lockfile: bool = False

    # Default excluded paths applied to every scan
    _DEFAULT_EXCLUDES: list[str] = field(
        default_factory=lambda: [
            ".git/**",
            "node_modules/**",
            "__pycache__/**",
            ".venv/**",
            "venv/**",
            "*.min.js",
        ],
        repr=False,
        compare=False,
    )

    # Default trusted container registries
    _DEFAULT_TRUSTED_REGISTRIES: list[str] = field(
        default_factory=lambda: [
            "docker.io",
            "index.docker.io",
            "gcr.io",
            "ghcr.io",
            "quay.io",
            "registry.hub.docker.com",
            "*.dkr.ecr.*.amazonaws.com",
            "*.azurecr.io",
        ],
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        if len(self.ignore) > MAX_IGNORE_RULES:
            raise ValueError(f"config may define at most {MAX_IGNORE_RULES} ignore rules")
        if not all(isinstance(rule, IgnoreRule) for rule in self.ignore):
            raise ValueError("config ignore entries must be IgnoreRule objects")

    @classmethod
    def load(cls, config_path: Path) -> "Config":
        """Load an exact, externally selected configuration file."""
        config_path = Path(config_path)
        if not config_path.exists():
            raise ValueError(f"config file does not exist: {config_path}")
        if not config_path.is_file():
            raise ValueError(f"config path is not a file: {config_path}")
        if yaml is None:
            raise ValueError("PyYAML is required to load scanner configuration")
        try:
            with open(config_path, encoding="utf-8") as f:
                raw = yaml.safe_load(f) or {}
        except (OSError, yaml.YAMLError) as exc:
            raise ValueError("unable to load scanner configuration") from exc
        return cls._from_dict(raw)

    @classmethod
    def load_target(cls, repo_root: Path) -> "Config":
        """Load target-owned policy after the caller has explicitly opted in."""
        root = Path(repo_root).resolve()
        config_path = root / ".github-inventory.yml"
        if not config_path.exists():
            return cls()
        try:
            resolved = config_path.resolve(strict=True)
        except OSError as exc:
            raise ValueError("unable to resolve target-owned scanner configuration") from exc
        if not resolved.is_relative_to(root):
            raise ValueError("target-owned scanner configuration must stay inside the target")
        return cls.load(resolved)

    @classmethod
    def _from_dict(cls, raw: dict) -> "Config":
        if not isinstance(raw, dict):
            raise ValueError("scanner configuration must be a mapping")
        _reject_unknown_keys(raw, _CONFIG_KEYS, "config")
        if "version" in raw:
            version = raw["version"]
            if (
                not isinstance(version, int)
                or isinstance(version, bool)
                or version != 1
            ):
                raise ValueError("config 'version' must be integer 1")

        raw_ignore = raw.get("ignore", [])
        if not isinstance(raw_ignore, list):
            raise ValueError("config 'ignore' must be a list")
        if len(raw_ignore) > MAX_IGNORE_RULES:
            raise ValueError(f"config may define at most {MAX_IGNORE_RULES} ignore rules")
        ignore: list[IgnoreRule] = []
        for item in raw_ignore:
            if not isinstance(item, dict) or "pattern" not in item:
                raise ValueError("each ignore rule must be a mapping with a pattern")
            _reject_unknown_keys(item, _IGNORE_KEYS, "ignore rule")
            ignore.append(IgnoreRule(pattern=item["pattern"], reason=item.get("reason", "")))

        exclude_paths = _string_list(raw.get("exclude_paths", []), "exclude_paths")
        trusted_registries = _string_list(
            raw.get("trusted_registries", []), "trusted_registries"
        )

        raw_overrides = raw.get("severity_overrides", {})
        if not isinstance(raw_overrides, dict):
            raise ValueError("config 'severity_overrides' must be a mapping")
        severity_overrides: dict[str, str] = {}
        for pattern_id, value in raw_overrides.items():
            if not isinstance(pattern_id, str) or not isinstance(value, dict):
                raise ValueError("severity overrides must map pattern IDs to mappings")
            _reject_unknown_keys(
                value, _SEVERITY_OVERRIDE_KEYS, f"severity override {pattern_id!r}"
            )
            severity = value.get("severity")
            if severity not in {"critical", "high", "medium", "low"}:
                raise ValueError("severity override must be critical, high, medium, or low")
            severity_overrides[pattern_id] = severity
        return cls(
            ignore=ignore,
            exclude_paths=exclude_paths,
            severity_overrides=severity_overrides,
            trusted_registries=trusted_registries,
        )

    def should_ignore(self, extracted_dep: str) -> bool:
        return any(rule.matches(extracted_dep) for rule in self.ignore)

    def is_path_excluded(self, rel_path: str) -> bool:
        all_excludes = list(self._DEFAULT_EXCLUDES) + list(self.exclude_paths)
        return any(fnmatch(rel_path, pat) for pat in all_excludes)

    def get_all_trusted_registries(self) -> list[str]:
        return list(self._DEFAULT_TRUSTED_REGISTRIES) + list(self.trusted_registries)


def _string_list(value: object, name: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"config '{name}' must be a list of strings")
    return list(value)


def _reject_unknown_keys(value: dict, allowed: set[str], location: str) -> None:
    unknown = sorted((key for key in value if key not in allowed), key=str)
    if unknown:
        rendered = ", ".join(repr(key) for key in unknown)
        raise ValueError(f"unknown key(s) in {location}: {rendered}")
