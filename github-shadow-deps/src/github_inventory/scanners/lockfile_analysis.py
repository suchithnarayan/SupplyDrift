"""
Lockfile-aware shadow-dependency detection.

Standard pattern scanners look at *committed source* (package.json scripts,
Cargo.toml deps). They miss the long tail of *transitive* risks declared in
lockfiles — packages with `postinstall` / `preinstall` / `prepare` /
`install` scripts that execute on every `npm install`. Notable historical
incidents: ua-parser-js (2021), event-stream (2018), colors.js (2022).

This scanner parses lockfiles structurally (JSON / YAML / TOML) and emits
a TRANSITIVE_HOOK finding for every package whose metadata declares an
install-time script. It is opt-in via Config flag because:
- Lockfiles are large (10k+ packages); parsing costs real time.
- The signal is noisy without context — most postinstall hooks are benign
  (e.g. esbuild, sharp, prebuild-install pulling matching native binaries).

The point is *visibility*: surface the universe of code that runs on
`npm install`, even if most of it is fine.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterable

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore[assignment]

from github_inventory.config import Config
from github_inventory.discovery import FileTarget
from github_inventory.models import Category, Finding, Severity

# Lifecycle hook keys we care about across ecosystems.
_NPM_HOOK_KEYS = ("postinstall", "preinstall", "install", "prepare", "prepublish",
                  "prepublishOnly", "postpack", "prepack")


class LockfileAnalysisScanner:
    """Parses lockfiles and reports transitive packages with install hooks.

    Not a BaseScanner subclass — it does structural parsing instead of regex,
    and is invoked directly from the engine when ``Config.deep_lockfile`` is
    set.
    """

    name = "lockfile-analysis"

    def __init__(self, config: Config):
        self.config = config

    def analyze(self, repo_root: Path, targets: Iterable[FileTarget]) -> list[Finding]:
        if not getattr(self.config, "deep_lockfile", False):
            return []
        out: list[Finding] = []
        for target in targets:
            name = target.path.name
            try:
                if name == "package-lock.json":
                    out.extend(self._scan_npm_lock(target))
                elif name == "pnpm-lock.yaml":
                    out.extend(self._scan_pnpm_lock(target))
                elif name == "bun.lock":
                    out.extend(self._scan_bun_lock(target))
                elif name == "yarn.lock":
                    out.extend(self._scan_yarn_lock(target))
            except (OSError, json.JSONDecodeError, ValueError):
                continue
        return out

    # ------------------------------------------------------------------
    # Per-format parsers
    # ------------------------------------------------------------------

    def _scan_npm_lock(self, target: FileTarget) -> list[Finding]:
        data = json.loads(target.path.read_text(errors="replace"))
        out: list[Finding] = []
        # npm v7+ has `packages` keyed by node_modules path.
        # Two shapes:
        # - older: `scripts: {postinstall: "...", ...}` inline.
        # - v3+ : just `hasInstallScript: true` (script body fetched on install).
        for pkg_path, meta in (data.get("packages") or {}).items():
            if not isinstance(meta, dict):
                continue
            if not pkg_path:
                continue  # the root project entry; handled by package_scripts.py
            scripts = meta.get("scripts") or {}
            inline_hooks = [k for k in _NPM_HOOK_KEYS if scripts.get(k)]
            has_install = bool(meta.get("hasInstallScript"))
            if not inline_hooks and not has_install:
                continue
            pkg_name = pkg_path.split("node_modules/")[-1] if "node_modules/" in pkg_path else pkg_path
            version = meta.get("version", "?")
            if inline_hooks:
                for hook in inline_hooks:
                    out.append(self._mk_finding(
                        target=target, pkg_name=pkg_name, version=version,
                        hook=hook, cmd=str(scripts[hook])[:200],
                    ))
            else:
                # hasInstallScript flag without inline body
                out.append(self._mk_finding(
                    target=target, pkg_name=pkg_name, version=version,
                    hook="(hasInstallScript)",
                    cmd="install/postinstall hook will run; script body resolved at install",
                ))
        return out

    def _scan_pnpm_lock(self, target: FileTarget) -> list[Finding]:
        if yaml is None:
            return []
        data = yaml.safe_load(target.path.read_text(errors="replace")) or {}
        out: list[Finding] = []
        # pnpm has a top-level `packages:` map keyed by /<name>@<ver>
        for pkg_key, meta in (data.get("packages") or {}).items():
            if not isinstance(meta, dict):
                continue
            # `requiresBuild: true` is pnpm's signal that the package has
            # an install/postinstall script — exact script content isn't
            # stored, so we report the package itself.
            if not meta.get("requiresBuild"):
                continue
            pkg_name, version = _split_pnpm_key(pkg_key)
            out.append(self._mk_finding(
                target=target,
                pkg_name=pkg_name,
                version=version,
                hook="(pnpm requiresBuild)",
                cmd="postinstall/install hook executed during pnpm install",
            ))
        return out

    def _scan_bun_lock(self, target: FileTarget) -> list[Finding]:
        # bun.lock is JSON5-ish: allows trailing commas. Strip them so the
        # standard json module can parse.
        raw = target.path.read_text(errors="replace")
        cleaned = re.sub(r",(\s*[}\]])", r"\1", raw)
        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError:
            return []
        out: list[Finding] = []
        packages = data.get("packages") or {}
        if isinstance(packages, dict):
            for pkg_key, entry in packages.items():
                # Each entry can be an array; check for embedded scripts dict
                if isinstance(entry, list):
                    for item in entry:
                        if isinstance(item, dict) and isinstance(item.get("scripts"), dict):
                            scripts = item["scripts"]
                            hooks_present = [k for k in _NPM_HOOK_KEYS if scripts.get(k)]
                            for hook in hooks_present:
                                pkg_name, version = _split_bun_key(pkg_key)
                                out.append(self._mk_finding(
                                    target=target, pkg_name=pkg_name, version=version,
                                    hook=hook, cmd=str(scripts[hook])[:200],
                                ))
                elif isinstance(entry, dict) and isinstance(entry.get("scripts"), dict):
                    scripts = entry["scripts"]
                    hooks_present = [k for k in _NPM_HOOK_KEYS if scripts.get(k)]
                    for hook in hooks_present:
                        pkg_name, version = _split_bun_key(pkg_key)
                        out.append(self._mk_finding(
                            target=target, pkg_name=pkg_name, version=version,
                            hook=hook, cmd=str(scripts[hook])[:200],
                        ))
        return out

    def _scan_yarn_lock(self, target: FileTarget) -> list[Finding]:
        # yarn.lock is a custom YAML-ish format. It does NOT include scripts
        # metadata (yarn fetches it on install). We can't reliably enumerate
        # postinstall hooks without a registry lookup, so emit nothing here
        # but reserve the file_type for future deep-lookup support.
        return []

    # ------------------------------------------------------------------
    # Finding constructor
    # ------------------------------------------------------------------

    def _mk_finding(self, *, target: FileTarget, pkg_name: str, version: str,
                    hook: str, cmd: str) -> Finding:
        return Finding(
            file_path=target.rel_path,
            line_number=1,
            category=Category.TRANSITIVE_HOOK,
            severity=Severity.LOW,
            pattern_id="transitive-install-hook",
            matched_text=f"{pkg_name}@{version} {hook}: {cmd[:80]}",
            extracted_dep=f"{pkg_name}@{version}",
            description=f"Transitive package {pkg_name}@{version} declares {hook} script (runs on install)",
            scanner_name=self.name,
        )


# ---------- helpers --------------------------------------------------------


_PNPM_KEY_RE = re.compile(r"^/?(?P<name>(?:@[\w.-]+/)?[\w.-]+)@(?P<ver>[\w.+\-]+)")


def _split_pnpm_key(key: str) -> tuple[str, str]:
    m = _PNPM_KEY_RE.match(key)
    if m:
        return m.group("name"), m.group("ver")
    return key, "?"


def _split_bun_key(key: str) -> tuple[str, str]:
    if "@" in key and not key.startswith("@"):
        n, _, v = key.rpartition("@")
        return n, v
    if key.startswith("@") and key.count("@") >= 2:
        # @scope/pkg@version
        idx = key.find("@", 1)
        return key[:idx], key[idx + 1:]
    return key, "?"
