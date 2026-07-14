from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch
import json
from pathlib import Path
import re
from typing import Any, Iterator

from github_inventory.config import Config

# Extensions that are always treated as binary files (Category 7)
BINARY_EXTENSIONS: frozenset[str] = frozenset(
    {".exe", ".dll", ".so", ".dylib", ".wasm", ".bin", ".jar", ".class", ".war", ".ear",
     ".a", ".lib", ".o", ".obj", ".pyc", ".pyo",
     ".woff", ".woff2", ".ttf", ".otf", ".eot"}
)

# Directories to always skip — caches, vendor mirrors, and build artifact
# dirs that would otherwise let us scan transitive dependencies as if they
# were first-party project code (the equivalent of scanning node_modules).
SKIP_DIRS: frozenset[str] = frozenset(
    {
        # VCS and Python tooling
        ".git", "__pycache__", ".venv", "venv", ".tox",
        ".mypy_cache", ".ruff_cache", ".pytest_cache",
        # JS / package managers
        "node_modules",
        # Build outputs
        "dist", "build", "target", ".gradle",
        # PlatformIO transitive lib cache (embedded equivalent of node_modules)
        ".pio",
        # Generic caches
        ".cache",
        # Terraform / Pulumi local state + plugin caches
        ".terraform", ".pulumi",
        # Dart / Flutter
        ".dart_tool",
        # Erlang / Elixir build cache
        "_build", "deps",
        # CocoaPods install cache (Pods/) and Carthage build artifacts
        "Pods", "Carthage",
        # Sphinx / docs build
        "_site",
    }
)

# File classification rules — order matters, first match wins.
# Each entry: (file_type, [glob_patterns])
FILE_RULES: list[tuple[str, list[str]]] = [
    ("ci", [
        ".github/workflows/*.yml",
        ".github/workflows/*.yaml",
        # Support repos nested in subdirectories (e.g. eval corpus, monorepos)
        "**/.github/workflows/*.yml",
        "**/.github/workflows/*.yaml",
        ".gitlab-ci.yml",
        ".gitlab-ci/**/*.yml",
        ".gitlab-ci/**/*.yaml",
        "Jenkinsfile",
        "Jenkinsfile.*",
        ".circleci/config.yml",
        ".circleci/**/*.yml",
        ".travis.yml",
        "cloudbuild.yaml",
        "cloudbuild.yml",
        "buildspec.yml",
        "buildspec.yaml",
        "snapcraft.yaml", "**/snapcraft.yaml",
        "azure-pipelines.yml",
        "azure-pipelines/**/*.yml",
        ".buildkite/**/*.yml",
        ".buildkite/**/*.yaml",
        "bitbucket-pipelines.yml",
        "appveyor.yml",
        "wercker.yml", "wercker.yaml",
        "wercker*.yml", "wercker*.yaml",
        ".drone.yml",
        ".woodpecker.yml",
        ".woodpecker/*.yml",
        # AWS CodeBuild + Google Cloud Build (already had cloudbuild.yaml/buildspec.yml)
        "buildspec-*.yml", "buildspec-*.yaml",
        # Concourse pipelines
        "ci/pipeline*.yml", "ci/pipeline*.yaml",
        ".concourse/*.yml", ".concourse/*.yaml",
        # Argo Workflows
        ".argo/*.yml", ".argo/*.yaml",
        "argo-*.yaml", "argo-*.yml",
        # Tekton tasks/pipelines
        "tekton/*.yaml", "tekton/*.yml",
        ".tekton/*.yaml", ".tekton/*.yml",
        # Dagger
        "dagger.json", "**/dagger.json",
    ]),
    ("github_action", [
        ".github/actions/*/action.yml",
        ".github/actions/*/action.yaml",
        "action.yml",
        "action.yaml",
    ]),
    ("dockerfile", [
        "Dockerfile",
        "Dockerfile.*",
        "*.dockerfile",
        "*.Dockerfile",
        "**/Dockerfile",
        "**/Dockerfile.*",
        "**/*.dockerfile",
        "**/*.Dockerfile",
        "docker-compose*.yml",
        "docker-compose*.yaml",
        "**/docker-compose*.yml",
        "**/docker-compose*.yaml",
        "Containerfile",
        "**/Containerfile",
        "Earthfile",
        "**/Earthfile",
    ]),
    ("winget_manifest", [
        "**/*.installer.yaml",
        "**/*.installer.yml",
    ]),
    ("k8s", [
        "k8s/**/*.yml", "k8s/**/*.yaml",
        "kubernetes/**/*.yml", "kubernetes/**/*.yaml",
        "deploy/**/*.yml", "deploy/**/*.yaml",
        "helm/**/*.yml", "helm/**/*.yaml",
        "charts/**/*.yml", "charts/**/*.yaml",
        "**/Chart.yaml",
        "**/values.yaml", "**/values.*.yaml", "**/values-*.yaml",
        "**/kustomization.yaml", "**/kustomization.yml",
        "skaffold.yaml", "skaffold.yml",
        # Common Kubernetes manifest filenames in any directory
        "**/deployment.yaml", "**/deployment.yml",
        "**/deployment-*.yaml", "**/deployment-*.yml",
        "**/*-deployment.yaml", "**/*-deployment.yml",
    ]),
    ("iac", [
        "**/*.tf",
        "terraform/**/*.yml", "terraform/**/*.yaml",
        "infra/**/*.yml", "infra/**/*.yaml",
    ]),
    ("build", [
        "Makefile", "makefile", "GNUmakefile",
        "Makefile.*",
        "**/pom.xml",
        "build.gradle", "build.gradle.kts",
        "settings.gradle", "settings.gradle.kts",
        "**/build.gradle", "**/build.gradle.kts",
        "CMakeLists.txt", "**/CMakeLists.txt",
        "Rakefile", "**/Rakefile",
        "Taskfile.yml", "Taskfile.yaml",
        "meson.build",
        "WORKSPACE", "WORKSPACE.bazel", "MODULE.bazel",
        "**/*.bzl",
        "justfile", "**/justfile",
        # Buck / Buck2 / Pants
        "BUCK", "**/BUCK",
        "BUCK.bzl", "**/BUCK.bzl",
        "BUILD", "**/BUILD",
        "BUILD.bazel", "**/BUILD.bazel",
        "BUILD.pants", "**/BUILD.pants",
        # Mage / xtask Rust
        "magefile.go", "**/magefile.go",
    ]),
    ("build_wrapper", [
        "gradle/wrapper/gradle-wrapper.properties",
        "**/gradle/wrapper/gradle-wrapper.properties",
        ".mvn/wrapper/maven-wrapper.properties",
        "**/.mvn/wrapper/maven-wrapper.properties",
    ]),
    ("script", [
        "**/*.sh", "**/*.bash", "**/*.zsh",
        "**/*.ps1", "**/*.bat", "**/*.cmd",
        "install.sh", "setup.sh", "bootstrap.sh", "deploy.sh",
        ".husky/*",
        "**/.husky/*",
    ]),
    ("package_config", [
        "**/package.json",
        "**/setup.py",
        "**/setup.cfg",
        "**/pyproject.toml",
        "**/Cargo.toml",
        "**/go.mod",
        "**/Gemfile",
        "**/Podfile",
        "**/Package.swift",
        "**/composer.json",
    ]),
    ("pip_config", [
        "requirements*.txt",
        "**/requirements*.txt",
        "constraints*.txt",
        "**/constraints*.txt",
    ]),
    ("precommit_config", [
        ".pre-commit-config.yaml",
        "**/.pre-commit-config.yaml",
    ]),
    ("devcontainer", [
        ".devcontainer/devcontainer.json",
        ".devcontainer.json",
        "**/.devcontainer/devcontainer.json",
    ]),
    ("toolversions", [
        ".tool-versions",
        "**/.tool-versions",
        ".mise.toml",
        "**/mise.toml",
        "**/.mise.toml",
    ]),
    ("gitmodules", [
        ".gitmodules",
    ]),
    ("nix", [
        "**/*.nix",
        "flake.nix",
    ]),
    ("npmrc", [
        ".npmrc", "**/.npmrc",
        ".yarnrc.yml", "**/.yarnrc.yml",
    ]),
    ("pip_conf", [
        "pip.conf", "**/pip.conf", ".pip/pip.conf",
        "pip.ini", "**/pip.ini",
    ]),
    ("nuget_config", [
        "nuget.config", "**/nuget.config",
        "NuGet.Config", "**/NuGet.Config",
        "NuGet.config", "**/NuGet.config",
    ]),
    ("web_asset", [
        "**/*.html", "**/*.htm", "**/*.css",
    ]),
    ("pubspec", [
        "pubspec.yaml", "**/pubspec.yaml",
    ]),
    ("cartfile", [
        "Cartfile", "**/Cartfile",
    ]),
    ("podspec", [
        "*.podspec", "**/*.podspec",
    ]),
    ("conanfile", [
        "conanfile.txt", "**/conanfile.txt",
        "conanfile.py", "**/conanfile.py",
    ]),
    ("vcpkg_config", [
        "vcpkg.json", "**/vcpkg.json",
        "vcpkg-configuration.json", "**/vcpkg-configuration.json",
    ]),
    ("meson_wrap", [
        "subprojects/*.wrap", "**/subprojects/*.wrap",
    ]),
    ("sbt_build", [
        "build.sbt", "**/build.sbt",
        "project/plugins.sbt", "**/project/plugins.sbt",
        "project/*.scala",
    ]),
    ("mix_config", [
        "mix.exs", "**/mix.exs",
    ]),
    ("rebar_config", [
        "rebar.config", "**/rebar.config",
    ]),
    ("mcp_config", [
        ".mcp.json", "**/.mcp.json",
        "mcp.json", "**/mcp.json",
        ".mcp/*.json", "**/.mcp/*.json",
        ".cursor/mcp.json", "**/.cursor/mcp.json",
        ".vscode/mcp.json", "**/.vscode/mcp.json",
    ]),
    ("agent_plugin", [
        ".claude-plugin/plugin.json", "**/.claude-plugin/plugin.json",
        ".claude-plugin/marketplace.json", "**/.claude-plugin/marketplace.json",
        ".codex-plugin/plugin.json", "**/.codex-plugin/plugin.json",
        ".codex-plugin/marketplace.json", "**/.codex-plugin/marketplace.json",
        ".cursor-plugin/plugin.json", "**/.cursor-plugin/plugin.json",
        ".cursor-plugin/marketplace.json", "**/.cursor-plugin/marketplace.json",
        ".copilot-plugin/plugin.json", "**/.copilot-plugin/plugin.json",
        ".copilot-plugin/marketplace.json", "**/.copilot-plugin/marketplace.json",
    ]),
    ("agent_instruction", [
        "AGENTS.md", "**/AGENTS.md",
        "CLAUDE.md", "**/CLAUDE.md",
        "CODEX.md", "**/CODEX.md",
        "SKILL.md", "**/SKILL.md",
        ".agents/**/*.md", "**/.agents/**/*.md",
        ".claude/**/*.md", "**/.claude/**/*.md",
        ".codex/**/*.md", "**/.codex/**/*.md",
        ".cursor/**/*.md", "**/.cursor/**/*.md",
    ]),
    ("lockfile", [
        "package-lock.json", "**/package-lock.json",
        "pnpm-lock.yaml", "**/pnpm-lock.yaml",
        "bun.lock", "**/bun.lock",
        "yarn.lock", "**/yarn.lock",
    ]),
    ("homebrew_formula", [
        "Formula/*.rb",
        "**/Formula/*.rb",
    ]),
    ("scoop_manifest", [
        "bucket/*.json",
        "**/bucket/*.json",
    ]),
    ("idf_component", [
        "idf_component.yml", "**/idf_component.yml",
        "idf_component.yaml", "**/idf_component.yaml",
    ]),
    ("system_packages", [
        "Brewfile", "**/Brewfile",
        "Aptfile", "**/Aptfile",
        "apt-packages", "**/apt-packages",
        ".apt-packages", "**/.apt-packages",
    ]),
    ("source_code", [
        "**/*.js", "**/*.mjs", "**/*.cjs",
        "**/*.ts", "**/*.mts",
        "**/*.jsx", "**/*.tsx",
        "**/*.py",
    ]),
]

AGENT_SOURCE_HINT_RE = re.compile(
    r"(?:^|[/_-])(?:agent|agents|mcp|skills?)(?:[/_.-]|$)",
    re.IGNORECASE,
)
CONTENT_CLASSIFY_MAX_SIZE = 2 * 1024 * 1024

_MARKDOWN_DOC_EXTENSIONS = {".md", ".mdx"}
_AGENT_DOC_PATH_RE = re.compile(
    r"(?:^|[/_-])(?:agent|agents|mcp|skills?|claude|codex|openclaw|llms?|modelcontextprotocol)"
    r"(?:[/_.-]|$)",
    re.IGNORECASE,
)
_AGENT_DOC_CONTENT_RE = re.compile(
    r"(?:\bmcpServers\b|Model Context Protocol|\bOpenCLAW\b|\ballowed-tools\b|"
    r"\bClaude Code\b|\bCodex\b|\bnpx\s+skills\s+add\b|\bllms\.txt\b)",
    re.IGNORECASE,
)
_MCP_JSON_RE = re.compile(r'"mcpServers"\s*:', re.IGNORECASE)
_SCOOP_JSON_RE = re.compile(r'"architecture"\s*:|"bin"\s*:|"hash"\s*:', re.IGNORECASE)
_SCOOP_URL_RE = re.compile(
    r'"url"\s*:\s*(?:\[[^\]]*https?://|"https?://)',
    re.IGNORECASE | re.DOTALL,
)
_HOMEBREW_FORMULA_RE = re.compile(
    r"<\s*Formula\b|^\s*url\s+['\"]https?://",
    re.IGNORECASE | re.MULTILINE,
)
_WINGET_MANIFEST_RE = re.compile(r"^\s*(?:PackageIdentifier|InstallerUrl)\s*:", re.MULTILINE)
_GO_SOURCE_COMMAND_HINT_RE = re.compile(
    r"\b(?:npx\s+skills\s+add|npm\s+(?:install|i)\s+(?:-g|--global)|"
    r"brew\s+install|pip3?\s+install|mcpServers|Model Context Protocol)\b",
    re.IGNORECASE,
)


@dataclass
class FileTarget:
    path: Path
    rel_path: str
    file_type: str


_MAX_SHEBANG_SIZE = 1024 * 1024  # 1 MB cap — don't sniff huge binaries


def _classify_by_shebang(path: Path) -> str | None:
    """Classify extensionless executables by their `#!` line.

    Catches things like `./verify`, `./bootstrap`, `./run` — bash/python/node
    scripts that real projects commit without an extension. Only reads the
    first 80 bytes and only on files under 1 MB.
    """
    try:
        size = path.stat().st_size
        if size == 0 or size > _MAX_SHEBANG_SIZE:
            return None
        with open(path, "rb") as f:
            first = f.read(80)
    except OSError:
        return None
    if not first.startswith(b"#!"):
        return None
    line = first.split(b"\n", 1)[0].lower()
    # Order matters: check python/node first because their paths may also
    # contain 'sh' (e.g. /usr/bin/python3 could be in a 'sharness' test env).
    if b"python" in line:
        return "source_code"
    if b"node" in line or b"deno" in line or b"bun" in line:
        return "source_code"
    if b"ruby" in line or b"perl" in line:
        return "source_code"
    if (
        b"/env sh" in line or b"/bin/sh" in line or b"bash" in line
        or b"zsh" in line or b"dash" in line
    ):
        return "script"
    return None


def _glob_match(rel_path: str, name: str, pattern: str) -> bool:
    """Match a path against a glob, with `**/X` semantics that include root.

    Python's `fnmatch` on POSIX treats `**` the same as `*` (single segment),
    so `fnmatch("package.json", "**/package.json")` is False. That silently
    disables every `**/X` rule for root-level files. Treat `**/X` as
    "X anywhere, including the repo root".
    """
    if fnmatch(rel_path, pattern) or fnmatch(name, pattern):
        return True
    if pattern.startswith("**/"):
        rest = pattern[3:]
        if fnmatch(rel_path, rest) or fnmatch(name, rest):
            return True
    return False


class FileDiscovery:
    def __init__(self, repo_root: Path, config: Config):
        self.repo_root = repo_root.resolve()
        self.config = config

    def discover(self) -> Iterator[FileTarget]:
        """Yield all text-based files to scan."""
        for path in self._walk():
            if path.suffix.lower() in BINARY_EXTENSIONS:
                continue
            rel = str(path.relative_to(self.repo_root))
            if self.config.is_path_excluded(rel):
                continue
            file_type = self._classify(rel, path)
            if file_type:
                yield FileTarget(path=path, rel_path=rel, file_type=file_type)

    def discover_binaries(self) -> Iterator[FileTarget]:
        """Separate pass: yield vendored binary files by extension."""
        for path in self._walk():
            if path.suffix.lower() not in BINARY_EXTENSIONS:
                continue
            rel = str(path.relative_to(self.repo_root))
            if self.config.is_path_excluded(rel):
                continue
            yield FileTarget(path=path, rel_path=rel, file_type="binary")

    def _classify(self, rel_path: str, path: Path) -> str | None:
        for file_type, patterns in FILE_RULES:
            for pattern in patterns:
                if _glob_match(rel_path, path.name, pattern):
                    return file_type
        # Go source is too broad to scan globally (large repos often vendor
        # thousands of .go files). Include it only when the repo or path is
        # clearly agent/MCP/skill-related so generated install instructions in
        # MCP servers are visible without flooding results from vendor trees.
        if path.suffix.lower() == ".go" and AGENT_SOURCE_HINT_RE.search(
            f"{self.repo_root.name}/{rel_path}"
        ):
            return "source_code"
        content_type = _classify_by_content(rel_path, path, self.repo_root.name)
        if content_type:
            return content_type
        # Last fallback: shebang sniff. Catches extensionless executables
        # (e.g. `verify`, `bootstrap`, `run`) that real projects use for
        # install/dev tooling. Only reads the first 80 bytes.
        return _classify_by_shebang(path)

    def _walk(self) -> Iterator[Path]:
        repo_root_resolved = self.repo_root.resolve()
        for item in self.repo_root.rglob("*"):
            if not item.is_file():
                continue
            # Skip symlinks whose target escapes the repo root: a cloned repo can
            # commit `creds -> /etc/passwd`, and is_file() follows symlinks, so we
            # would otherwise read host files and leak them into findings.
            if item.is_symlink() and not item.resolve().is_relative_to(repo_root_resolved):
                continue
            # Skip if any path component is in SKIP_DIRS
            if any(part in SKIP_DIRS for part in item.parts):
                continue
            yield item


def _classify_by_content(rel_path: str, path: Path, repo_name: str) -> str | None:
    suffix = path.suffix.lower()
    if suffix not in {".json", ".rb", ".yaml", ".yml", ".go"} | _MARKDOWN_DOC_EXTENSIONS:
        return None

    content = _read_small_text(path)
    if content is None:
        return None

    if suffix == ".json":
        # Localization bundles often contain translated strings for MCP-related
        # settings such as "mcpServers" and "command", but they are inert data,
        # not executable MCP client configuration.
        if rel_path.lower().endswith(".i18n.json"):
            return None
        if _MCP_JSON_RE.search(content):
            return "mcp_config"
        if _looks_like_scoop_manifest(content):
            return "scoop_manifest"
        return None

    if suffix == ".rb":
        repo_rel = f"{repo_name}/{rel_path}".lower()
        if (
            _HOMEBREW_FORMULA_RE.search(content)
            and ("homebrew" in repo_rel or "/formula/" in repo_rel or "< formula" in content.lower())
        ):
            return "homebrew_formula"
        return None

    if suffix in {".yaml", ".yml"}:
        if _WINGET_MANIFEST_RE.search(content):
            return "winget_manifest"
        return None

    if suffix == ".go":
        if _GO_SOURCE_COMMAND_HINT_RE.search(content):
            return "source_code"
        return None

    if suffix in _MARKDOWN_DOC_EXTENSIONS and _is_targeted_markdown_doc(rel_path, content):
        return "agent_instruction"

    return None


def _read_small_text(path: Path) -> str | None:
    try:
        size = path.stat().st_size
        if size == 0 or size > CONTENT_CLASSIFY_MAX_SIZE:
            return None
        return path.read_text(errors="replace")
    except OSError:
        return None


def _looks_like_scoop_manifest(content: str) -> bool:
    if not (_SCOOP_URL_RE.search(content) and _SCOOP_JSON_RE.search(content)):
        return False
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return False
    if not isinstance(data, dict):
        return False
    version = data.get("version")
    if not isinstance(version, (str, int, float)):
        return False
    if _looks_like_scoop_download_section(data):
        return True
    architecture = data.get("architecture")
    if not isinstance(architecture, dict):
        return False
    return any(
        _looks_like_scoop_download_section(section)
        for section in architecture.values()
        if isinstance(section, dict)
    )


def _looks_like_scoop_download_section(section: dict[str, Any]) -> bool:
    if not _json_value_has_http_url(section.get("url")):
        return False
    return "hash" in section or any(
        key in section
        for key in (
            "bin",
            "shortcuts",
            "extract_dir",
            "extract_to",
            "installer",
            "pre_install",
            "post_install",
        )
    )


def _json_value_has_http_url(value: Any) -> bool:
    if isinstance(value, str):
        return value.startswith(("http://", "https://"))
    if isinstance(value, list):
        return any(_json_value_has_http_url(item) for item in value)
    return False


def _is_targeted_markdown_doc(rel_path: str, content: str) -> bool:
    rel_lower = rel_path.lower()
    if "/vendor/" in f"/{rel_lower}":
        return False
    if _is_documentation_tree_path(rel_lower):
        return False
    if _AGENT_DOC_PATH_RE.search(rel_path) or _AGENT_DOC_CONTENT_RE.search(content):
        return True
    return False


def _is_documentation_tree_path(rel_lower: str) -> bool:
    normalized = f"/{rel_lower}"
    return any(
        marker in normalized
        for marker in (
            "/docs/",
            "/doc/",
            "/documentation/",
            "/blog/",
            "/blogs/",
            "/content/blog/",
            "/src/content/docs/",
            "/src/content/blog/",
            "/src/frontend/src/content/docs/",
            "/website/blog/",
        )
    )
