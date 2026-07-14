"""Category 3: npm -g, npx, pip URL, go install, cargo install, brew, apt, gem, and more."""
from __future__ import annotations

import json
from pathlib import Path
import re

from github_inventory.discovery import FileTarget
from github_inventory.models import Category, Finding, Severity
from github_inventory.scanners.base import BaseScanner, PatternRule
from github_inventory.scanners.source_shell import iter_javascript_shell_commands, iter_python_shell_commands

_CI_SCRIPT = ["ci", "script", "build", "github_action"]
_CI_SCRIPT_DOCKER = ["ci", "script", "build", "dockerfile", "github_action"]
_AGENT_INSTRUCTION = ["agent_instruction"]
_DEVCONTAINER = ["devcontainer"]
_UNMANAGED_SCRIPTABLE = ["ci", "script", "build", "dockerfile", "github_action", "agent_instruction"]
_SHELL_SUBSTITUTION_TOKEN = r"\$\([^)\n]*\)"
_APT_REPO_COMMAND_SUB_URL_TOKEN = r"https?://(?:(?:" + _SHELL_SUBSTITUTION_TOKEN + r")|[^'\"\s)])+"
_AZURE_CLI_EXTENSION_COMMAND_RE = r"\b(?:Invoke-Az|az)\s+extension\s+add\b"
_GITHUB_CLI_EXTENSION_COMMAND_RE = r"\bgh\s+extension\s+(?:install|upgrade)\b"
_VSCODE_EXTENSION_INSTALL_COMMAND_RE = r"\b(?:code|code-insiders)(?:\.cmd|\.exe)?\s+--install-extension\b"
_KREW_PLUGIN_INSTALL_COMMAND_RE = r"\b(?:kubectl\s+)?krew\s+install\b"
_CONDA_CUSTOM_CHANNEL_COMMAND_RE = re.compile(
    r"(?<![$\w.-])"
    r"(?:conda|mamba|micromamba|"
    r"\$\{?(?:(?:[A-Za-z_][A-Za-z0-9_]*)_)?(?:CONDA|MAMBA|MICROMAMBA)[A-Za-z0-9_]*\}?)"
    r"\s+(?:install|create)\b",
    re.IGNORECASE,
)
_SYSTEM_PACKAGE_COMMAND_RE = (
    r"\b(?:(?:apt-get|apt|yum|dnf|tdnf|apk)\b\s+"
    r"(?:(?:--[\w-]+(?:=(?:\$\{\{.*?\}\}|[^\s]+))?|-{1,2}[A-Za-z]+)\s+)*"
    r"(?:install|add)|zypper\b\s+"
    r"(?:(?:--[\w-]+(?:=(?:\$\{\{.*?\}\}|[^\s]+))?|-{1,2}[A-Za-z]+)\s+)*"
    r"(?:install|in))"
)
_KNOWN_BIN_PACKAGES = {
    "changeset": {"@changesets/cli"},
    "playwright": {"playwright", "@playwright/test"},
    "tsc": {"typescript"},
    "tsserver": {"typescript"},
    "tsp": {"@typespec/compiler"},
    "vsce": {"@vscode/vsce"},
}
_UV_TOOL_PROSE_DEPS = {"or", "and", "to", "for", "with", "from", "the", "a", "an"}
_PRINTED_INSTALL_HINT_PATTERNS = {
    "pip-install-url": re.compile(r"\bpip3?\s+install\b", re.IGNORECASE),
    "pip-install-ci": re.compile(r"\bpip3?\s+install\b", re.IGNORECASE),
    "pip-custom-index": re.compile(r"\bpip3?\s+install\b", re.IGNORECASE),
    "npm-global-install": re.compile(r"\bnpm\s+(?:install|i)\b[^\n]*(?:-g|--global)\b", re.IGNORECASE),
    "npm-global-install-flag-after": re.compile(r"\bnpm\s+(?:install|i)\b[^\n]*(?:-g|--global)\b", re.IGNORECASE),
    "npm-create": re.compile(r"\bnpm\s+create\b", re.IGNORECASE),
    "npm-exec-package": re.compile(r"\bnpm\s+(?:exec|x)\b", re.IGNORECASE),
    "pnpx-execution": re.compile(r"\bpnpx\b", re.IGNORECASE),
    "rustup-target-add": re.compile(r"\brustup\s+target\s+add\b", re.IGNORECASE),
    "rustup-component-add": re.compile(r"\brustup\s+component\s+add\b", re.IGNORECASE),
    "rustup-toolchain-install": re.compile(r"\brustup\s+(?:toolchain\s+)?install\b", re.IGNORECASE),
    "rustup-toolchain-update": re.compile(r"\brustup\s+update\b", re.IGNORECASE),
    "rustup-toolchain-default": re.compile(r"\brustup\s+default\b", re.IGNORECASE),
    "uv-python-install": re.compile(r"\buv\s+python\s+install\b", re.IGNORECASE),
    "pyenv-install": re.compile(r"\bpyenv\s+install\b", re.IGNORECASE),
    "tfenv-install": re.compile(r"\btfenv\s+install\b", re.IGNORECASE),
    "nvm-install": re.compile(r"\bnvm\s+install\b", re.IGNORECASE),
    "fnm-install": re.compile(r"\bfnm\s+install\b", re.IGNORECASE),
    "powershell-install-package-provider": re.compile(r"\bInstall-PackageProvider\b", re.IGNORECASE),
    "powershell-install-package": re.compile(r"\bInstall-Package\b", re.IGNORECASE),
    "dotnet-workload-install": re.compile(r"\bdotnet\s+workload\s+install\b", re.IGNORECASE),
    "dotnet-workload-update": re.compile(r"\bdotnet\s+workload\s+update\b", re.IGNORECASE),
    "dotnet-workload-restore": re.compile(r"\bdotnet\s+workload\s+restore\b", re.IGNORECASE),
    "brew-tap-ci": re.compile(r"\bbrew\s+tap\b", re.IGNORECASE),
    "brew-install-ci": re.compile(r"\bbrew\s+install\b", re.IGNORECASE),
    "corepack-install": re.compile(r"\bcorepack\s+install\b", re.IGNORECASE),
    "corepack-prepare": re.compile(r"\bcorepack\s+prepare\b", re.IGNORECASE),
    "system-package-install": re.compile(_SYSTEM_PACKAGE_COMMAND_RE, re.IGNORECASE),
    "winget-command-install": re.compile(r"\bwinget\s+install\b", re.IGNORECASE),
    "choco-install": re.compile(r"\bchoco(?:latey)?\s+install\b", re.IGNORECASE),
    "scoop-install": re.compile(r"\bscoop\s+install\b", re.IGNORECASE),
    "azure-cli-extension-install": re.compile(_AZURE_CLI_EXTENSION_COMMAND_RE, re.IGNORECASE),
    "azure-cli-bicep-install": re.compile(r"\baz\s+bicep\s+(?:install|upgrade)\b", re.IGNORECASE),
    "azure-cli-aks-install-cli": re.compile(r"\baz\s+aks\s+install-cli\b", re.IGNORECASE),
    "github-cli-extension-install": re.compile(_GITHUB_CLI_EXTENSION_COMMAND_RE, re.IGNORECASE),
    "vscode-extension-install": re.compile(_VSCODE_EXTENSION_INSTALL_COMMAND_RE, re.IGNORECASE),
    "krew-plugin-install": re.compile(_KREW_PLUGIN_INSTALL_COMMAND_RE, re.IGNORECASE),
    "helm-repo-add": re.compile(r"\bhelm\s+repo\s+add\b", re.IGNORECASE),
    "helm-chart-pull": re.compile(r"\bhelm\s+(?:chart\s+)?pull\b", re.IGNORECASE),
    "helm-plugin-install": re.compile(r"\bhelm\s+plugin\s+(?:install|add)\b", re.IGNORECASE),
    "conda-custom-channel": _CONDA_CUSTOM_CHANNEL_COMMAND_RE,
}
_MARKDOWN_DOC_EXTENSIONS = frozenset({".md", ".mdx"})
_AGENT_CONTROL_DOC_NAMES = frozenset({"AGENTS.md", "CLAUDE.md", "CODEX.md", "SKILL.md"})
_AGENT_CONTROL_DOC_DIRS = frozenset({".agents", ".claude", ".codex", ".cursor"})
_UNMANAGED_MARKDOWN_COMMAND_RE = re.compile(
    r"\b(?:"
    r"(?:python3?\s+-m\s+)?pip3?\s+install"
    r"|uv\s+(?:pip\s+install|tool\s+(?:install|run)|python\s+install|add)"
    r"|uvx"
    r"|npx"
    r"|pnpx"
    r"|npm\s+(?:install|i)"
    r"|npm\s+create"
    r"|npm\s+(?:exec|x)"
    r"|pnpm\s+dlx"
    r"|pnpm\s+add"
    r"|yarn\s+dlx"
    r"|yarn\s+add"
    r"|corepack\s+(?:install|prepare)"
    r"|(?:apt-get|apt|yum|dnf|tdnf|apk)\s+(?:install|add)"
    r"|zypper\s+(?:install|in)"
    r"|brew\s+install"
    r"|brew\s+tap"
    r"|winget\s+install"
    r"|choco(?:latey)?\s+install"
    r"|scoop\s+install"
    r"|(?:Invoke-Az|az)\s+extension\s+add"
    r"|az\s+(?:bicep\s+(?:install|upgrade)|aks\s+install-cli)"
    r"|gh\s+extension\s+(?:install|upgrade)"
    r"|(?:code|code-insiders)(?:\.cmd|\.exe)?\s+--install-extension"
    r"|(?:kubectl\s+)?krew\s+install"
    r"|helm\s+(?:repo\s+add|(?:chart\s+)?pull|plugin\s+(?:install|add))"
    r"|pipx\s+(?:install|run)"
    r"|go\s+install"
    r"|go\s+run"
    r"|cargo\s+(?:install|binstall)"
    r"|rustup\s+(?:(?:target|component)\s+add|(?:toolchain\s+)?install|update|default)"
    r"|(?:pyenv|tfenv|nvm|fnm)\s+install"
    r"|dotnet\s+(?:tool\s+(?:install|update)|new\s+install|workload\s+(?:install|update|restore))"
    r"|(?:Install|Save)-(?:Module|PSResource)"
    r"|Install-Package(?:Provider)?"
    r"|(?:conda|mamba|micromamba)\s+(?:install|create)"
    r"|add-apt-repository"
    r")\b",
    re.IGNORECASE,
)


class UnmanagedPackageScanner(BaseScanner):
    name = "unmanaged-packages"

    def scan_file_content(self, target: FileTarget, content: str, lines: list[str]) -> list[Finding]:
        findings = super().scan_file_content(target, content, lines)
        findings.extend(_scan_agent_instruction_comment_installers(target, lines, findings))
        findings = _normalize_npm_global_findings(findings)
        findings = _normalize_system_package_findings(target, lines, findings)
        findings = _normalize_go_install_findings(target, lines, findings)
        findings = _normalize_apt_sources_list_findings(lines, findings)
        findings = [
            f for f in findings
            if not _is_non_executable_metadata_or_list_item(target, f, lines)
        ]
        findings.extend(_expand_npx_package_executions(target, lines, findings))
        findings.extend(_expand_npm_exec_package_executions(target, lines, findings))
        findings.extend(_expand_rustup_additions(target, lines, findings))
        findings.extend(_scan_version_manager_installs(target, lines, findings))
        findings.extend(_expand_multi_package_installs(target, lines, findings))
        findings.extend(_scan_uvx_executions(target, lines, findings))
        findings.extend(_scan_pip_custom_indexes(target, lines, findings))
        findings.extend(_scan_conda_custom_channels(target, lines, findings))
        findings.extend(_scan_go_run_remote_modules(target, lines, findings))
        findings.extend(_expand_corepack_prepare(target, lines, findings))
        findings.extend(_scan_dynamic_nuget_restores(target, content, lines, findings))
        findings.extend(_scan_resolved_nuget_installs(target, lines, findings))
        findings.extend(_scan_dotnet_tool_installs(target, lines, findings))
        findings.extend(_scan_dotnet_workloads(target, lines, findings))
        findings.extend(_scan_r_install_lines(target, lines, findings))
        findings.extend(_scan_julia_pkg_add_lines(target, lines, findings))
        findings.extend(_scan_python_shell_system_package_installs(target, content, lines, findings))
        findings.extend(_scan_python_shell_azure_cli_extensions(target, content, lines, findings))
        findings.extend(_scan_python_shell_pip_installs(target, content, lines, findings))
        findings.extend(_scan_javascript_shell_package_runners(target, content, lines, findings))
        findings.extend(_scan_resolved_azure_cli_extensions(target, lines, findings))
        findings.extend(_scan_resolved_vscode_extensions(target, lines, findings))
        findings.extend(_scan_powershell_install_modules(target, lines, findings))
        findings.extend(_scan_powershell_package_management(target, lines, findings))
        findings.extend(_scan_helm_remote_artifacts(target, lines, findings))
        findings = _normalize_winget_install_findings(target, lines, findings)
        findings = _suppress_local_npx_findings(target, content, lines, findings)
        findings = [
            f for f in findings
            if not _is_non_executable_metadata_or_list_item(target, f, lines)
        ]
        return _dedupe_findings(findings)

    def register_rules(self) -> None:
        # --- JavaScript ecosystem ---

        # npm install -g <pkg> (flag before package). Allow shell variables
        # ($PKG, ${PKG}) so variable-substituted installs are still flagged.
        self.add_rule(PatternRule(
            pattern_id="npm-global-install",
            regex=re.compile(
                r"\bnpm\s+(?:install|i)\s+(?:-g|--global)\s+"
                r"(?P<dep>(?:\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|[\w@/.-]+)"
                r"(?:\s+(?:\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|[\w@/.-]+))*)",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="Global npm package installed outside manifest: {dep}",
            category=Category.UNMANAGED_PACKAGE,
            file_types=_CI_SCRIPT_DOCKER + _AGENT_INSTRUCTION + _DEVCONTAINER,
            escalate_when=[
                (re.compile(r"@(?:latest|alpha|beta|next|canary|nightly|edge)\b", re.IGNORECASE), Severity.CRITICAL),
            ],
        ))

        # npm install <pkg> -g (flag after package)
        self.add_rule(PatternRule(
            pattern_id="npm-global-install-flag-after",
            regex=re.compile(
                r"\bnpm\s+(?:install|i)\s+(?P<dep>[\w@/.-]+(?:\s+[\w@/.-]+)*)\s+(?:-g|--global)",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="Global npm package installed outside manifest: {dep}",
            category=Category.UNMANAGED_PACKAGE,
            file_types=_CI_SCRIPT_DOCKER + _AGENT_INSTRUCTION + _DEVCONTAINER,
            escalate_when=[
                (re.compile(r"@(?:latest|alpha|beta|next|canary|nightly|edge)\b", re.IGNORECASE), Severity.CRITICAL),
            ],
        ))

        # npm install <pkg> in Dockerfile/CI context. This excludes bare
        # `npm install`/`npm ci`, which install from committed manifests, and
        # excludes local path installs like `npm install .`.
        self.add_rule(PatternRule(
            pattern_id="npm-direct-install",
            regex=re.compile(
                r"\bnpm\s+(?:install|i)\s+"
                r"(?!-g\b|--global\b|&&|;|$|\.{1,2}(?:\s|$))"
                r"(?![^\n;&|]*(?:\s(?:-g|--global)\b))"
                r"(?:-{1,2}[\w-]+(?:[= ](?!-)\S+)?\s+)*"
                r"(?P<dep>(?!-)(?:@[\w.-]+/)?[\w][\w./-]*(?:@[\w.+\-]+)?)",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="npm installs package directly in CI/Dockerfile: {dep}",
            category=Category.UNMANAGED_PACKAGE,
            file_types=["ci", "dockerfile", "github_action", "agent_instruction"],
            escalate_when=[
                (re.compile(r"@(?:latest|alpha|beta|next|canary|nightly|edge)\b", re.IGNORECASE), Severity.CRITICAL),
            ],
        ))

        self.add_rule(PatternRule(
            pattern_id="yarn-global-add",
            regex=re.compile(
                r"\byarn\s+global\s+add\s+(?P<dep>[\w@/.-]+(?:\s+[\w@/.-]+)*)",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="Global yarn package installed outside manifest: {dep}",
            category=Category.UNMANAGED_PACKAGE,
            file_types=_CI_SCRIPT + _AGENT_INSTRUCTION,
        ))

        # npx <pkg>. Capture an optional @version suffix so escalate_when can
        # bump severity for explicit @latest / @alpha / @next.
        self.add_rule(PatternRule(
            pattern_id="npx-execution",
            regex=re.compile(
                r"(?<![$\w.-])(?!(?-i:NPX\s+CLI\b))npx\b\s+"
                r"(?:--yes\s+|-y\s+|--no-install\s+)?"
                r"(?P<dep>(?:@[\w-]+/)?[\w][\w.-]*(?:@[\w.+\-]+)?)",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="npx executes package on-demand (shadow download): {dep}",
            category=Category.UNMANAGED_PACKAGE,
            file_types=_CI_SCRIPT_DOCKER + ["package_config"] + _AGENT_INSTRUCTION,
            escalate_when=[
                (re.compile(r"@(?:latest|alpha|beta|next|canary|nightly|edge)\b", re.IGNORECASE), Severity.CRITICAL),
            ],
        ))

        self.add_rule(PatternRule(
            pattern_id="npx-package-execution",
            regex=re.compile(
                r"(?<![$\w.-])npx\b\s+(?:--yes\s+|-y\s+|--no-install\s+)*"
                r"(?:--package(?:=|\s+)|-p\s+)"
                r"(?P<dep>(?:@[\w.-]+/)?[\w][\w.-]*(?:@[\w.+\-]+)?)",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="npx installs package via --package option: {dep}",
            category=Category.UNMANAGED_PACKAGE,
            file_types=_CI_SCRIPT_DOCKER + _AGENT_INSTRUCTION,
            escalate_when=[
                (re.compile(r"@(?:latest|alpha|beta|next|canary|nightly|edge)\b", re.IGNORECASE), Severity.CRITICAL),
            ],
        ))

        self.add_rule(PatternRule(
            pattern_id="npm-create",
            regex=re.compile(
                r"(?<![$\w.-])npm\s+create\s+"
                r"(?P<dep>(?:@[\w.-]+/)?[\w][\w.-]*(?:@[\w.+\-]+)?)",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="npm create executes initializer package on-demand: {dep}",
            category=Category.UNMANAGED_PACKAGE,
            file_types=_CI_SCRIPT_DOCKER + _AGENT_INSTRUCTION,
            escalate_when=[
                (re.compile(r"@(?:latest|alpha|beta|next|canary|nightly|edge)\b", re.IGNORECASE), Severity.CRITICAL),
            ],
        ))

        self.add_rule(PatternRule(
            pattern_id="pnpm-dlx",
            regex=re.compile(
                r"\bpnpm\s+dlx\s+(?P<dep>(?:@[\w-]+/)?[\w][\w.-]*(?:@[\w.+\-]+)?)",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="pnpm dlx executes package on-demand: {dep}",
            category=Category.UNMANAGED_PACKAGE,
            file_types=_CI_SCRIPT_DOCKER + ["package_config"] + _AGENT_INSTRUCTION,
            escalate_when=[
                (re.compile(r"@(?:latest|alpha|beta|next|canary|nightly|edge)\b", re.IGNORECASE), Severity.CRITICAL),
            ],
        ))

        self.add_rule(PatternRule(
            pattern_id="pnpx-execution",
            regex=re.compile(
                r"(?<![$\w.-])pnpx\b\s+"
                r"(?:--yes\s+|-y\s+|--no-install\s+)?"
                r"(?P<dep>(?:@[\w-]+/)?[\w][\w.-]*(?:@[\w.+\-]+)?)",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="pnpx executes package on-demand (shadow download): {dep}",
            category=Category.UNMANAGED_PACKAGE,
            file_types=_CI_SCRIPT_DOCKER + ["package_config"] + _AGENT_INSTRUCTION,
            escalate_when=[
                (re.compile(r"@(?:latest|alpha|beta|next|canary|nightly|edge)\b", re.IGNORECASE), Severity.CRITICAL),
            ],
        ))

        # bunx (Bun's npx equivalent)
        self.add_rule(PatternRule(
            pattern_id="bunx-execution",
            regex=re.compile(
                r"\bbunx\s+(?P<dep>(?:@[\w-]+/)?[\w][\w.-]*(?:@[\w.+\-]+)?)",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="bunx executes package on-demand (shadow download): {dep}",
            category=Category.UNMANAGED_PACKAGE,
            file_types=_CI_SCRIPT_DOCKER + ["package_config"] + _AGENT_INSTRUCTION,
            escalate_when=[
                (re.compile(r"@(?:latest|alpha|beta|next|canary|nightly|edge)\b", re.IGNORECASE), Severity.CRITICAL),
            ],
        ))

        # bun install -g
        self.add_rule(PatternRule(
            pattern_id="bun-global-install",
            regex=re.compile(
                r"\bbun\s+(?:install|add)\s+[^\n]*(?:-g|--global)[^\n]*(?P<dep>[\w@/.-]+)",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="Global bun package installed outside manifest: {dep}",
            category=Category.UNMANAGED_PACKAGE,
            file_types=_CI_SCRIPT + _AGENT_INSTRUCTION,
        ))

        # `bun add <pkg>` / `pnpm add <pkg>` / `yarn add <pkg>` in CI/action context.
        # These add a dependency at workflow-time, outside any committed manifest.
        # Restricted to CI/action/agent-instruction contexts — local dev
        # scripts are not treated as CI shadow deps.
        self.add_rule(PatternRule(
            pattern_id="bun-add-in-ci",
            regex=re.compile(
                r"\bbun\s+add\s+(?!--save-text-lockfile)(?P<dep>(?:@[\w-]+/)?[\w][\w.-]*(?:@[\w.+\-]+)?)",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="bun add installs a package mid-workflow (no committed manifest): {dep}",
            category=Category.UNMANAGED_PACKAGE,
            file_types=["ci", "github_action", "agent_instruction"],
            escalate_when=[
                (re.compile(r"@(?:latest|alpha|beta|next|canary|nightly|edge)\b", re.IGNORECASE), Severity.CRITICAL),
            ],
        ))
        self.add_rule(PatternRule(
            pattern_id="pnpm-add-in-ci",
            regex=re.compile(
                r"\bpnpm\s+add\s+(?P<dep>(?:@[\w-]+/)?[\w][\w.-]*(?:@[\w.+\-]+)?)",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="pnpm add installs a package mid-workflow: {dep}",
            category=Category.UNMANAGED_PACKAGE,
            file_types=["ci", "github_action", "agent_instruction"],
            escalate_when=[
                (re.compile(r"@(?:latest|alpha|beta|next|canary|nightly|edge)\b", re.IGNORECASE), Severity.CRITICAL),
            ],
        ))
        self.add_rule(PatternRule(
            pattern_id="yarn-add-in-ci",
            regex=re.compile(
                r"\byarn\s+add\s+(?!--frozen-lockfile|--immutable)(?P<dep>(?:@[\w-]+/)?[\w][\w.-]*(?:@[\w.+\-]+)?)",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="yarn add installs a package mid-workflow: {dep}",
            category=Category.UNMANAGED_PACKAGE,
            file_types=["ci", "github_action", "agent_instruction"],
            escalate_when=[
                (re.compile(r"@(?:latest|alpha|beta|next|canary|nightly|edge)\b", re.IGNORECASE), Severity.CRITICAL),
            ],
        ))

        # --- Python ecosystem ---

        self.add_rule(PatternRule(
            pattern_id="pip-install-url",
            regex=re.compile(
                r"pip3?\s+install\s+[^;&|\n]*?(?P<dep>(?<!git\+)https?://[^\s'\";]+)",
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="pip installing package directly from URL: {dep}",
            category=Category.UNMANAGED_PACKAGE,
            file_types=_CI_SCRIPT_DOCKER + _AGENT_INSTRUCTION,
        ))

        # `pip install` in CI / Dockerfile that names a package directly
        # (no -r requirements file, no -e editable, no URL).
        # Excludes self-bootstrap installs (pip / setuptools / wheel / uv /
        # pip-tools) — those are routine `pip install --upgrade pip` lines,
        # not shadow deps.
        self.add_rule(PatternRule(
            pattern_id="pip-install-ci",
            regex=re.compile(
                r"\bpip3?\s+install\s+"
                r"(?!-r\s|-e\s|https?://)"
                r"(?:[^\S\n]*--?\w[\w-]*(?:\s+(?!-)\S+)?\s+)*"
                r"(?P<dep>(?!-)(?!(?:pip|setuptools|wheel|pip-tools|uv)(?:\s|$|==))"
                r"[\w.-]+(?:\[[\w,]+\])?(?:==[\w.]+)?)",
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="pip install in CI/Dockerfile (no lockfile pin): {dep}",
            category=Category.UNMANAGED_PACKAGE,
            file_types=_CI_SCRIPT_DOCKER + _AGENT_INSTRUCTION,
        ))

        # pip with non-PyPI index (dependency confusion risk)
        self.add_rule(PatternRule(
            pattern_id="pip-custom-index",
            regex=re.compile(
                r"pip3?\s+install\s+[^\n]*(?:--index-url|--extra-index-url|--index|-i)(?:=|\s+)['\"]?(?P<dep>https?://[^\s'\"]+)",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="pip using non-default package index (dependency confusion risk): {dep}",
            category=Category.UNMANAGED_PACKAGE,
            file_types=_CI_SCRIPT_DOCKER + _AGENT_INSTRUCTION,
        ))

        # pipx install / pipx run
        self.add_rule(PatternRule(
            pattern_id="pipx-install",
            regex=re.compile(
                # Skip leading flags like --force / --include-deps.
                r"\bpipx\s+(?:install|run)\s+(?:-{1,2}[\w-]+(?:\s+\S+)?\s+)*"
                r"(?P<dep>git\+https?://[^\s'\"`\\]+|(?!-)[\w@/.-]+)",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="pipx installs/runs package in isolation (shadow download): {dep}",
            category=Category.UNMANAGED_PACKAGE,
            file_types=_CI_SCRIPT + _AGENT_INSTRUCTION,
        ))

        # conda install from custom channel
        self.add_rule(PatternRule(
            pattern_id="conda-custom-channel",
            regex=re.compile(
                r"\b(?:conda|mamba|micromamba)\s+(?:install|create)\s+"
                r"[^\n]*(?:-c|--channel)(?:=|\s+)['\"]?(?P<dep>[^\s'\"\\]+)",
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="conda install from custom channel: {dep}",
            category=Category.UNMANAGED_PACKAGE,
            file_types=_UNMANAGED_SCRIPTABLE,
        ))

        # --- Go / Rust / Ruby ---

        self.add_rule(PatternRule(
            pattern_id="go-install",
            regex=re.compile(
                r"\bgo\s+install\s+(?P<dep>\S+@\S+|\S+)",
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="go install pulls binary from module path: {dep}",
            category=Category.UNMANAGED_PACKAGE,
            file_types=_CI_SCRIPT_DOCKER + _AGENT_INSTRUCTION + _DEVCONTAINER,
        ))

        self.add_rule(PatternRule(
            pattern_id="cargo-install",
            regex=re.compile(
                # Flag-skip handles both value-flags (`--target X`) and
                # boolean flags (`--locked`, `--force`).
                r"\bcargo\s+(?:\+\S+\s+)?install\s+(?:-{1,2}[a-z-]+(?:\s+(?!-)\S+)?\s+)*"
                r"(?P<dep>(?!-)[\w-]+(?:@(?:[\w.+-]+|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?))?)",
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="cargo install pulls crate binary: {dep}",
            category=Category.UNMANAGED_PACKAGE,
            file_types=_CI_SCRIPT_DOCKER + _AGENT_INSTRUCTION,
        ))

        self.add_rule(PatternRule(
            pattern_id="cargo-binstall",
            regex=re.compile(
                r"\bcargo\s+(?:\+\S+\s+)?binstall\s+(?:-{1,2}[a-z-]+(?:\s+(?!-)\S+)?\s+)*"
                r"(?P<dep>(?!-)[\w-]+)",
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="cargo binstall pulls prebuilt crate binary: {dep}",
            category=Category.UNMANAGED_PACKAGE,
            file_types=_CI_SCRIPT_DOCKER + _AGENT_INSTRUCTION,
        ))

        # uv (modern Python tooling). uv pip install / uv tool install / uv add
        # in CI installs from network, may bypass committed lockfile.
        self.add_rule(PatternRule(
            pattern_id="uv-pip-install",
            regex=re.compile(
                r"\buv\s+pip\s+install\s+(?!-r\s|--requirements?\s)(?P<dep>(?!-)[\w@.+/-]+)",
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="uv pip install in CI without lockfile: {dep}",
            category=Category.UNMANAGED_PACKAGE,
            file_types=_CI_SCRIPT_DOCKER + _AGENT_INSTRUCTION,
        ))
        self.add_rule(PatternRule(
            pattern_id="uv-tool-install",
            regex=re.compile(
                r"\buv\s+tool\s+(?:install|run)\s+"
                r"(?P<dep>git\+https?://[^\s'\"`\\]+|(?:@[\w-]+/)?[\w][\w.+/-]*(?:@[\w.+\-]+)?)",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="uv tool install fetches binary from PyPI: {dep}",
            category=Category.UNMANAGED_PACKAGE,
            file_types=_CI_SCRIPT_DOCKER + _AGENT_INSTRUCTION + _DEVCONTAINER,
            escalate_when=[
                (re.compile(r"@(?:latest|alpha|beta|next|nightly)\b", re.IGNORECASE), Severity.CRITICAL),
            ],
        ))
        self.add_rule(PatternRule(
            pattern_id="uv-add-in-ci",
            regex=re.compile(
                r"\buv\s+add\s+(?!--frozen)(?P<dep>(?:@[\w-]+/)?[\w][\w.+/-]*(?:@[\w.+\-]+)?)",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="uv add installs a package mid-workflow: {dep}",
            category=Category.UNMANAGED_PACKAGE,
            file_types=["ci", "github_action", "agent_instruction"],
        ))
        # uvx (uv tool run shortcut)
        self.add_rule(PatternRule(
            pattern_id="uvx-execution",
            regex=re.compile(
                r"\buvx\s+(?P<dep>(?:@[\w-]+/)?[\w][\w.+/-]*(?:@[\w.+\-]+)?)",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="uvx executes Python tool on-demand: {dep}",
            category=Category.UNMANAGED_PACKAGE,
            file_types=_CI_SCRIPT_DOCKER + ["package_config"] + _AGENT_INSTRUCTION,
            escalate_when=[
                (re.compile(r"@(?:latest|alpha|beta|next|nightly)\b", re.IGNORECASE), Severity.CRITICAL),
            ],
        ))

        self.add_rule(PatternRule(
            pattern_id="corepack-prepare",
            regex=re.compile(
                r"\bcorepack\s+prepare\s+(?P<dep>(?:pnpm|yarn|npm)@[\w.${}:+-]+)",
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="corepack downloads package manager outside manifest: {dep}",
            category=Category.UNMANAGED_PACKAGE,
            file_types=_UNMANAGED_SCRIPTABLE,
        ))

        self.add_rule(PatternRule(
            pattern_id="corepack-install",
            regex=re.compile(
                r"\bcorepack\s+install\s+(?:-(?:g|-global)\s+|--global\s+)"
                r"(?P<dep>(?:pnpm|yarn|npm)@[\w.${}:+-]+)",
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="corepack installs package manager outside manifest: {dep}",
            category=Category.UNMANAGED_PACKAGE,
            file_types=_UNMANAGED_SCRIPTABLE,
        ))

        # Adding a non-distro apt/dnf/yum/zypper repository — far higher
        # risk than just installing a package, since it gives the new repo
        # persistent install authority over the system.
        self.add_rule(PatternRule(
            pattern_id="add-apt-repository",
            regex=re.compile(
                r"\b(?:sudo\s+)?add-apt-repository\s+['\"]?\$\(\s*(?:curl|wget)\b[^\n)]*?"
                r"(?P<dep>" + _APT_REPO_COMMAND_SUB_URL_TOKEN + r")",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="Adds non-distro APT repository (persistent install authority): {dep}",
            category=Category.UNMANAGED_PACKAGE,
            file_types=_CI_SCRIPT_DOCKER + _AGENT_INSTRUCTION,
        ))
        self.add_rule(PatternRule(
            pattern_id="add-apt-repository",
            regex=re.compile(
                r"\b(?:sudo\s+)?add-apt-repository\s+(?:-y\s+|--yes\s+)?['\"]deb\s+[^'\"]*?"
                r"(?P<dep>https?://[^'\"\s]+)",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="Adds non-distro APT repository (persistent install authority): {dep}",
            category=Category.UNMANAGED_PACKAGE,
            file_types=_CI_SCRIPT_DOCKER + _AGENT_INSTRUCTION,
        ))
        self.add_rule(PatternRule(
            pattern_id="add-apt-repository",
            regex=re.compile(
                r"\b(?:sudo\s+)?add-apt-repository\s+(?:-y\s+|--yes\s+)?['\"]?"
                r"(?P<dep>(?!(?:main|universe|multiverse|restricted)(?:\s|$))(?!-)(?!deb\b)[\w:./+-]+)",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="Adds non-distro APT repository (persistent install authority): {dep}",
            category=Category.UNMANAGED_PACKAGE,
            file_types=_CI_SCRIPT_DOCKER + _AGENT_INSTRUCTION,
        ))
        self.add_rule(PatternRule(
            pattern_id="apt-sources-list-write",
            regex=re.compile(
                r"(?:tee|cat\s*>|cat\s*>>|echo\s+[^|]*?)\s*(?:[^\s]*\s*)?/etc/apt/sources\.list(?:\.d/[\w.-]+)?",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="Writes a custom APT sources.list entry (persistent install authority)",
            category=Category.UNMANAGED_PACKAGE,
            file_types=_CI_SCRIPT_DOCKER + _AGENT_INSTRUCTION,
            extract_group="0",
        ))
        self.add_rule(PatternRule(
            pattern_id="dnf-add-repo",
            regex=re.compile(
                r"\b(?:dnf|yum)\s+config-manager\s+--add-repo\s+(?P<dep>https?://\S+|\S+\.repo)",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="Adds non-distro DNF/YUM repository: {dep}",
            category=Category.UNMANAGED_PACKAGE,
            file_types=_CI_SCRIPT_DOCKER + _AGENT_INSTRUCTION,
        ))
        self.add_rule(PatternRule(
            pattern_id="zypper-add-repo",
            regex=re.compile(
                r"\b(?:sudo\s+)?zypper\s+(?:ar|addrepo)\s+[^\n]*?(?P<dep>https?://\S+)",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="Adds non-distro Zypper repository: {dep}",
            category=Category.UNMANAGED_PACKAGE,
            file_types=_CI_SCRIPT_DOCKER + _AGENT_INSTRUCTION,
        ))

        self.add_rule(PatternRule(
            pattern_id="gem-install",
            regex=re.compile(
                r"\bgem\s+install\s+(?P<dep>[\w-]+)",
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="gem install outside Gemfile: {dep}",
            category=Category.UNMANAGED_PACKAGE,
            file_types=_CI_SCRIPT_DOCKER + _AGENT_INSTRUCTION,
        ))

        # --- Deno ---

        # deno run <url> or deno install <url>
        self.add_rule(PatternRule(
            pattern_id="deno-remote-execution",
            regex=re.compile(
                r"\bdeno\s+(?:run|install)\s+[^\n]*?(?P<dep>https?://\S+)",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="Deno executes/installs remote module: {dep}",
            category=Category.UNMANAGED_PACKAGE,
            file_types=_CI_SCRIPT + _AGENT_INSTRUCTION,
        ))

        # --- .NET ---

        # dotnet tool install/update
        self.add_rule(PatternRule(
            pattern_id="dotnet-tool-install",
            regex=re.compile(
                r"\bdotnet\s+tool\s+(?:install|update)\s+"
                r"(?:(?:(?:--global|--local|--prerelease|--no-cache|--ignore-failed-sources|-g)|"
                r"(?:--tool-path|--version|--add-source|--configfile|--framework)\s+\S+)\s+)*"
                r"(?P<dep>(?!-)[\w.-]+)",
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="dotnet tool installed/updated outside project manifest: {dep}",
            category=Category.UNMANAGED_PACKAGE,
            file_types=_CI_SCRIPT + _AGENT_INSTRUCTION + ["devcontainer"],
        ))

        self.add_rule(PatternRule(
            pattern_id="dotnet-template-install",
            regex=re.compile(
                r"\bdotnet\s+new\s+install\s+(?P<dep>(?!-)[^`\s]+)",
                re.IGNORECASE,
            ),
            severity=Severity.LOW,
            description_template="dotnet template package installed outside project manifest: {dep}",
            category=Category.UNMANAGED_PACKAGE,
            file_types=_CI_SCRIPT + _AGENT_INSTRUCTION + ["devcontainer"],
        ))

        self.add_rule(PatternRule(
            pattern_id="nuget-install",
            regex=re.compile(
                r"\bnuget(?:\.exe)?\s+install\s+(?P<dep>(?!-)[\w.-]+)",
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="NuGet package installed outside project manifest: {dep}",
            category=Category.UNMANAGED_PACKAGE,
            file_types=_CI_SCRIPT + _AGENT_INSTRUCTION,
        ))

        # --- PHP ---

        # composer global require / composer require (in CI)
        self.add_rule(PatternRule(
            pattern_id="composer-global-require",
            regex=re.compile(
                r"\bcomposer\s+(?:global\s+)?require\s+(?P<dep>[\w/.-]+)",
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="Composer package installed in CI: {dep}",
            category=Category.UNMANAGED_PACKAGE,
            file_types=["ci", "script", "github_action", "agent_instruction"],
        ))

        # --- ESP-IDF Components Registry ---

        # idf_component.yml entries look like:
        #   lvgl/lvgl: "~8.3"
        #   espressif/esp_lcd_touch_cst816s: "^1.0"
        # Range specs (~, ^, >, >=) mean the resolver can pick any matching
        # version — unpinned transitive code at flash time.
        self.add_rule(PatternRule(
            pattern_id="idf-component-unpinned",
            regex=re.compile(
                r"^\s+(?P<dep>[\w./-]+/[\w./-]+):\s*['\"][~^>][^'\"]+['\"]",
                re.MULTILINE,
            ),
            severity=Severity.MEDIUM,
            description_template="ESP-IDF component with non-exact version range: {dep}",
            category=Category.UNMANAGED_PACKAGE,
            file_types=["idf_component"],
        ))

        # --- System package managers ---

        self.add_rule(PatternRule(
            pattern_id="brew-install-ci",
            regex=re.compile(
                r"\bbrew\s+install\s+"
                r"(?:(?:--(?:cask|formula|build-from-source|force|quiet|verbose|debug|HEAD|"
                r"ignore-dependencies|include-test|overwrite|display-times|no-sandbox)|-[A-Za-z]+)\s+)*"
                r"['\"]?(?P<dep>\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|[\w@/.-]+)['\"]?",
                re.IGNORECASE,
            ),
            severity=Severity.LOW,
            description_template="Homebrew package installed outside manifest: {dep}",
            category=Category.UNMANAGED_PACKAGE,
            file_types=_CI_SCRIPT + _AGENT_INSTRUCTION,
        ))

        self.add_rule(PatternRule(
            pattern_id="brew-tap-ci",
            regex=re.compile(
                r"\bbrew\s+tap\s+"
                r"(?:(?:--[\w-]+|-[A-Za-z]+)\s+)*"
                r"['\"]?(?P<dep>(?!-)(?:[\w.-]+/[\w.-]+|https?://[^\s'\";]+))['\"]?",
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="Homebrew tap added in CI/script: {dep}",
            category=Category.UNMANAGED_PACKAGE,
            file_types=_UNMANAGED_SCRIPTABLE,
        ))

        self.add_rule(PatternRule(
            pattern_id="winget-command-install",
            regex=re.compile(
                r"\bwinget\s+install\b[^\n]*?(?:--id|-Id)\s+"
                r"(?P<dep>\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|[\w.][\w.-]*)",
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="winget package installed outside manifest: {dep}",
            category=Category.UNMANAGED_PACKAGE,
            file_types=_CI_SCRIPT + _AGENT_INSTRUCTION,
        ))
        self.add_rule(PatternRule(
            pattern_id="winget-command-install",
            regex=re.compile(
                r"\bwinget\s+install\s+(?P<dep>(?!-)(?:\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|[\w.][\w.-]*))",
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="winget package installed outside manifest: {dep}",
            category=Category.UNMANAGED_PACKAGE,
            file_types=_CI_SCRIPT + _AGENT_INSTRUCTION,
        ))
        self.add_rule(PatternRule(
            pattern_id="choco-install",
            regex=re.compile(
                r"\bchoco(?:latey)?\s+install\s+(?P<dep>(?!-)[\w.][\w.-]*)",
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="Chocolatey package installed outside manifest: {dep}",
            category=Category.UNMANAGED_PACKAGE,
            file_types=_CI_SCRIPT + _AGENT_INSTRUCTION,
        ))
        self.add_rule(PatternRule(
            pattern_id="scoop-install",
            regex=re.compile(
                r"\bscoop\s+install\s+(?P<dep>(?!-)[\w./-]+)",
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="Scoop package installed outside manifest: {dep}",
            category=Category.UNMANAGED_PACKAGE,
            file_types=_CI_SCRIPT + _AGENT_INSTRUCTION,
        ))
        self.add_rule(PatternRule(
            pattern_id="azure-cli-extension-install",
            regex=re.compile(
                _AZURE_CLI_EXTENSION_COMMAND_RE
                + r"[^\n]*?(?:--name|-n)(?:=|\s+)(?P<dep>(?!-)[A-Za-z0-9][\w.-]*)",
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="Azure CLI extension installed outside manifest: {dep}",
            category=Category.UNMANAGED_PACKAGE,
            file_types=_UNMANAGED_SCRIPTABLE,
        ))
        self.add_rule(PatternRule(
            pattern_id="azure-cli-bicep-install",
            regex=re.compile(
                r"\baz\s+(?P<dep>bicep)\s+(?:install|upgrade)\b",
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="Azure CLI installs or upgrades managed tool binary: {dep}",
            category=Category.UNMANAGED_PACKAGE,
            file_types=_CI_SCRIPT_DOCKER + _AGENT_INSTRUCTION,
        ))
        self.add_rule(PatternRule(
            pattern_id="azure-cli-aks-install-cli",
            regex=re.compile(
                r"\baz\s+(?P<dep>aks\s+install-cli)\b",
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="Azure CLI installs Kubernetes CLI tools: {dep}",
            category=Category.UNMANAGED_PACKAGE,
            file_types=_CI_SCRIPT_DOCKER + _AGENT_INSTRUCTION,
        ))
        self.add_rule(PatternRule(
            pattern_id="github-cli-extension-install",
            regex=re.compile(
                _GITHUB_CLI_EXTENSION_COMMAND_RE
                + r"\s+(?:-{1,2}[\w-]+(?:\s+(?!-)\S+)?\s+)*"
                r"(?P<dep>(?!-)[\w.-]+/[\w.-]+)",
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="GitHub CLI extension installed outside manifest: {dep}",
            category=Category.UNMANAGED_PACKAGE,
            file_types=_UNMANAGED_SCRIPTABLE,
        ))
        self.add_rule(PatternRule(
            pattern_id="vscode-extension-install",
            regex=re.compile(
                _VSCODE_EXTENSION_INSTALL_COMMAND_RE
                + r"\s+(?:-{1,2}[\w-]+(?:\s+(?!-)\S+)?\s+)*"
                r"(?P<dep>(?!-)[A-Za-z0-9][\w-]*(?:\.[A-Za-z0-9][\w-]*)+)",
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="VS Code extension installed outside manifest: {dep}",
            category=Category.UNMANAGED_PACKAGE,
            file_types=_UNMANAGED_SCRIPTABLE + ["package_config"],
        ))
        self.add_rule(PatternRule(
            pattern_id="krew-plugin-install",
            regex=re.compile(
                _KREW_PLUGIN_INSTALL_COMMAND_RE
                + r"\s+(?:-{1,2}[\w-]+(?:[= ](?!-)\S+)?\s+)*"
                r"(?P<dep>(?!-)[\w.-]+)",
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="kubectl krew plugin installed outside manifest: {dep}",
            category=Category.UNMANAGED_PACKAGE,
            file_types=_UNMANAGED_SCRIPTABLE,
        ))

        self.add_rule(PatternRule(
            pattern_id="system-package-install",
            regex=re.compile(
                _SYSTEM_PACKAGE_COMMAND_RE + r"\s+"
                r"(?:(?:--[\w-]+(?:=(?:\$\{\{.*?\}\}|[^\s]+))?|-{1,2}[A-Za-z]+)\s+)*"
                r"(?P<dep>(?![-./])[A-Za-z0-9_][\w.+-]*(?:\s+(?![-./])[A-Za-z0-9_][\w.+-]*)*)",
                re.IGNORECASE,
            ),
            severity=Severity.LOW,
            description_template="System package manager install outside manifest: {dep}",
            category=Category.UNMANAGED_PACKAGE,
            file_types=_UNMANAGED_SCRIPTABLE,
        ))

        # snap install
        self.add_rule(PatternRule(
            pattern_id="snap-install",
            regex=re.compile(
                r"snap\s+install\s+(?:--classic\s+)?(?P<dep>[\w.-]+)",
                re.IGNORECASE,
            ),
            severity=Severity.LOW,
            description_template="snap package installed outside manifest: {dep}",
            category=Category.UNMANAGED_PACKAGE,
            file_types=["ci", "script", "github_action", "agent_instruction"],
        ))

        # --- Go generate directives ---

        self.add_rule(PatternRule(
            pattern_id="go-generate-command",
            regex=re.compile(
                r"^\s*//go:generate\s+(?P<dep>\S+)",
                re.MULTILINE,
            ),
            severity=Severity.LOW,
            description_template="go:generate invokes external tool: {dep}",
            category=Category.UNMANAGED_PACKAGE,
            file_types=["source_code"],
        ))


def _package_json_dependency_names(content: str) -> set[str]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return set()
    if not isinstance(data, dict):
        return set()
    names: set[str] = set()
    for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        deps = data.get(key)
        if isinstance(deps, dict):
            names.update(str(name) for name in deps)
    return names


def _package_json_local_dependency_bins(content: str, package_json_path) -> set[str]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return set()
    if not isinstance(data, dict):
        return set()
    bins: set[str] = set()
    for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        deps = data.get(key)
        if not isinstance(deps, dict):
            continue
        for spec in deps.values():
            if not isinstance(spec, str) or not spec.startswith("file:"):
                continue
            dep_path = (package_json_path.parent / spec.removeprefix("file:")).resolve()
            try:
                dep_data = json.loads((dep_path / "package.json").read_text(errors="replace"))
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(dep_data, dict):
                continue
            bin_config = dep_data.get("bin")
            if isinstance(bin_config, str):
                name = dep_data.get("name")
                if isinstance(name, str):
                    bins.add(name)
            elif isinstance(bin_config, dict):
                bins.update(str(bin_name) for bin_name in bin_config)
    return bins


def _suppress_local_npx_findings(
    target: FileTarget,
    content: str,
    lines: list[str],
    findings: list[Finding],
) -> list[Finding]:
    if not any(f.pattern_id == "npx-execution" for f in findings):
        return findings
    local_packages, local_bins = _local_npx_context(target, content)
    workflow_contexts: dict[str, tuple[set[str], set[str]]] = {}
    kept: list[Finding] = []
    for finding in findings:
        if finding.pattern_id != "npx-execution":
            kept.append(finding)
            continue
        if _npx_dep_is_local(finding.extracted_dep, local_packages, local_bins):
            continue
        working_directory = _github_workflow_working_directory_for_line(target, lines, finding.line_number)
        if working_directory:
            packages, bins = workflow_contexts.setdefault(
                working_directory,
                _package_json_npx_context_for_working_directory(target, working_directory),
            )
            if _npx_dep_is_local(finding.extracted_dep, packages, bins):
                continue
        kept.append(finding)
    return kept


def _local_npx_context(target: FileTarget, content: str) -> tuple[set[str], set[str]]:
    if target.file_type == "package_config" and target.path.name == "package.json":
        return (
            _package_json_dependency_names(content),
            _package_json_local_dependency_bins(content, target.path),
        )
    package_json = _nearest_package_json(target)
    if package_json is None:
        return set(), set()
    try:
        package_content = package_json.read_text(errors="replace")
    except OSError:
        return set(), set()
    return (
        _package_json_dependency_names(package_content),
        _package_json_local_dependency_bins(package_content, package_json),
    )


def _nearest_package_json(target: FileTarget):
    root = _repo_root_for_target(target)
    current = target.path.parent
    while True:
        candidate = current / "package.json"
        if candidate.is_file():
            return candidate
        if current == root:
            return None
        if root not in current.parents:
            return None
        current = current.parent


def _repo_root_for_target(target: FileTarget) -> Path:
    root = target.path
    for _ in Path(target.rel_path).parts:
        root = root.parent
    return root


def _github_workflow_working_directory_for_line(
    target: FileTarget,
    lines: list[str],
    line_number: int,
) -> str | None:
    if target.file_type not in {"ci", "github_action"}:
        return None
    rel_path = target.rel_path.replace("\\", "/")
    if not rel_path.startswith(".github/workflows/"):
        return None
    start = min(max(line_number - 1, 0), len(lines) - 1)
    for index in range(start, -1, -1):
        line = lines[index]
        match = re.search(r"\bworking-directory:\s*['\"]?(?P<dir>[^'\"\s#]+)", line)
        if match:
            working_directory = match.group("dir").strip()
            if working_directory and not working_directory.startswith(("/", "$")) and ".." not in Path(working_directory).parts:
                return working_directory
        if re.match(r"^\s{2}[\w.-]+:\s*(?:#.*)?$", line):
            break
    return None


def _package_json_npx_context_for_working_directory(
    target: FileTarget,
    working_directory: str,
) -> tuple[set[str], set[str]]:
    root = _repo_root_for_target(target)
    package_json = (root / working_directory / "package.json").resolve()
    try:
        package_json.relative_to(root.resolve())
        package_content = package_json.read_text(errors="replace")
    except (OSError, ValueError):
        return set(), set()
    return (
        _package_json_dependency_names(package_content),
        _package_json_local_dependency_bins(package_content, package_json),
    )


def _npx_dep_is_local(dep: str, local_packages: set[str], local_bins: set[str] | None = None) -> bool:
    if local_bins and dep in local_bins:
        return True
    name = dep.split("@", 1)[0] if not dep.startswith("@") else "@".join(dep.split("@")[:2])
    if name in local_packages:
        return True
    return bool(_KNOWN_BIN_PACKAGES.get(name, set()) & local_packages)


def _normalize_npm_global_findings(findings: list[Finding]) -> list[Finding]:
    normalized: list[Finding] = []
    for finding in findings:
        if finding.pattern_id not in {"npm-global-install", "npm-global-install-flag-after"}:
            normalized.append(finding)
            continue
        deps = _extract_npm_global_install_deps(finding.matched_text)
        if not deps:
            continue
        for dep in deps:
            dep = dep[:200]
            normalized.append(Finding(
                file_path=finding.file_path,
                line_number=finding.line_number,
                category=finding.category,
                severity=_mutable_tag_severity(dep, finding.severity),
                pattern_id=finding.pattern_id,
                matched_text=finding.matched_text,
                extracted_dep=dep,
                description=f"Global npm package installed outside manifest: {dep}",
                scanner_name=finding.scanner_name,
                end_line=finding.end_line,
                analysis_source=finding.analysis_source,
                confidence=finding.confidence,
                enrichment=finding.enrichment,
            ))
    return normalized


def _extract_npm_global_install_deps(line: str) -> list[str]:
    match = re.search(r"\bnpm\s+(?:install|i)\s+(?P<body>[^;&|\n]*)", line, re.IGNORECASE)
    if not match:
        return []
    body = _trim_markdown_inline_code_body(line, match.start(), match.group("body"))
    tokens = _merge_github_expression_tokens(_simple_shell_tokens(body))
    if not any(token in {"-g", "--global"} for token in tokens):
        return []
    deps: list[str] = []
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if token in {"-g", "--global"}:
            i += 1
            continue
        if token in _NPM_VALUE_FLAGS:
            i += 2
            continue
        if token.startswith(tuple(f"{flag}=" for flag in _NPM_VALUE_FLAGS)):
            i += 1
            continue
        if token.startswith("-"):
            i += 1
            continue
        if _is_npm_package_token(token):
            deps.append(token)
        i += 1
    return _unique(deps)


def _trim_markdown_inline_code_body(line: str, command_start: int, body: str) -> str:
    if line[:command_start].count("`") % 2 == 1 and "`" in body:
        return body.split("`", 1)[0]
    return body


def _normalize_system_package_findings(
    target: FileTarget,
    lines: list[str],
    findings: list[Finding],
) -> list[Finding]:
    normalized: list[Finding] = []
    for finding in findings:
        if finding.pattern_id != "system-package-install":
            normalized.append(finding)
            continue
        line = (
            lines[finding.line_number - 1]
            if 0 < finding.line_number <= len(lines)
            else finding.matched_text
        )
        deps = _extract_system_package_install_deps(line)
        for dep in deps:
            dep = dep[:200]
            normalized.append(Finding(
                file_path=finding.file_path,
                line_number=finding.line_number,
                category=finding.category,
                severity=finding.severity,
                pattern_id=finding.pattern_id,
                matched_text=finding.matched_text,
                extracted_dep=dep,
                description=f"System package manager install outside manifest: {dep}",
                scanner_name=finding.scanner_name,
                end_line=finding.end_line,
                analysis_source=finding.analysis_source,
                confidence=finding.confidence,
                enrichment=finding.enrichment,
            ))
    return normalized


def _normalize_go_install_findings(
    target: FileTarget,
    lines: list[str],
    findings: list[Finding],
) -> list[Finding]:
    normalized: list[Finding] = []
    for finding in findings:
        if finding.pattern_id != "go-install":
            normalized.append(finding)
            continue
        line = (
            _go_install_continuation_line(lines, finding.line_number)
            if 0 < finding.line_number <= len(lines)
            else finding.matched_text
        )
        deps = _extract_go_install_deps(line)
        for dep in deps:
            dep = dep[:200]
            normalized.append(Finding(
                file_path=finding.file_path,
                line_number=finding.line_number,
                category=finding.category,
                severity=finding.severity,
                pattern_id=finding.pattern_id,
                matched_text=finding.matched_text,
                extracted_dep=dep,
                description=f"go install pulls binary from module path: {dep}",
                scanner_name=finding.scanner_name,
                end_line=finding.end_line,
                analysis_source=finding.analysis_source,
                confidence=finding.confidence,
                enrichment=finding.enrichment,
            ))
    return normalized


def _normalize_apt_sources_list_findings(lines: list[str], findings: list[Finding]) -> list[Finding]:
    normalized: list[Finding] = []
    for finding in findings:
        if finding.pattern_id != "apt-sources-list-write":
            normalized.append(finding)
            continue
        line = (
            lines[finding.line_number - 1]
            if 0 < finding.line_number <= len(lines)
            else finding.matched_text
        )
        start = max(0, finding.line_number - 7)
        end = min(len(lines), finding.line_number + 6)
        context = "\n".join(lines[start:end])
        dep = _extract_apt_sources_list_dep(finding.extracted_dep, line, context)
        if not dep:
            normalized.append(finding)
            continue
        normalized.append(Finding(
            file_path=finding.file_path,
            line_number=finding.line_number,
            category=finding.category,
            severity=finding.severity,
            pattern_id=finding.pattern_id,
            matched_text=finding.matched_text,
            extracted_dep=dep[:200],
            description=f"Writes a custom APT sources.list entry (persistent install authority): {dep[:200]}",
            scanner_name=finding.scanner_name,
            end_line=finding.end_line,
            analysis_source=finding.analysis_source,
            confidence=finding.confidence,
            enrichment=finding.enrichment,
        ))
    return normalized


def _extract_apt_sources_list_dep(extracted_dep: str, line: str, context: str) -> str:
    for text in (line, context, extracted_dep):
        match = re.search(
            r"\bdeb(?:\s+\[[^\]]+\])?\s+(?P<url>" + _APT_REPO_COMMAND_SUB_URL_TOKEN + r")",
            text,
            re.IGNORECASE,
        )
        if match:
            return match.group("url").rstrip(";,")
        match = re.search(r"\bURIs:\s*(?P<url>https?://[^'\"\s>]+)", text, re.IGNORECASE)
        if match:
            return match.group("url").rstrip(";,")
    for text in (extracted_dep, line):
        match = re.search(_APT_REPO_COMMAND_SUB_URL_TOKEN, text, re.IGNORECASE)
        if match:
            return match.group(0).rstrip(";,")
    return ""


_NPM_VALUE_FLAGS = {
    "--registry",
    "--cache",
    "--prefix",
    "--userconfig",
    "--globalconfig",
    "--tag",
    "--otp",
    "--workspace",
    "--include",
    "--omit",
    "--loglevel",
}


def _is_npm_package_token(token: str) -> bool:
    if not token or token.startswith((".", "/", "http://", "https://")):
        return False
    if re.fullmatch(r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?", token):
        return True
    if "${{" in token:
        return bool(re.fullmatch(
            r"(?:@[\w.-]+/)?[\w][\w./-]*@\$\{\{\s*[^}]+\s*\}\}",
            token,
        ))
    if token in {"true", "false"}:
        return False
    return bool(re.fullmatch(r"(?:@[\w.-]+/)?[\w][\w./-]*(?:@[\w.${}:+-]+)?", token))


def _scan_agent_instruction_comment_installers(
    target: FileTarget,
    lines: list[str],
    existing: list[Finding],
) -> list[Finding]:
    if target.file_type != "agent_instruction":
        return []
    existing_keys = {
        (finding.line_number, finding.pattern_id, finding.extracted_dep)
        for finding in existing
    }
    added: list[Finding] = []
    patterns = (
        (
            "winget-command-install",
            re.compile(
                r"\bwinget\s+install\b[^\n]*?(?:--id|-Id)\s+"
                r"(?P<dep>\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|[\w.][\w.-]*)",
                re.IGNORECASE,
            ),
            Severity.MEDIUM,
            "winget package installed outside manifest: {dep}",
        ),
        (
            "winget-command-install",
            re.compile(
                r"\bwinget\s+install\s+(?P<dep>(?!-)(?:\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|[\w.][\w.-]*))",
                re.IGNORECASE,
            ),
            Severity.MEDIUM,
            "winget package installed outside manifest: {dep}",
        ),
        (
            "choco-install",
            re.compile(r"\bchoco(?:latey)?\s+install\s+(?P<dep>(?!-)[\w.][\w.-]*)", re.IGNORECASE),
            Severity.MEDIUM,
            "Chocolatey package installed outside manifest: {dep}",
        ),
        (
            "scoop-install",
            re.compile(r"\bscoop\s+install\s+(?P<dep>(?!-)[\w./-]+)", re.IGNORECASE),
            Severity.MEDIUM,
            "Scoop package installed outside manifest: {dep}",
        ),
    )
    for line_number, line in enumerate(lines, start=1):
        if not line.lstrip().startswith("#"):
            continue
        if _is_markdown_fence_delimiter(line):
            continue
        for pattern_id, regex, severity, description_template in patterns:
            match = regex.search(line)
            if not match:
                continue
            dep = match.group("dep")
            key = (line_number, pattern_id, dep)
            if key in existing_keys:
                continue
            added.append(_finding(
                target,
                line_number,
                pattern_id,
                dep,
                line,
                severity,
                description_template.format(dep=dep),
            ))
            existing_keys.add(key)
    return added


def _is_non_executable_metadata_or_list_item(
    target: FileTarget,
    finding: Finding,
    lines: list[str] | None = None,
) -> bool:
    if lines is not None and _is_powershell_block_comment_line(target, lines, finding.line_number):
        return True
    if target.file_type in {"ci", "github_action"} and _is_yaml_metadata_label(finding.matched_text):
        return True
    if target.file_type == "agent_instruction" and _is_markdown_fence_delimiter(finding.matched_text):
        return True
    if target.file_type == "agent_instruction" and _is_agent_frontmatter_metadata(finding.matched_text):
        return True
    if target.file_type == "agent_instruction" and _is_markdown_image_alt_text(finding.matched_text):
        return True
    if lines is not None and _is_non_control_markdown_unmanaged_example(target, finding, lines):
        return True
    if _is_printed_install_hint(finding):
        return True
    if finding.pattern_id == "pip-install-url":
        line = (
            lines[finding.line_number - 1]
            if lines is not None and 0 < finding.line_number <= len(lines)
            else finding.matched_text
        )
        if (
            _pip_after_inline_hash_comment(line)
            or _pip_url_is_index_argument(finding)
            or _is_markdown_inline_pip_install_prose(line)
        ):
            return True
    if finding.pattern_id == "pip-custom-index":
        line = _pip_index_continuation_line(lines, finding.line_number, finding.matched_text)
        valid_indexes = {dep[:200] for dep in _extract_pip_custom_indexes(line)}
        if _pip_after_inline_hash_comment(line) or finding.extracted_dep not in valid_indexes:
            return True
    if finding.pattern_id == "npx-execution":
        line = (
            lines[finding.line_number - 1]
            if lines is not None and 0 < finding.line_number <= len(lines)
            else finding.matched_text
        )
        if _is_non_executable_npx_context(line):
            return True
    if finding.pattern_id == "pnpx-execution":
        line = (
            lines[finding.line_number - 1]
            if lines is not None and 0 < finding.line_number <= len(lines)
            else finding.matched_text
        )
        if finding.extracted_dep not in _extract_pnpx_execution_deps(line):
            return True
    if finding.pattern_id == "npm-create":
        line = (
            lines[finding.line_number - 1]
            if lines is not None and 0 < finding.line_number <= len(lines)
            else finding.matched_text
        )
        if _is_npm_create_prose_context(line) or finding.extracted_dep not in _extract_npm_create_deps(line):
            return True
    if finding.pattern_id == "npm-direct-install":
        line = (
            lines[finding.line_number - 1]
            if lines is not None and 0 < finding.line_number <= len(lines)
            else finding.matched_text
        )
        direct_deps = _extract_npm_direct_install_deps(line)
        direct_deps.extend(_extract_javascript_shell_npm_direct_install_deps(line))
        if (
            _is_npm_direct_prose_context(line)
            or _is_npm_direct_redirection_only(line)
            or finding.extracted_dep not in direct_deps
        ):
            return True
    if finding.pattern_id == "pip-install-ci":
        line = (
            finding.matched_text
            if target.file_type == "source_code"
            else _pip_install_continuation_line(lines, finding.line_number, finding.matched_text)
        )
        if (
            _pip_after_inline_hash_comment(line)
            or _is_markdown_inline_pip_install_prose(line)
            or
            _pip_install_dep_is_from_uv_pip(line, finding.extracted_dep)
            or
            not _is_pip_package_token(finding.extracted_dep)
            or finding.extracted_dep not in _extract_pip_install_deps(line)
        ):
            return True
    if finding.pattern_id == "uv-pip-install":
        line = (
            lines[finding.line_number - 1]
            if lines is not None and 0 < finding.line_number <= len(lines)
            else finding.matched_text
        )
        if (
            _pip_after_inline_hash_comment(line)
            or not _is_pip_package_token(finding.extracted_dep)
            or finding.extracted_dep not in _extract_uv_pip_install_deps(line)
        ):
            return True
    if finding.pattern_id == "uv-tool-install":
        line = (
            lines[finding.line_number - 1]
            if lines is not None and 0 < finding.line_number <= len(lines)
            else finding.matched_text
        )
        if finding.extracted_dep not in _extract_uv_tool_install_deps(line):
            return True
    if finding.pattern_id == "uv-add-in-ci" and _is_placeholder_package_dep(finding.extracted_dep):
        return True
    if finding.pattern_id == "uvx-execution":
        line = (
            lines[finding.line_number - 1]
            if lines is not None and 0 < finding.line_number <= len(lines)
            else finding.matched_text
        )
        if (
            _is_uvx_shell_redirection(line, finding.extracted_dep)
            or _is_uvx_prose_context(line)
            or finding.extracted_dep not in _extract_uvx_execution_deps(line)
        ):
            return True
    if finding.pattern_id == "cargo-install":
        line = (
            lines[finding.line_number - 1]
            if lines is not None and 0 < finding.line_number <= len(lines)
            else finding.matched_text
        )
        if finding.extracted_dep not in _extract_cargo_install_deps(line):
            return True
    if finding.pattern_id == "cargo-install-git-source":
        line = (
            lines[finding.line_number - 1]
            if lines is not None and 0 < finding.line_number <= len(lines)
            else finding.matched_text
        )
        if finding.extracted_dep not in _extract_cargo_install_git_sources(line):
            return True
    if finding.pattern_id == "cargo-binstall":
        line = (
            lines[finding.line_number - 1]
            if lines is not None and 0 < finding.line_number <= len(lines)
            else finding.matched_text
        )
        if finding.extracted_dep not in _extract_cargo_binstall_deps(line):
            return True
    if finding.pattern_id == "gem-install":
        line = (
            lines[finding.line_number - 1]
            if lines is not None and 0 < finding.line_number <= len(lines)
            else finding.matched_text
        )
        if finding.extracted_dep not in _extract_gem_install_deps(line):
            return True
    if finding.pattern_id == "conda-custom-channel":
        line = _conda_continuation_line(lines, finding.line_number, finding.matched_text)
        if _is_manual_scan_comment_line(target, line) or finding.extracted_dep not in _extract_conda_custom_channels(line):
            return True
    if finding.pattern_id == "brew-install-ci":
        line = (
            lines[finding.line_number - 1]
            if lines is not None and 0 < finding.line_number <= len(lines)
            else finding.matched_text
        )
        valid_deps = _extract_brew_install_deps(line)
        valid_deps.extend(_extract_brew_install_deps(finding.matched_text))
        if finding.extracted_dep not in valid_deps:
            return True
    if finding.pattern_id == "brew-tap-ci":
        line = (
            lines[finding.line_number - 1]
            if lines is not None and 0 < finding.line_number <= len(lines)
            else finding.matched_text
        )
        if finding.extracted_dep not in _extract_brew_tap_deps(line):
            return True
    if finding.pattern_id == "azure-cli-extension-install":
        line = (
            finding.matched_text
            if target.file_type == "source_code"
            else lines[finding.line_number - 1]
            if lines is not None and 0 < finding.line_number <= len(lines)
            else finding.matched_text
        )
        valid_deps = _extract_azure_cli_extension_deps(line)
        if lines is not None:
            valid_deps.extend(_resolved_azure_cli_extension_deps_at_line(lines, finding.line_number))
        if finding.extracted_dep not in valid_deps:
            return True
    if finding.pattern_id == "github-cli-extension-install":
        line = (
            lines[finding.line_number - 1]
            if lines is not None and 0 < finding.line_number <= len(lines)
            else finding.matched_text
        )
        if finding.extracted_dep not in _extract_github_cli_extension_deps(line):
            return True
    if finding.pattern_id == "vscode-extension-install":
        line = (
            lines[finding.line_number - 1]
            if lines is not None and 0 < finding.line_number <= len(lines)
            else finding.matched_text
        )
        valid_deps = _extract_vscode_extension_deps(line)
        if lines is not None:
            valid_deps.extend(_resolved_vscode_extension_deps_at_line(lines, finding.line_number))
        if finding.extracted_dep not in valid_deps:
            return True
    if finding.pattern_id == "krew-plugin-install":
        line = (
            lines[finding.line_number - 1]
            if lines is not None and 0 < finding.line_number <= len(lines)
            else finding.matched_text
        )
        if finding.extracted_dep not in _extract_krew_plugin_deps(line):
            return True
    if finding.pattern_id == "system-package-install":
        line = (
            lines[finding.line_number - 1]
            if lines is not None and 0 < finding.line_number <= len(lines)
            else finding.matched_text
        )
        valid_deps = _extract_system_package_install_deps(line)
        if not any(_normalize_dep_ws(finding.extracted_dep) == _normalize_dep_ws(dep) for dep in valid_deps):
            return True
    if (
        finding.pattern_id == "system-package-install"
        and target.file_type == "dockerfile"
        and not _dockerfile_system_packages_are_tooling(finding.extracted_dep)
    ):
        return True
    return False


def _is_yaml_metadata_label(line: str) -> bool:
    return bool(re.match(r"\s*(?:-\s*)?(?:displayName|name|description|title):\s+", line, re.IGNORECASE))


def _is_markdown_fence_delimiter(line: str) -> bool:
    stripped = line.strip()
    return stripped.startswith("```") or stripped.startswith("~~~")


def _is_agent_frontmatter_metadata(line: str) -> bool:
    return line.strip().lower().startswith("allowed-tools:")


def _is_markdown_image_alt_text(line: str) -> bool:
    stripped = line.strip()
    return stripped.startswith("![") and "](" in stripped


def _is_non_control_markdown_unmanaged_example(
    target: FileTarget,
    finding: Finding,
    lines: list[str],
) -> bool:
    if target.file_type != "agent_instruction" or target.path.suffix.lower() not in _MARKDOWN_DOC_EXTENSIONS:
        return False
    if target.path.name.lower() in {doc.lower() for doc in _AGENT_CONTROL_DOC_NAMES}:
        return False
    if any(part.lower() in _AGENT_CONTROL_DOC_DIRS for part in target.path.parts):
        return False
    if _is_reference_markdown_path(target.rel_path):
        return _is_markdown_install_command_line(lines, finding.line_number, finding.extracted_dep)
    return _is_markdown_code_example_line(lines, finding.line_number, finding.extracted_dep)


def _is_reference_markdown_path(rel_path: str) -> bool:
    path = "/" + rel_path.replace("\\", "/").lower()
    return "/reference/" in path or "/references/" in path


def _is_markdown_install_command_line(lines: list[str], line_number: int, dep: str) -> bool:
    if not (0 < line_number <= len(lines)) or not dep:
        return False
    line = lines[line_number - 1]
    return dep.lower() in line.lower() and bool(_UNMANAGED_MARKDOWN_COMMAND_RE.search(line))


def _is_markdown_code_example_line(lines: list[str], line_number: int, dep: str) -> bool:
    if not (0 < line_number <= len(lines)):
        return False
    line = lines[line_number - 1]
    if line.startswith(("    ", "\t")):
        return True
    if _is_markdown_inline_code_example(line, dep):
        return True

    in_fence = False
    for index, current in enumerate(lines, start=1):
        stripped = current.lstrip()
        is_fence = stripped.startswith("```") or stripped.startswith("~~~")
        if index == line_number:
            return in_fence or is_fence
        if is_fence:
            in_fence = not in_fence
    return False


def _is_markdown_inline_code_example(line: str, dep: str) -> bool:
    if "`" not in line or not dep:
        return False
    dep = dep.lower()
    start = 0
    while True:
        start = line.find("`", start)
        if start == -1:
            return False
        end = line.find("`", start + 1)
        if end == -1:
            return False
        span = line[start + 1:end].lower()
        if dep in span and _UNMANAGED_MARKDOWN_COMMAND_RE.search(span):
            return True
        start = end + 1


def _is_powershell_block_comment_line(target: FileTarget, lines: list[str], line_number: int) -> bool:
    if target.file_type != "script" or target.path.suffix.lower() not in {".ps1", ".psm1", ".psd1"}:
        return False
    in_block = False
    for index, line in enumerate(lines, start=1):
        stripped = line.lstrip()
        if in_block:
            if index == line_number:
                return True
            if "#>" in line:
                in_block = False
            continue
        if stripped.startswith("<#"):
            if index == line_number:
                return True
            if "#>" not in stripped[stripped.find("<#") + 2:]:
                in_block = True
    return False


def _is_manual_scan_comment_line(target: FileTarget, line: str) -> bool:
    if target.file_type == "script" and re.match(r"(?i)\s*(?:rem(?:\s|$)|::)", line):
        return True
    if target.file_type in {"ci", "script", "build", "dockerfile", "github_action"}:
        stripped = line.lstrip()
        return stripped.startswith("#") and not stripped.startswith("#!")
    return False


def _is_placeholder_package_dep(dep: str) -> bool:
    return bool(re.fullmatch(
        r"(?:@scope/)?(?:package|package-name|your-package|dependency|module)(?:@(?:version|\d+(?:\.\d+){1,3}))?",
        dep,
        re.IGNORECASE,
    ))


def _is_uvx_shell_redirection(line: str, dep: str) -> bool:
    return bool(re.search(
        rf"\buvx\s+{re.escape(dep)}\s*>|"
        rf"\buvx\s+{re.escape(dep)}>",
        line,
        re.IGNORECASE,
    ))


def _is_uvx_prose_context(line: str) -> bool:
    return bool(re.search(
        r"\buvx\s+(?:is|are|was|were|for|when|commands?\.?|found|available|exists?|"
        r"type|cache|support|vs|route|dependency|call)\b",
        line,
        re.IGNORECASE,
    ))


def _printed_input_pipes_into_uvx(line: str) -> bool:
    return bool(re.match(
        r"\s*@?(?:echo|printf)\b.*\|\s*uvx\b",
        line,
        re.IGNORECASE,
    ))


def _extract_uvx_execution_deps(line: str) -> list[str]:
    deps: list[str] = []
    for match in re.finditer(r"(?<![$\w.-])uvx\b", line, re.IGNORECASE):
        if not _uvx_match_is_command_context(line, match.start()):
            continue
        body = re.split(r"(?:&&|\|\||[;|])", line[match.end():], maxsplit=1)[0]
        body = _trim_shell_redirection(body)
        tokens = _merge_github_expression_tokens(_simple_shell_tokens(body))
        dep = _extract_uvx_execution_dep_from_tokens(tokens)
        if dep:
            deps.append(dep)
    return _unique(deps)


def _uvx_match_is_command_context(line: str, start: int) -> bool:
    prefix = line[:start].rstrip()
    if not prefix:
        return True
    if re.search(r"(?:[;&|]|\$\(|\(|`|['\"])\s*$", prefix):
        return True
    if re.search(r"(?:^|[\s|])xargs$", prefix):
        return True
    if re.search(r"(?:=|:)\s*['\"]$", prefix):
        return True
    if re.search(r"\b(?:run|command|script)\s*:\s*['\"`]?$", prefix, re.IGNORECASE):
        return True
    return False


_UVX_VALUE_FLAGS = {
    "--config-setting",
    "--constraint",
    "--default-index",
    "--extra-index-url",
    "--index",
    "--index-url",
    "--keyring-provider",
    "--python",
    "--refresh-package",
    "--with",
    "--with-editable",
    "--with-requirements",
    "-c",
    "-p",
}


def _extract_uvx_execution_dep_from_tokens(tokens: list[str]) -> str:
    i = 0
    while i < len(tokens):
        token = tokens[i].rstrip(",")
        if token == "--":
            return ""
        if token.startswith("--from="):
            dep = _clean_uvx_token(token.split("=", 1)[1])
            return dep if _is_uvx_source_token(dep) else ""
        if token == "--from":
            dep = _clean_uvx_token(tokens[i + 1]) if i + 1 < len(tokens) else ""
            return dep if _is_uvx_source_token(dep) else ""
        name = token.split("=", 1)[0]
        if name in _UVX_VALUE_FLAGS:
            i += 1 if "=" in token else 2
            continue
        if token.startswith("-"):
            i += 1
            continue
        dep = _clean_uvx_token(token)
        return dep if _is_uvx_command_token(dep) else ""
    return ""


def _clean_uvx_token(token: str) -> str:
    return token.strip().strip("'\"").rstrip(",;\\)")


def _is_uvx_source_token(token: str) -> bool:
    if token.startswith("git+https://"):
        return True
    if token.startswith(("http://", "https://", "git+", "file:", ".", "/", "$")):
        return False
    return _is_pip_package_token(token)


def _is_uvx_command_token(token: str) -> bool:
    if not token or token.startswith(("-", ".", "/", "$", "<")):
        return False
    if token.startswith(("http://", "https://", "git+", "file:")):
        return False
    if any(ch in token for ch in "*\\{}"):
        return False
    return bool(re.fullmatch(r"(?:@[\w.-]+/)?[\w][\w.+/-]*(?:@[\w.+-]+)?", token))


def _is_printed_install_hint(finding: Finding) -> bool:
    install_pattern = _PRINTED_INSTALL_HINT_PATTERNS.get(finding.pattern_id)
    if install_pattern is None:
        return False
    line = finding.matched_text
    match = install_pattern.search(line)
    if not match:
        return False
    prefix = line[:match.start()]
    if "$(" in prefix:
        return False
    if re.search(r"(?:&&|\|\||[;|])", prefix):
        return False
    if _looks_like_js_install_hint_storage(prefix):
        return True
    if "`" in prefix:
        return False
    if _looks_like_install_hint_storage(prefix):
        return True
    segment = re.split(r"(?:[{}])", prefix)[-1]
    return _looks_like_printed_help(segment)


def _looks_like_install_hint_storage(prefix: str) -> bool:
    return bool(re.search(
        r"(?:^|[\s;])\$?(?:MISSING(?:_ITEMS?)?|WARNINGS?|ERRORS?|MESSAGES?|INSTALL_HINTS?)\s*\+?=\s*\(?\s*['\"][^'\"]*$",
        prefix,
        re.IGNORECASE,
    ))


def _looks_like_js_install_hint_storage(prefix: str) -> bool:
    return bool(re.search(
        r"(?:^|[\s;])(?:const|let|var)\s+"
        r"(?:body|message|comment(?:_?body)?|warning|error|hint|install_?hint)\s*=\s*['\"][^'\"]*$",
        prefix,
        re.IGNORECASE,
    ))


def _pip_url_is_index_argument(finding: Finding) -> bool:
    url_index = finding.matched_text.find(finding.extracted_dep)
    if url_index == -1:
        url_match = re.search(r"https?://", finding.matched_text, re.IGNORECASE)
        if url_match is None:
            return False
        url_index = url_match.start()
    prefix = finding.matched_text[:url_index]
    return bool(re.search(
        r"(?:--index-url|--extra-index-url|--index|-i)(?:=|\s+)['\"]?$",
        prefix,
        re.IGNORECASE,
    ))


def _pip_install_dep_is_from_uv_pip(line: str, dep: str) -> bool:
    for match in re.finditer(r"\buv\s+pip\s+install\s+(?P<body>[^;&|\n]*)", line, re.IGNORECASE):
        if dep in _extract_pip_install_body_deps(match.group("body")):
            return True
    return False


def _is_shell_for_list_item(line: str) -> bool:
    return bool(re.match(
        r"\s*for\s+[A-Za-z_][A-Za-z0-9_]*\s+in\s+[^;\n]*\bnpx\b",
        line,
        re.IGNORECASE,
    ))


def _is_non_executable_npx_context(line: str) -> bool:
    if _is_shell_for_list_item(line):
        return True
    if _npx_after_inline_hash_comment(line):
        return True
    if _is_quoted_research_prompt_line(line):
        return True
    if _is_npx_prose_context(line):
        return True
    if _looks_like_printed_help(line) and re.search(r"\bnpx\b", line, re.IGNORECASE):
        return True
    if re.search(r"\bgit\s+commit\b[^\n]*(?:-m|--message)(?:=|\s+)['\"][^'\"]*\bnpx\b", line, re.IGNORECASE):
        return True
    if re.search(r"\bconsole\.(?:log|warn|error|info)\s*\([^)]*\bnpx\b", line, re.IGNORECASE):
        return True
    if re.match(r"\s*['\"][^'\"]*\bnpx\b[^'\"]*['\"]\s*\|\s*Tee-Object\b", line, re.IGNORECASE):
        return True
    if re.search(r"\bthrow\s+['\"][^'\"]*\bnpx\b", line, re.IGNORECASE):
        return True
    return False


def _is_quoted_research_prompt_line(line: str) -> bool:
    stripped = line.strip()
    if not re.match(r"""^['"]Write\s+(?:a|an|the)\b""", stripped, re.IGNORECASE):
        return False
    if not re.search(r"\bnpx\b", stripped, re.IGNORECASE):
        return False
    return bool(re.search(
        r"\b(?:micro expert|deep research|cover|include|define|defining|describe|document)\b",
        stripped,
        re.IGNORECASE,
    ))


def _is_npx_prose_context(line: str) -> bool:
    return bool(re.search(
        r"\bnpx\s+(?:is|are|was|were|for|when|commands?\.?|found|available|exists?|"
        r"type|cache|caching|live|route|dependency|call|support|and|failed|fails?|connect(?:ed)?)\b",
        line,
        re.IGNORECASE,
    ))


def _is_npm_create_prose_context(line: str) -> bool:
    normalized = re.sub(r"[*_`]", "", line)
    if re.search(r"\b(?:do\s+not|don't|dont|never|avoid)\s+use\b[^\n]*\bnpm\s+create\b", normalized, re.IGNORECASE):
        return True
    return bool(re.search(
        r"\bnpm\s+create\s+\S+\s+"
        r"(?:is|are|was|were|will|would|should|can|could|must|may|has|have)\b"
        r"\s+(?:run|used|called|shown|displayed|available|blocked|a|an|the|by|in|on|when|with|from|for|to|as)\b",
        line,
        re.IGNORECASE,
    ))


def _extract_npm_create_deps(line: str) -> list[str]:
    deps: list[str] = []
    for match in re.finditer(r"(?<![$\w.-])npm\s+create\s+(?P<body>[^;&|\n]*)", line, re.IGNORECASE):
        tokens = _simple_shell_tokens(_trim_npm_install_body(match.group("body")))
        i = 0
        while i < len(tokens):
            token = tokens[i].rstrip(",")
            if token == "--":
                break
            next_i = _skip_npm_install_option(tokens, i)
            if next_i != i:
                i = next_i
                continue
            if _is_npm_direct_package_token(token):
                deps.append(token)
            break
    return _unique(deps)


def _is_npm_direct_prose_context(line: str) -> bool:
    if re.search(
        r"\bnpm\s+(?:install|i)\s+"
        r"(?:is|are|was|were|will|would|should|can|could|must|may)\b"
        r"\s+(?:a|an|the|allowed|blocked|not|required|optional|command|commands)\b",
        line,
        re.IGNORECASE,
    ):
        return True
    return bool(re.search(
        r"\bnpm\s+(?:install|i)\s+\S+\s+"
        r"(?:is|are|was|were|will|would|should|can|could|must|may|has|have)\b"
        r"\s+(?:run|used|called|shown|displayed|available|allowed|blocked|installed|a|an|the|by|in|on|when|with|from|for|to|as)\b",
        line,
        re.IGNORECASE,
    ))


def _is_npm_direct_redirection_only(line: str) -> bool:
    return bool(re.search(r"\bnpm\s+(?:install|i)\s+\d*\s*>", line, re.IGNORECASE))


def _extract_npm_direct_install_deps(line: str) -> list[str]:
    deps: list[str] = []
    for match in re.finditer(r"\bnpm\s+(?:install|i)\s+(?P<body>[^;&|\n]*)", line, re.IGNORECASE):
        tokens = _simple_shell_tokens(_trim_npm_install_body(match.group("body")))
        i = 0
        while i < len(tokens):
            token = tokens[i].rstrip(",")
            if token in {"-g", "--global"}:
                break
            next_i = _skip_npm_install_option(tokens, i)
            if next_i != i:
                i = next_i
                continue
            if _is_npm_direct_package_token(token):
                deps.append(token)
            i += 1
    return _unique(deps)


def _extract_javascript_shell_npm_direct_install_deps(line: str) -> list[str]:
    deps = _extract_npm_direct_install_deps(line)
    for match in re.finditer(r"\bnpm\s+(?:install|i)\s+(?P<body>[^;&|\n]*)", line, re.IGNORECASE):
        tokens = _simple_shell_tokens(_trim_npm_install_body(match.group("body")))
        i = 0
        while i < len(tokens):
            token = tokens[i].rstrip(",")
            if token in {"-g", "--global"}:
                break
            next_i = _skip_npm_install_option(tokens, i)
            if next_i != i:
                i = next_i
                continue
            if _is_npm_direct_dynamic_package_token(token):
                deps.append(token)
            i += 1
    return _unique(deps)


_NPM_VALUE_FLAGS = {
    "--registry",
    "--cache",
    "--prefix",
    "--userconfig",
    "--tag",
    "--workspace",
    "-w",
}


def _skip_npm_install_option(tokens: list[str], index: int) -> int:
    token = tokens[index].rstrip(",")
    name = token.split("=", 1)[0]
    if name in _NPM_VALUE_FLAGS:
        return index + 1 if "=" in token else min(index + 2, len(tokens))
    if token.startswith("-"):
        return index + 1
    return index


def _trim_npm_install_body(body: str) -> str:
    body = re.split(r"\s+#", body, maxsplit=1)[0]
    body = re.split(r"\s+\(", body, maxsplit=1)[0]
    if "`" in body:
        body = body.split("`", 1)[0]
    return body


def _is_npm_direct_package_token(token: str) -> bool:
    if "..." in token:
        return False
    if not token or token.startswith(("-", ".", "/", "$", "http://", "https://", "git+")):
        return False
    if any(ch in token for ch in "*\\{}"):
        return False
    return bool(re.fullmatch(r"(?:@[\w.-]+/)?[\w][\w./-]*(?:@[\w.+-]+)?", token))


def _is_npm_direct_dynamic_package_token(token: str) -> bool:
    token = token.strip("'\"`").rstrip(",")
    if "..." in token:
        return False
    if not token or token.startswith(("-", ".", "/", "$", "http://", "https://", "git+")):
        return False
    if any(ch in token for ch in "*\\"):
        return False
    return bool(re.fullmatch(
        r"(?:@[\w.-]+/)?[\w][\w.-]*"
        r"(?:(?:\$\{[^}\s]+\}[\w.-]*)+|@(?:\$\{[^}\s]+\}|[\w.+-]*\$\{[^}\s]+\}[\w.+-]*))",
        token,
    ))


def _npx_after_inline_hash_comment(line: str) -> bool:
    hash_index = line.find("#")
    if hash_index == -1:
        return False
    npx_match = re.search(r"(?<![$\w.-])npx\b", line, re.IGNORECASE)
    return bool(npx_match and hash_index < npx_match.start())


def _pip_after_inline_hash_comment(line: str) -> bool:
    hash_index = line.find("#")
    if hash_index == -1:
        return False
    pip_match = re.search(r"\bpip3?\s+install\b", line, re.IGNORECASE)
    return bool(pip_match and hash_index < pip_match.start())


def _expand_npx_package_executions(
    target: FileTarget,
    lines: list[str],
    existing: list[Finding],
) -> list[Finding]:
    if not _supports_npx_package_target(target):
        return []
    existing_keys = {
        (f.line_number, f.pattern_id, f.extracted_dep)
        for f in existing
    }
    added: list[Finding] = []
    for line_number, line in enumerate(lines, start=1):
        if _is_manual_scan_comment_line(target, line):
            continue
        if _is_non_executable_npx_context(line) or not re.search(r"(?<![$\w.-])npx\b", line, re.IGNORECASE):
            continue
        for dep in _extract_npx_package_deps(line):
            key = (line_number, "npx-package-execution", dep)
            if key in existing_keys:
                continue
            severity = _mutable_tag_severity(dep, Severity.HIGH)
            added.append(_finding(
                target,
                line_number,
                "npx-package-execution",
                dep,
                line,
                severity,
                f"npx installs package via --package option: {dep}",
            ))
            existing_keys.add(key)
    return added


def _supports_npx_package_target(target: FileTarget) -> bool:
    if target.file_type in set(_CI_SCRIPT_DOCKER + _AGENT_INSTRUCTION):
        return True
    return target.file_type == "package_config" and target.path.name == "package.json"


def _expand_npm_exec_package_executions(
    target: FileTarget,
    lines: list[str],
    existing: list[Finding],
) -> list[Finding]:
    if not _supports_npx_package_target(target):
        return []
    existing_keys = {
        (f.line_number, f.pattern_id, f.extracted_dep)
        for f in existing
    }
    added: list[Finding] = []
    for line_number, line in enumerate(lines, start=1):
        if _is_manual_scan_comment_line(target, line):
            continue
        if not re.search(r"(?<![$\w.-])npm\s+(?:exec|x)\b", line, re.IGNORECASE):
            continue
        for dep in _extract_npm_exec_package_deps(line):
            key = (line_number, "npm-exec-package", dep)
            if key in existing_keys:
                continue
            severity = _mutable_tag_severity(dep, Severity.HIGH)
            added.append(_finding(
                target,
                line_number,
                "npm-exec-package",
                dep,
                line,
                severity,
                f"npm exec installs package via --package option: {dep}",
            ))
            existing_keys.add(key)
    return added


def _extract_npx_package_deps(line: str) -> list[str]:
    deps: list[str] = []
    for match in re.finditer(r"(?<![$\w.-])npx\b", line, re.IGNORECASE):
        body = re.split(r"(?:&&|\|\||[;|])", line[match.end():], maxsplit=1)[0]
        tokens = _merge_github_expression_tokens(_simple_shell_tokens(body))
        i = 0
        while i < len(tokens):
            token = tokens[i].rstrip(",")
            if token == "--":
                break
            if token.startswith("--package="):
                dep = token.split("=", 1)[1]
                if _is_npx_package_dep(dep):
                    deps.append(dep)
                i += 1
                continue
            if token == "--package":
                if i + 1 < len(tokens) and _is_npx_package_dep(tokens[i + 1]):
                    deps.append(tokens[i + 1])
                i += 2
                continue
            if token == "-p":
                if i + 1 < len(tokens) and _is_npx_package_dep(tokens[i + 1]):
                    deps.append(tokens[i + 1])
                i += 2
                continue
            if token in {"--yes", "-y", "--no-install"}:
                i += 1
                continue
            if token.startswith("-"):
                i += 1
                continue
            break
    return _unique(deps)


def _extract_pnpx_execution_deps(line: str) -> list[str]:
    deps: list[str] = []
    for match in re.finditer(r"(?<![$\w.-])pnpx\b", line, re.IGNORECASE):
        body = re.split(r"(?:&&|\|\||[;|])", line[match.end():], maxsplit=1)[0]
        tokens = _merge_github_expression_tokens(_simple_shell_tokens(body))
        i = 0
        while i < len(tokens):
            token = tokens[i].rstrip(",")
            if token in {"--yes", "-y", "--no-install"}:
                i += 1
                continue
            if token.startswith("-"):
                i += 1
                continue
            dep = token.strip("'\"`")
            if _is_npx_package_dep(dep):
                deps.append(dep)
            break
    return _unique(deps)


def _extract_npx_execution_deps(line: str) -> list[str]:
    deps: list[str] = []
    for match in re.finditer(r"(?<![$\w.-])npx\b", line, re.IGNORECASE):
        body = re.split(r"(?:&&|\|\||[;|])", line[match.end():], maxsplit=1)[0]
        tokens = _merge_github_expression_tokens(_simple_shell_tokens(body))
        i = 0
        while i < len(tokens):
            token = tokens[i].rstrip(",")
            if token == "--":
                break
            if token.startswith("--package") or token == "-p":
                break
            if token == "--offline":
                break
            if token in {"--yes", "-y", "--no-install"}:
                i += 1
                continue
            if token.startswith("-"):
                i += 1
                continue
            dep = token.strip("'\"`")
            if _is_npx_package_dep(dep):
                deps.append(dep)
            break
    return _unique(deps)


def _is_npx_package_dep(dep: str) -> bool:
    return bool(re.fullmatch(r"(?:@[\w.-]+/)?[\w][\w.-]*(?:@[\w.+\-]+)?", dep))


def _extract_npm_exec_package_deps(line: str) -> list[str]:
    deps: list[str] = []
    for match in re.finditer(r"(?<![$\w.-])npm\s+(?:exec|x)\b", line, re.IGNORECASE):
        body = re.split(r"(?:&&|\|\||[;|])", line[match.end():], maxsplit=1)[0]
        tokens = _simple_shell_tokens(body)
        i = 0
        while i < len(tokens):
            token = tokens[i].rstrip(",")
            if token == "--":
                break
            if token.startswith("--package="):
                dep = token.split("=", 1)[1]
                if _is_npx_package_dep(dep):
                    deps.append(dep)
                i += 1
                continue
            if token == "--package":
                if i + 1 < len(tokens) and _is_npx_package_dep(tokens[i + 1]):
                    deps.append(tokens[i + 1])
                i += 2
                continue
            if token == "-p":
                if i + 1 < len(tokens) and _is_npx_package_dep(tokens[i + 1]):
                    deps.append(tokens[i + 1])
                i += 2
                continue
            i += 1
    return _unique(deps)


def _expand_rustup_additions(
    target: FileTarget,
    lines: list[str],
    existing: list[Finding],
) -> list[Finding]:
    if target.file_type not in set(_UNMANAGED_SCRIPTABLE):
        return []
    existing_keys = {
        (f.line_number, f.pattern_id, f.extracted_dep)
        for f in existing
    }
    added: list[Finding] = []
    specs = (
        (
            "rustup-target-add",
            _extract_rustup_target_add_deps,
            "rustup target installed outside manifest",
        ),
        (
            "rustup-component-add",
            _extract_rustup_component_add_deps,
            "rustup component installed outside manifest",
        ),
        (
            "rustup-toolchain-install",
            _extract_rustup_toolchain_install_deps,
            "rustup installs toolchain outside manifest",
        ),
        (
            "rustup-toolchain-update",
            _extract_rustup_toolchain_update_deps,
            "rustup updates toolchain outside manifest",
        ),
        (
            "rustup-toolchain-default",
            _extract_rustup_toolchain_default_deps,
            "rustup sets default toolchain outside manifest",
        ),
    )
    for line_number, line in enumerate(lines, start=1):
        if _is_manual_scan_comment_line(target, line) or _looks_like_printed_help(line):
            continue
        for pattern_id, extractor, description_prefix in specs:
            for dep in extractor(line):
                key = (line_number, pattern_id, dep)
                if key in existing_keys:
                    continue
                added.append(_finding(
                    target,
                    line_number,
                    pattern_id,
                    dep,
                    line,
                    Severity.MEDIUM,
                    f"{description_prefix}: {dep}",
                ))
                existing_keys.add(key)
    return added


def _extract_rustup_target_add_deps(line: str) -> list[str]:
    return _extract_rustup_add_deps(line, r"\brustup\s+target\s+add\b")


def _extract_rustup_component_add_deps(line: str) -> list[str]:
    return _extract_rustup_add_deps(line, r"\brustup\s+component\s+add\b")


def _extract_rustup_toolchain_install_deps(line: str) -> list[str]:
    return _extract_rustup_toolchain_deps(line, r"\brustup\s+(?:toolchain\s+)?install\b")


def _extract_rustup_toolchain_update_deps(line: str) -> list[str]:
    return _extract_rustup_toolchain_deps(line, r"\brustup\s+update\b")


def _extract_rustup_toolchain_default_deps(line: str) -> list[str]:
    return _extract_rustup_toolchain_deps(line, r"\brustup\s+default\b")


def _extract_rustup_add_deps(line: str, command_re: str) -> list[str]:
    deps: list[str] = []
    for match in re.finditer(command_re, line, re.IGNORECASE):
        body = re.split(r"(?:&&|\|\||[;|])", line[match.end():], maxsplit=1)[0]
        body = _trim_shell_redirection(body)
        if "`" in body:
            body = body.split("`", 1)[0]
        tokens = _merge_github_expression_tokens(_simple_shell_tokens(body))
        i = 0
        while i < len(tokens):
            token = tokens[i].rstrip(",")
            next_i = _skip_rustup_add_option(tokens, i)
            if next_i != i:
                i = next_i
                continue
            if _is_rustup_add_dep(token):
                deps.append(token)
            i += 1
    return _unique(deps)


def _extract_rustup_toolchain_deps(line: str, command_re: str) -> list[str]:
    deps: list[str] = []
    for match in re.finditer(command_re, line, re.IGNORECASE):
        body = re.split(r"(?:&&|\|\||[;|])", line[match.end():], maxsplit=1)[0]
        body = _trim_shell_redirection(body)
        if "`" in body:
            body = body.split("`", 1)[0]
        tokens = _merge_github_expression_tokens(_simple_shell_tokens(body))
        i = 0
        while i < len(tokens):
            token = tokens[i].rstrip(",")
            next_i = _skip_rustup_toolchain_option(tokens, i)
            if next_i != i:
                i = next_i
                continue
            if _is_rustup_toolchain_dep(token):
                deps.append(token)
            i += 1
    return _unique(deps)


_RUSTUP_ADD_VALUE_FLAGS = {"--toolchain"}
_RUSTUP_TOOLCHAIN_VALUE_FLAGS = {
    "--component",
    "--components",
    "--default-host",
    "--profile",
    "--target",
    "--targets",
}


def _skip_rustup_add_option(tokens: list[str], index: int) -> int:
    token = tokens[index].rstrip(",")
    name = token.split("=", 1)[0]
    if name in _RUSTUP_ADD_VALUE_FLAGS:
        return index + 1 if "=" in token else min(index + 2, len(tokens))
    if token.startswith("-"):
        return index + 1
    return index


def _skip_rustup_toolchain_option(tokens: list[str], index: int) -> int:
    token = tokens[index].rstrip(",")
    name = token.split("=", 1)[0]
    if name in _RUSTUP_TOOLCHAIN_VALUE_FLAGS:
        return index + 1 if "=" in token else min(index + 2, len(tokens))
    if token.startswith("-"):
        return index + 1
    return index


def _is_rustup_add_dep(dep: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9][\w.+-]*", dep))


def _is_rustup_toolchain_dep(dep: str) -> bool:
    if not dep or dep.startswith(("-", "$", "%", ".", "/", "\\")):
        return False
    if any(marker in dep for marker in ("$(", "${", "%")) and not re.match(
        r"^(?:stable|nightly|beta)-\$\{\{[^}\n]+(?:\}[^}\n]+)*\}\}$",
        dep,
    ):
        return False
    return bool(re.fullmatch(
        r"(?:stable|nightly|beta)(?:-[A-Za-z0-9_.-]+)?"
        r"|(?:stable|nightly|beta)-\$\{\{[^}\n]+(?:\}[^}\n]+)*\}\}"
        r"|\d+(?:\.\d+){0,2}(?:-[A-Za-z0-9_.-]+)?",
        dep,
    ))


def _scan_version_manager_installs(
    target: FileTarget,
    lines: list[str],
    existing: list[Finding],
) -> list[Finding]:
    if target.file_type not in set(_UNMANAGED_SCRIPTABLE):
        return []
    existing_keys = {
        (f.line_number, f.pattern_id, f.extracted_dep)
        for f in existing
    }
    added: list[Finding] = []
    specs = (
        (
            "pyenv-install",
            _extract_pyenv_install_deps,
            "pyenv installs Python runtime outside manifest",
        ),
        (
            "uv-python-install",
            _extract_uv_python_install_deps,
            "uv installs Python runtime outside manifest",
        ),
        (
            "tfenv-install",
            _extract_tfenv_install_deps,
            "tfenv installs Terraform runtime outside manifest",
        ),
        (
            "nvm-install",
            _extract_nvm_install_deps,
            "nvm installs Node.js runtime outside manifest",
        ),
        (
            "fnm-install",
            _extract_fnm_install_deps,
            "fnm installs Node.js runtime outside manifest",
        ),
    )
    for line_number, line in enumerate(lines, start=1):
        if _is_manual_scan_comment_line(target, line) or _looks_like_printed_help(line):
            continue
        for pattern_id, extractor, description_prefix in specs:
            for dep in extractor(line):
                key = (line_number, pattern_id, dep)
                if key in existing_keys:
                    continue
                finding = _finding(
                    target,
                    line_number,
                    pattern_id,
                    dep,
                    line,
                    Severity.MEDIUM,
                    f"{description_prefix}: {dep}",
                )
                if _is_non_executable_metadata_or_list_item(target, finding, lines):
                    continue
                added.append(finding)
                existing_keys.add(key)
    return added


def _extract_pyenv_install_deps(line: str) -> list[str]:
    return _extract_version_manager_install_deps(line, r"\bpyenv\s+install\b", "pyenv")


_UV_PYTHON_INSTALL_VALUE_FLAGS = frozenset({
    "--allow-insecure-host",
    "--config-file",
    "--config-setting",
    "--directory",
    "--install-dir",
    "--link-mode",
    "--mirror",
    "--project",
    "--pypy-install-mirror",
    "--python-preference",
})


def _extract_uv_python_install_deps(line: str) -> list[str]:
    deps: list[str] = []
    for match in re.finditer(r"\buv\s+python\s+install\b", line, re.IGNORECASE):
        if _command_match_is_inert_quoted_string(line, match.start()):
            continue
        body = re.split(r"(?:&&|\|\||[;|])", line[match.end():], maxsplit=1)[0]
        body = _trim_shell_redirection(body)
        if "`" in body:
            body = body.split("`", 1)[0]
        tokens = _merge_github_expression_tokens(_simple_shell_tokens(body))
        if any(t.rstrip(",").lower() in {"--help", "-h"} for t in tokens):
            continue
        explicit_dep = False
        i = 0
        while i < len(tokens):
            token = tokens[i].rstrip(",")
            option = token.split("=", 1)[0]
            if option in _UV_PYTHON_INSTALL_VALUE_FLAGS:
                i += 1 if "=" in token else 2
                continue
            if token.startswith("-"):
                i += 1
                continue
            dep = token.strip("'\"")
            if _is_version_manager_install_dep(dep):
                deps.append(dep)
                explicit_dep = True
            i += 1
        if not explicit_dep:
            deps.append("python")
    return _unique(deps)


def _extract_tfenv_install_deps(line: str) -> list[str]:
    return _extract_version_manager_install_deps(line, r"\btfenv\s+install\b", "tfenv")


def _extract_nvm_install_deps(line: str) -> list[str]:
    return _extract_version_manager_install_deps(line, r"\bnvm\s+install\b", "nvm")


def _extract_fnm_install_deps(line: str) -> list[str]:
    return _extract_version_manager_install_deps(line, r"\bfnm\s+install\b", "fnm")


def _extract_version_manager_install_deps(line: str, command_re: str, tool: str) -> list[str]:
    deps: list[str] = []
    for match in re.finditer(command_re, line, re.IGNORECASE):
        if _command_match_is_inert_quoted_string(line, match.start()):
            continue
        body = re.split(r"(?:&&|\|\||[;|])", line[match.end():], maxsplit=1)[0]
        body = _trim_shell_redirection(body)
        if "`" in body:
            body = body.split("`", 1)[0]
        tokens = _merge_github_expression_tokens(_simple_shell_tokens(body))
        if tool == "pyenv" and any(t.rstrip(",").lower() in {"--list", "-l"} for t in tokens):
            continue
        i = 0
        while i < len(tokens):
            token = tokens[i].rstrip(",")
            if token.startswith("-"):
                i += 1
                continue
            dep = token.strip("'\"")
            if _is_version_manager_install_dep(dep):
                deps.append(dep)
            i += 1
    return _unique(deps)


def _is_version_manager_install_dep(dep: str) -> bool:
    if not dep or dep.startswith((".", "/", "\\")):
        return False
    if dep in {"-", "--"}:
        return False
    if dep.startswith("${{"):
        return bool(re.fullmatch(r"\$\{\{[^}\n]+(?:\}[^}\n]+)*\}\}", dep))
    if dep.startswith("$"):
        return bool(re.fullmatch(r"\$[A-Za-z_][A-Za-z0-9_]*|\$\{[A-Za-z_][A-Za-z0-9_]*\}", dep))
    return bool(re.fullmatch(
        r"(?:latest|min-required)|\d+(?:\.\d+){0,3}(?::latest|[-+][A-Za-z0-9_.-]+)?",
        dep,
        re.IGNORECASE,
    ))


def _mutable_tag_severity(dep: str, default: Severity) -> Severity:
    if re.search(r"@(?:latest|alpha|beta|next|canary|nightly|edge)\b", dep, re.IGNORECASE):
        return Severity.CRITICAL
    return default


def _expand_multi_package_installs(
    target: FileTarget,
    lines: list[str],
    existing: list[Finding],
) -> list[Finding]:
    if target.file_type not in set(_CI_SCRIPT_DOCKER + _AGENT_INSTRUCTION):
        return []
    existing_keys = {
        (f.line_number, f.pattern_id, f.extracted_dep)
        for f in existing
    }
    executable_lines = {
        (f.line_number, f.pattern_id)
        for f in existing
        if f.pattern_id in {"pip-install-ci", "cargo-install", "brew-install-ci", "npm-direct-install", "gem-install"}
    }
    added: list[Finding] = []
    for line_number, line in enumerate(lines, start=1):
        if _is_manual_scan_comment_line(target, line):
            continue
        if (line_number, "npm-direct-install") in executable_lines:
            for dep in _extract_npm_direct_install_deps(line):
                key = (line_number, "npm-direct-install", dep)
                if key in existing_keys:
                    continue
                finding = _finding(
                    target,
                    line_number,
                    "npm-direct-install",
                    dep,
                    line,
                    _mutable_tag_severity(dep, Severity.HIGH),
                    f"npm installs package directly in CI/Dockerfile: {dep}",
                )
                if _is_non_executable_metadata_or_list_item(target, finding, lines):
                    continue
                added.append(finding)
                existing_keys.add(key)
        if (
            (line_number, "pip-install-ci") in executable_lines
            or re.search(r"\bpip3?\s+install\b", line, re.IGNORECASE)
        ):
            command_line = _pip_install_continuation_line(lines, line_number, line)
            for dep in _extract_pip_install_deps(command_line):
                key = (line_number, "pip-install-ci", dep)
                if key in existing_keys:
                    continue
                finding = _finding(
                    target,
                    line_number,
                    "pip-install-ci",
                    dep,
                    command_line,
                    Severity.MEDIUM,
                    f"pip install in CI/Dockerfile (no lockfile pin): {dep}",
                )
                if _is_non_executable_metadata_or_list_item(target, finding, lines):
                    continue
                added.append(finding)
                existing_keys.add(key)
        if (line_number, "cargo-install") in executable_lines or _has_cargo_toolchain_install(line):
            if _looks_like_printed_help(line):
                continue
            for dep in _extract_cargo_install_deps(line):
                key = (line_number, "cargo-install", dep)
                if key not in existing_keys:
                    added.append(_finding(
                        target,
                        line_number,
                        "cargo-install",
                        dep,
                        line,
                        Severity.MEDIUM,
                        f"cargo install pulls crate binary: {dep}",
                    ))
                    existing_keys.add(key)
            for dep in _extract_cargo_install_git_sources(line):
                key = (line_number, "cargo-install-git-source", dep)
                if key not in existing_keys:
                    added.append(_finding(
                        target,
                        line_number,
                        "cargo-install-git-source",
                        dep,
                        line,
                        Severity.MEDIUM,
                        f"cargo install pulls crate from git source: {dep}",
                    ))
                    existing_keys.add(key)
        if (line_number, "cargo-binstall") in executable_lines or _has_cargo_toolchain_binstall(line):
            if _looks_like_printed_help(line):
                continue
            for dep in _extract_cargo_binstall_deps(line):
                key = (line_number, "cargo-binstall", dep)
                if key not in existing_keys:
                    added.append(_finding(
                        target,
                        line_number,
                        "cargo-binstall",
                        dep,
                        line,
                        Severity.MEDIUM,
                        f"cargo binstall pulls prebuilt crate binary: {dep}",
                    ))
                    existing_keys.add(key)
        if (line_number, "brew-install-ci") in executable_lines:
            for dep in _extract_brew_install_deps(line):
                key = (line_number, "brew-install-ci", dep)
                if key not in existing_keys:
                    added.append(_finding(
                        target,
                        line_number,
                        "brew-install-ci",
                        dep,
                        line,
                        Severity.LOW,
                        f"Homebrew installs package in CI/script: {dep}",
                    ))
                    existing_keys.add(key)
        if (line_number, "gem-install") in executable_lines or re.search(r"\bgem\s+install\b", line, re.IGNORECASE):
            if _is_manual_scan_comment_line(target, line) or _looks_like_printed_help(line):
                continue
            for dep in _extract_gem_install_deps(line):
                key = (line_number, "gem-install", dep)
                if key in existing_keys:
                    continue
                finding = _finding(
                    target,
                    line_number,
                    "gem-install",
                    dep,
                    line,
                    Severity.MEDIUM,
                    f"gem install outside Gemfile: {dep}",
                )
                if _is_non_executable_metadata_or_list_item(target, finding, lines):
                    continue
                added.append(finding)
                existing_keys.add(key)
        for dep in _extract_uv_pip_install_deps(line):
            key = (line_number, "uv-pip-install", dep)
            if key not in existing_keys:
                added.append(_finding(
                    target,
                    line_number,
                    "uv-pip-install",
                    dep,
                    line,
                    Severity.MEDIUM,
                    f"uv pip install in CI without lockfile: {dep}",
                ))
                existing_keys.add(key)
        for dep in _extract_uv_tool_install_deps(line):
            key = (line_number, "uv-tool-install", dep)
            if key in existing_keys:
                continue
            finding = _finding(
                target,
                line_number,
                "uv-tool-install",
                dep,
                line,
                _mutable_tag_severity(dep, Severity.HIGH),
                f"uv tool install fetches binary from PyPI: {dep}",
            )
            if _is_non_executable_metadata_or_list_item(target, finding, lines):
                continue
            added.append(finding)
            existing_keys.add(key)
    return added


def _scan_uvx_executions(
    target: FileTarget,
    lines: list[str],
    existing: list[Finding],
) -> list[Finding]:
    if target.file_type not in set(_CI_SCRIPT_DOCKER + ["package_config"] + _AGENT_INSTRUCTION):
        return []
    existing_keys = {
        (f.line_number, f.pattern_id, f.extracted_dep)
        for f in existing
    }
    added: list[Finding] = []
    for line_number, line in enumerate(lines, start=1):
        if _is_manual_scan_comment_line(target, line):
            continue
        if not re.search(r"(?<![$\w.-])uvx\b", line, re.IGNORECASE):
            continue
        if (
            _looks_like_printed_help(line)
            and not re.search(r"\$\([^)]*\buvx\b", line, re.IGNORECASE)
            and not _printed_input_pipes_into_uvx(line)
        ):
            continue
        for dep in _extract_uvx_execution_deps(line):
            key = (line_number, "uvx-execution", dep)
            if key in existing_keys:
                continue
            finding = _finding(
                target,
                line_number,
                "uvx-execution",
                dep,
                line,
                _mutable_tag_severity(dep, Severity.HIGH),
                f"uvx executes Python tool on-demand: {dep}",
            )
            if _is_non_executable_metadata_or_list_item(target, finding, lines):
                continue
            added.append(finding)
            existing_keys.add(key)
    return added


def _scan_pip_custom_indexes(
    target: FileTarget,
    lines: list[str],
    existing: list[Finding],
) -> list[Finding]:
    if target.file_type not in set(_CI_SCRIPT_DOCKER + _AGENT_INSTRUCTION):
        return []
    existing_keys = {
        (f.line_number, f.pattern_id, f.extracted_dep)
        for f in existing
    }
    added: list[Finding] = []
    for line_number, line in enumerate(lines, start=1):
        if _is_manual_scan_comment_line(target, line):
            continue
        if "index" not in line.lower() or not re.search(r"\bpip3?\s+install\b", line, re.IGNORECASE):
            continue
        command_line = _pip_install_continuation_line(lines, line_number, line)
        if _looks_like_printed_help(line):
            continue
        for dep in _extract_pip_custom_indexes(command_line):
            key = (line_number, "pip-custom-index", dep)
            if key in existing_keys:
                continue
            finding = _finding(
                target,
                line_number,
                "pip-custom-index",
                dep,
                command_line,
                Severity.HIGH,
                f"pip using non-default package index (dependency confusion risk): {dep}",
            )
            if _is_non_executable_metadata_or_list_item(target, finding, lines):
                continue
            added.append(finding)
            existing_keys.add(key)
    return added


def _scan_conda_custom_channels(
    target: FileTarget,
    lines: list[str],
    existing: list[Finding],
) -> list[Finding]:
    if target.file_type not in set(_UNMANAGED_SCRIPTABLE):
        return []
    existing_keys = {
        (f.line_number, f.pattern_id, f.extracted_dep)
        for f in existing
    }
    added: list[Finding] = []
    for line_number, line in enumerate(lines, start=1):
        if _is_manual_scan_comment_line(target, line):
            continue
        if _looks_like_printed_help(line) or not _CONDA_CUSTOM_CHANNEL_COMMAND_RE.search(line):
            continue
        command_line = _conda_continuation_line(lines, line_number, line)
        for dep in _extract_conda_custom_channels(command_line):
            key = (line_number, "conda-custom-channel", dep)
            if key in existing_keys:
                continue
            finding = _finding(
                target,
                line_number,
                "conda-custom-channel",
                dep,
                command_line,
                Severity.MEDIUM,
                f"conda install from custom channel: {dep}",
            )
            if _is_non_executable_metadata_or_list_item(target, finding, lines):
                continue
            added.append(finding)
            existing_keys.add(key)
    return added


def _scan_go_run_remote_modules(
    target: FileTarget,
    lines: list[str],
    existing: list[Finding],
) -> list[Finding]:
    if target.file_type not in set(_UNMANAGED_SCRIPTABLE):
        return []
    existing_keys = {
        (f.line_number, f.pattern_id, f.extracted_dep)
        for f in existing
    }
    added: list[Finding] = []
    for line_number, line in enumerate(lines, start=1):
        if _is_manual_scan_comment_line(target, line):
            continue
        if _looks_like_printed_help(line) or not re.search(r"\bgo\s+run\b", line, re.IGNORECASE):
            continue
        for dep in _extract_go_run_remote_deps(line):
            key = (line_number, "go-run-remote", dep)
            if key in existing_keys:
                continue
            finding = _finding(
                target,
                line_number,
                "go-run-remote",
                dep,
                line,
                _mutable_tag_severity(dep, Severity.HIGH),
                f"go run executes remote module on-demand: {dep}",
            )
            if _is_non_executable_metadata_or_list_item(target, finding, lines):
                continue
            added.append(finding)
            existing_keys.add(key)
    return added


def _expand_corepack_prepare(
    target: FileTarget,
    lines: list[str],
    existing: list[Finding],
) -> list[Finding]:
    if target.file_type not in set(_UNMANAGED_SCRIPTABLE):
        return []
    existing_keys = {
        (f.line_number, f.pattern_id, f.extracted_dep)
        for f in existing
    }
    added: list[Finding] = []
    for line_number, line in enumerate(lines, start=1):
        if _is_manual_scan_comment_line(target, line):
            continue
        for match in re.finditer(r"\bcorepack\s+prepare\s+(?P<dep>(?:pnpm|yarn|npm)@[\w.${}:+-]+)", line, re.IGNORECASE):
            dep = match.group("dep")
            key = (line_number, "corepack-prepare", dep)
            if key in existing_keys:
                continue
            added.append(_finding(
                target,
                line_number,
                "corepack-prepare",
                dep,
                line,
                Severity.MEDIUM,
                f"corepack downloads package manager outside manifest: {dep}",
            ))
            existing_keys.add(key)
    return added


def _scan_dynamic_nuget_restores(
    target: FileTarget,
    content: str,
    lines: list[str],
    existing: list[Finding],
) -> list[Finding]:
    if target.file_type not in set(_CI_SCRIPT + _AGENT_INSTRUCTION):
        return []
    if not re.search(r"\bdotnet\s+restore\b", content, re.IGNORECASE):
        return []
    if not re.search(r"<Package(?:Reference|Version)\b", content, re.IGNORECASE):
        return []
    if not re.search(
        r"\b(?:Invoke-RestMethod|Invoke-WebRequest|irm|iwr)\b|api\.nuget\.org|nuget\.org|flatcontainer|registration\d?\.semver",
        content,
        re.IGNORECASE,
    ):
        return []

    existing_keys = {
        (f.line_number, f.pattern_id, f.extracted_dep)
        for f in existing
    }
    dep = _extract_generated_nuget_dep(content)
    added: list[Finding] = []
    for line_number, line in enumerate(lines, start=1):
        if _is_manual_scan_comment_line(target, line):
            continue
        if not _is_executable_dotnet_restore_line(line):
            continue
        key = (line_number, "dotnet-dynamic-restore", dep)
        if key in existing_keys:
            continue
        added.append(_finding(
            target,
            line_number,
            "dotnet-dynamic-restore",
            dep,
            line,
            Severity.HIGH,
            f"dotnet restore uses dynamically generated NuGet package references: {dep}",
        ))
        existing_keys.add(key)
    return added


def _is_executable_dotnet_restore_line(line: str) -> bool:
    return bool(re.search(r"(?:^|[=;&|]\s*)&?\s*dotnet\s+restore\b", line, re.IGNORECASE))


def _scan_dotnet_workloads(
    target: FileTarget,
    lines: list[str],
    existing: list[Finding],
) -> list[Finding]:
    if target.file_type not in set(_UNMANAGED_SCRIPTABLE + ["devcontainer"]):
        return []
    existing_keys = {
        (f.line_number, f.pattern_id, f.extracted_dep)
        for f in existing
    }
    added: list[Finding] = []
    for line_number, line in enumerate(lines, start=1):
        if _is_manual_scan_comment_line(target, line) or _looks_like_printed_help(line):
            continue
        for pattern_id, dep in _extract_dotnet_workload_deps(line):
            key = (line_number, pattern_id, dep)
            if key in existing_keys:
                continue
            finding = _finding(
                target,
                line_number,
                pattern_id,
                dep,
                line,
                Severity.MEDIUM,
                f"dotnet workload command resolves SDK workloads outside project manifest: {dep}",
            )
            if _is_non_executable_metadata_or_list_item(target, finding, lines):
                continue
            added.append(finding)
            existing_keys.add(key)
    return added


def _scan_resolved_nuget_installs(
    target: FileTarget,
    lines: list[str],
    existing: list[Finding],
) -> list[Finding]:
    if target.file_type not in set(_UNMANAGED_SCRIPTABLE):
        return []
    foreach_bindings = _powershell_foreach_literal_arrays(lines)
    existing_keys = {
        (f.line_number, f.pattern_id, f.extracted_dep)
        for f in existing
    }
    added: list[Finding] = []
    for line_number, line in enumerate(lines, start=1):
        if _is_manual_scan_comment_line(target, line):
            continue
        if _looks_like_printed_help(line):
            continue
        for dep in _extract_nuget_install_deps(line, foreach_bindings):
            key = (line_number, "nuget-install", dep)
            if key in existing_keys:
                continue
            added.append(_finding(
                target,
                line_number,
                "nuget-install",
                dep,
                line,
                Severity.MEDIUM,
                f"NuGet package installed outside project manifest: {dep}",
            ))
            existing_keys.add(key)
    return added


def _extract_nuget_install_deps(
    line: str,
    foreach_bindings: dict[str, list[str]] | None = None,
) -> list[str]:
    deps: list[str] = []
    for value in _nuget_install_values(line):
        deps.extend(_resolve_nuget_dep_value(value, foreach_bindings or {}))
    return _unique(deps)


def _nuget_install_values(line: str) -> list[str]:
    values: list[str] = []
    command_re = re.compile(
        r"(?<![$\w.-])(?:&\s*)?(?:nuget(?:\.exe)?|"
        r"\$(?=[A-Za-z_][A-Za-z0-9_]*\b)(?=[A-Za-z0-9_]*nuget)[A-Za-z_][A-Za-z0-9_]*)"
        r"\s+install\b(?P<body>[^#\n;|]*)",
        re.IGNORECASE,
    )
    for match in command_re.finditer(line):
        if _command_match_is_inert_quoted_string(line, match.start()):
            continue
        if _looks_like_printed_help(line[:match.start()]):
            continue
        tokens = _simple_shell_tokens(match.group("body"))
        i = 0
        while i < len(tokens):
            token = tokens[i].rstrip(",`")
            lower = token.lower()
            if lower in _NUGET_INSTALL_VALUE_FLAGS:
                i += 2
                continue
            if any(lower.startswith(f"{flag}:") or lower.startswith(f"{flag}=") for flag in _NUGET_INSTALL_VALUE_FLAGS):
                i += 1
                continue
            if token.startswith("-"):
                i += 1
                continue
            values.append(token)
            break
    return _unique(values)


_NUGET_INSTALL_VALUE_FLAGS = {
    "-configfile",
    "-dependencyversion",
    "-directdownload",
    "-excludeversion",
    "-fallbacksource",
    "-framework",
    "-msbuildpath",
    "-outputdirectory",
    "-packagesavemode",
    "-solutiondirectory",
    "-source",
    "-verbosity",
    "-version",
}


def _resolve_nuget_dep_value(value: str, foreach_bindings: dict[str, list[str]]) -> list[str]:
    value = value.strip("'\"`")
    variable = re.fullmatch(r"\$(?P<name>[A-Za-z_][A-Za-z0-9_]*)", value)
    if variable:
        return [
            dep for dep in foreach_bindings.get(variable.group("name").lower(), [])
            if _is_nuget_package_id(dep)
        ]
    if _is_nuget_package_id(value):
        return [value]
    return []


def _is_nuget_package_id(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*(?:\.[A-Za-z0-9][A-Za-z0-9_.-]*)*", value))


def _scan_dotnet_tool_installs(
    target: FileTarget,
    lines: list[str],
    existing: list[Finding],
) -> list[Finding]:
    if target.file_type not in set(_CI_SCRIPT + _AGENT_INSTRUCTION + _DEVCONTAINER):
        return []
    existing_keys = {
        (f.line_number, f.pattern_id, f.extracted_dep)
        for f in existing
    }
    added: list[Finding] = []
    for line_number, line in enumerate(lines, start=1):
        if _is_manual_scan_comment_line(target, line):
            continue
        if _looks_like_printed_help(line):
            continue
        if not re.search(r"\bdotnet\s+tool\s+(?:install|update)\b", line, re.IGNORECASE):
            continue
        command_line = _dotnet_tool_continuation_line(lines, line_number)
        for dep in _extract_dotnet_tool_install_deps(command_line):
            key = (line_number, "dotnet-tool-install", dep)
            if key in existing_keys:
                continue
            added.append(_finding(
                target,
                line_number,
                "dotnet-tool-install",
                dep,
                command_line,
                Severity.MEDIUM,
                f"dotnet tool installed/updated outside project manifest: {dep}",
            ))
            existing_keys.add(key)
    return added


def _dotnet_tool_continuation_line(lines: list[str], line_number: int) -> str:
    if not (0 < line_number <= len(lines)):
        return ""
    start = lines[line_number - 1]
    parts = [start.strip().rstrip("\\`").rstrip()]
    if _extract_dotnet_tool_install_deps(parts[0]):
        return parts[0]
    base_indent = len(start) - len(start.lstrip())
    index = line_number
    while index < len(lines) and len(parts) < 8:
        raw = lines[index]
        stripped = raw.strip()
        if not stripped:
            break
        indent = len(raw) - len(raw.lstrip())
        if indent < base_indent:
            break
        if re.match(r"(?:-|[A-Za-z_][\w-]*:)\s", stripped) and not stripped.startswith("--"):
            break
        parts.append(stripped.rstrip("\\`").rstrip())
        if _extract_dotnet_tool_install_deps(" ".join(parts)):
            # Keep nearby value flags in the matched text when present, but avoid
            # drifting into unrelated YAML or shell commands.
            lookahead = index + 1
            while lookahead < len(lines) and len(parts) < 8:
                next_raw = lines[lookahead]
                next_stripped = next_raw.strip()
                next_indent = len(next_raw) - len(next_raw.lstrip())
                if (
                    not next_stripped
                    or next_indent < base_indent
                    or re.match(r"(?:-|[A-Za-z_][\w-]*:)\s", next_stripped) and not next_stripped.startswith("--")
                ):
                    break
                if not next_stripped.startswith("-"):
                    break
                parts.append(next_stripped.rstrip("\\`").rstrip())
                lookahead += 1
            break
        index += 1
    return " ".join(parts)


def _extract_dotnet_tool_install_deps(line: str) -> list[str]:
    deps: list[str] = []
    command_re = re.compile(r"\bdotnet\s+tool\s+(?:install|update)\s+(?P<body>[^#\n;|]*)", re.IGNORECASE)
    for match in command_re.finditer(line):
        tokens = _merge_github_expression_tokens(_simple_shell_tokens(match.group("body")))
        i = 0
        while i < len(tokens):
            token = tokens[i].rstrip(",`")
            next_i = _skip_dotnet_tool_option(tokens, i)
            if next_i != i:
                i = next_i
                continue
            if _is_dotnet_tool_package_id(token):
                deps.append(token)
                break
            i += 1
    return _unique(deps)


_DOTNET_TOOL_VALUE_FLAGS = {
    "--add-source",
    "--arch",
    "--configfile",
    "--framework",
    "--tool-manifest",
    "--tool-path",
    "--verbosity",
    "--version",
}


def _skip_dotnet_tool_option(tokens: list[str], index: int) -> int:
    token = tokens[index].rstrip(",`")
    name = token.split("=", 1)[0]
    if name in _DOTNET_TOOL_VALUE_FLAGS:
        return index + 1 if "=" in token else min(index + 2, len(tokens))
    if token.startswith("-"):
        return index + 1
    return index


def _is_dotnet_tool_package_id(value: str) -> bool:
    if not value or value.startswith(("$", "@", "%", "-", ".", "/", "\\")):
        return False
    if value.lower() in {"install", "update"}:
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", value))


def _extract_dotnet_workload_deps(line: str) -> list[tuple[str, str]]:
    deps: list[tuple[str, str]] = []
    command_re = re.compile(
        r"(?<![\w.-])(?:sudo\s+)?(?:&\s*)?(?:\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|dotnet)"
        r"\s+workload\s+(?P<verb>install|update|restore)\b",
        re.IGNORECASE,
    )
    for match in command_re.finditer(line):
        verb = match.group("verb").lower()
        body = re.split(r"(?:&&|\|\||[;|])", line[match.end():], maxsplit=1)[0]
        body = _trim_shell_redirection(body)
        if "`" in body:
            body = body.split("`", 1)[0]
        if verb == "restore":
            deps.append(("dotnet-workload-restore", "restore"))
            continue
        if verb == "update":
            deps.append(("dotnet-workload-update", "update"))
            continue
        for dep in _extract_dotnet_workload_install_deps(body):
            deps.append(("dotnet-workload-install", dep))
    return _unique_tuples(deps)


def _extract_dotnet_workload_install_deps(body: str) -> list[str]:
    deps: list[str] = []
    tokens = _merge_github_expression_tokens(_simple_shell_tokens(body))
    i = 0
    while i < len(tokens):
        token = tokens[i].rstrip(",")
        next_i = _skip_dotnet_workload_option(tokens, i)
        if next_i != i:
            i = next_i
            continue
        if _is_dotnet_workload_id(token):
            deps.append(token)
        i += 1
    return _unique(deps)


_DOTNET_WORKLOAD_VALUE_FLAGS = {
    "--configfile",
    "--from-cache",
    "--from-rollback-file",
    "--sdk-version",
    "--source",
    "-s",
}


def _skip_dotnet_workload_option(tokens: list[str], index: int) -> int:
    token = tokens[index].rstrip(",")
    name = token.split("=", 1)[0]
    if name in _DOTNET_WORKLOAD_VALUE_FLAGS:
        return index + 1 if "=" in token else min(index + 2, len(tokens))
    if token.startswith("-"):
        return index + 1
    return index


def _is_dotnet_workload_id(dep: str) -> bool:
    if not dep or dep.startswith(("$", "@", "%", "-", ".", "/", "\\")):
        return False
    return bool(re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]*", dep))


def _extract_generated_nuget_dep(content: str) -> str:
    match = re.search(
        r"<Package(?:Reference|Version)\b[^>]*\bInclude=(?:\\?['\"])(?P<id>[^'\"\\]+)(?:\\?['\"])"
        r"[^>]*\bVersion=(?:\\?['\"])(?P<version>[^'\"\\]+)(?:\\?['\"])",
        content,
        re.IGNORECASE,
    )
    if match:
        return f"{match.group('id')}@{match.group('version')}"[:200]
    return "generated NuGet package reference"


def _scan_r_install_lines(
    target: FileTarget,
    lines: list[str],
    existing: list[Finding],
) -> list[Finding]:
    if target.file_type not in set(_UNMANAGED_SCRIPTABLE):
        return []
    existing_keys = {
        (f.line_number, f.pattern_id, f.extracted_dep)
        for f in existing
    }
    added: list[Finding] = []
    for line_number, line in enumerate(lines, start=1):
        if _is_manual_scan_comment_line(target, line):
            continue
        if _looks_like_printed_help(line):
            continue
        for body in _extract_r_call_bodies(line, r"\binstall\.packages\s*\("):
            for dep in _extract_r_install_package_deps(body):
                key = (line_number, "r-install-packages", dep)
                if key in existing_keys:
                    continue
                added.append(_finding(
                    target,
                    line_number,
                    "r-install-packages",
                    dep,
                    line,
                    Severity.MEDIUM,
                    f"R install.packages installs package outside manifest: {dep}",
                ))
                existing_keys.add(key)
        for body in _extract_r_call_bodies(line, r"\b(?:remotes|devtools)::install_github\s*\("):
            for dep in _extract_r_install_github_deps(body):
                key = (line_number, "r-install-github", dep)
                if key in existing_keys:
                    continue
                added.append(_finding(
                    target,
                    line_number,
                    "r-install-github",
                    dep,
                    line,
                    Severity.HIGH,
                    f"R install_github pulls package from GitHub: {dep}",
                ))
                existing_keys.add(key)
    return added


_JULIA_STRING_ASSIGNMENT_RE = re.compile(
    r"""^\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*["'](?P<value>[A-Za-z][A-Za-z0-9_.-]*)["']""",
)
_JULIA_PKG_ADD_RE = re.compile(r"\bPkg\.add\s*\((?P<body>[^\n]*)\)", re.IGNORECASE)


def _scan_julia_pkg_add_lines(
    target: FileTarget,
    lines: list[str],
    existing: list[Finding],
) -> list[Finding]:
    if target.file_type not in {"ci", "script", "build", "dockerfile", "github_action"}:
        return []
    existing_keys = {
        (f.line_number, f.pattern_id, f.extracted_dep)
        for f in existing
    }
    added: list[Finding] = []
    for line_number, line in enumerate(lines, start=1):
        if _is_manual_scan_comment_line(target, line) or _looks_like_printed_help(line):
            continue
        for dep in _extract_julia_pkg_add_deps(lines, line_number):
            key = (line_number, "julia-pkg-add", dep)
            if key in existing_keys:
                continue
            added.append(_finding(
                target,
                line_number,
                "julia-pkg-add",
                dep,
                line,
                Severity.MEDIUM,
                f"Julia Pkg.add installs package outside manifest: {dep}",
            ))
            existing_keys.add(key)
    return added


def _extract_julia_pkg_add_deps(lines: list[str], line_number: int) -> list[str]:
    if not (0 < line_number <= len(lines)):
        return []
    line = lines[line_number - 1]
    match = _JULIA_PKG_ADD_RE.search(line)
    if not match:
        return []
    body = match.group("body")
    deps: list[str] = []
    for named in re.finditer(
        r"""\bname\s*=\s*["'](?P<dep>[A-Za-z][A-Za-z0-9_.-]*)["']""",
        body,
        re.IGNORECASE,
    ):
        deps.append(named.group("dep"))
    if not deps:
        deps.extend(_extract_julia_pkg_add_string_args(body))
    if not deps and re.search(r"(?:^|[;,\s(])name(?:\s*[,)]|$)", body):
        assignments = _collect_nearby_julia_string_assignments(lines, line_number)
        dep = assignments.get("name")
        if dep:
            deps.append(dep)
    return _unique([dep for dep in deps if _is_julia_package_name(dep)])


def _extract_julia_pkg_add_string_args(body: str) -> list[str]:
    deps: list[str] = []
    for match in re.finditer(r"""["'](?P<dep>[A-Za-z][A-Za-z0-9_.-]*)["']""", body):
        prefix = body[:match.start()]
        if re.search(r"\b(?:uuid|version|url|rev)\s*=\s*$", prefix, re.IGNORECASE):
            continue
        deps.append(match.group("dep"))
    return deps


def _collect_nearby_julia_string_assignments(lines: list[str], line_number: int) -> dict[str, str]:
    values: dict[str, str] = {}
    start = max(0, line_number - 8)
    for candidate in lines[start:line_number - 1]:
        match = _JULIA_STRING_ASSIGNMENT_RE.search(candidate)
        if match:
            values[match.group("name")] = match.group("value")
    return values


def _is_julia_package_name(dep: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]*", dep)) and dep.lower() not in {
        "name",
        "uuid",
        "version",
    }


def _scan_python_shell_system_package_installs(
    target: FileTarget,
    content: str,
    lines: list[str],
    existing: list[Finding],
) -> list[Finding]:
    existing_keys = {
        (f.line_number, f.pattern_id, f.extracted_dep)
        for f in existing
    }
    added: list[Finding] = []
    for command in iter_python_shell_commands(target, content, lines):
        for dep in _extract_system_package_install_deps(command.command):
            key = (command.line_number, "system-package-install", dep)
            if key in existing_keys:
                continue
            added.append(_finding(
                target,
                command.line_number,
                "system-package-install",
                dep,
                command.matched_text,
                Severity.LOW,
                f"System package manager install outside manifest: {dep}",
            ))
            existing_keys.add(key)
    return added


def _scan_python_shell_azure_cli_extensions(
    target: FileTarget,
    content: str,
    lines: list[str],
    existing: list[Finding],
) -> list[Finding]:
    existing_keys = {
        (f.line_number, f.pattern_id, f.extracted_dep)
        for f in existing
    }
    added: list[Finding] = []
    for command in iter_python_shell_commands(target, content, lines):
        for dep in _extract_azure_cli_extension_deps(command.command):
            key = (command.line_number, "azure-cli-extension-install", dep)
            if key in existing_keys:
                continue
            added.append(_finding(
                target,
                command.line_number,
                "azure-cli-extension-install",
                dep,
                command.command,
                Severity.MEDIUM,
                f"Azure CLI extension installed outside manifest: {dep}",
            ))
            existing_keys.add(key)
    return added


def _scan_python_shell_pip_installs(
    target: FileTarget,
    content: str,
    lines: list[str],
    existing: list[Finding],
) -> list[Finding]:
    existing_keys = {
        (f.line_number, f.pattern_id, f.extracted_dep)
        for f in existing
    }
    added: list[Finding] = []
    for command in iter_python_shell_commands(target, content, lines):
        if re.search(r"(?:\bpython3?\s+-m\s+)?\bpip3?\s+install\b", command.command, re.IGNORECASE):
            for dep in _extract_pip_install_deps(command.command):
                key = (command.line_number, "pip-install-ci", dep)
                if key in existing_keys:
                    continue
                added.append(_finding(
                    target,
                    command.line_number,
                    "pip-install-ci",
                    dep,
                    command.command,
                    Severity.MEDIUM,
                    f"pip install in source shell command (no lockfile pin): {dep}",
                ))
                existing_keys.add(key)
        for dep in _extract_uv_tool_install_deps(command.command):
            key = (command.line_number, "uv-tool-install", dep)
            if key in existing_keys:
                continue
            added.append(_finding(
                target,
                command.line_number,
                "uv-tool-install",
                dep,
                command.command,
                _mutable_tag_severity(dep, Severity.HIGH),
                f"uv tool install fetches binary from PyPI: {dep}",
            ))
            existing_keys.add(key)
    return added


def _scan_javascript_shell_package_runners(
    target: FileTarget,
    content: str,
    lines: list[str],
    existing: list[Finding],
) -> list[Finding]:
    existing_keys = {
        (f.line_number, f.pattern_id, f.extracted_dep)
        for f in existing
    }
    added: list[Finding] = []
    for command in iter_javascript_shell_commands(target, content, lines):
        global_deps = _extract_npm_global_install_deps(command.command)
        for dep in global_deps:
            key = (command.line_number, "npm-global-install", dep)
            if key in existing_keys:
                continue
            severity = _mutable_tag_severity(dep, Severity.HIGH)
            added.append(_finding(
                target,
                command.line_number,
                "npm-global-install",
                dep,
                command.command,
                severity,
                f"Global npm package installed outside manifest: {dep}",
            ))
            existing_keys.add(key)
        for dep in _extract_brew_install_deps(command.command):
            key = (command.line_number, "brew-install-ci", dep)
            if key in existing_keys:
                continue
            added.append(_finding(
                target,
                command.line_number,
                "brew-install-ci",
                dep,
                command.command,
                Severity.LOW,
                f"Homebrew package installed outside manifest: {dep}",
            ))
            existing_keys.add(key)
        for value in _winget_install_values(command.command):
            if not _is_winget_package_id(value):
                continue
            key = (command.line_number, "winget-command-install", value)
            if key in existing_keys:
                continue
            added.append(_finding(
                target,
                command.line_number,
                "winget-command-install",
                value,
                command.command,
                Severity.MEDIUM,
                f"winget package installed outside manifest: {value}",
            ))
            existing_keys.add(key)
        direct_deps = [] if global_deps else _extract_javascript_shell_npm_direct_install_deps(command.command)
        for dep in direct_deps:
            key = (command.line_number, "npm-direct-install", dep)
            if key in existing_keys:
                continue
            severity = _mutable_tag_severity(dep, Severity.HIGH)
            added.append(_finding(
                target,
                command.line_number,
                "npm-direct-install",
                dep,
                command.command,
                severity,
                f"npm installs package directly in source shell command: {dep}",
            ))
            existing_keys.add(key)
        for dep in _extract_npx_execution_deps(command.command):
            key = (command.line_number, "npx-execution", dep)
            if key in existing_keys:
                continue
            severity = _mutable_tag_severity(dep, Severity.HIGH)
            added.append(_finding(
                target,
                command.line_number,
                "npx-execution",
                dep,
                command.matched_text,
                severity,
                f"npx executes package on-demand (shadow download): {dep}",
            ))
            existing_keys.add(key)
        for dep in _extract_azure_cli_extension_deps(command.command):
            key = (command.line_number, "azure-cli-extension-install", dep)
            if key in existing_keys:
                continue
            added.append(_finding(
                target,
                command.line_number,
                "azure-cli-extension-install",
                dep,
                command.command,
                Severity.MEDIUM,
                f"Azure CLI extension installed outside manifest: {dep}",
            ))
            existing_keys.add(key)
        for dep in _extract_pnpx_execution_deps(command.command):
            key = (command.line_number, "pnpx-execution", dep)
            if key in existing_keys:
                continue
            severity = _mutable_tag_severity(dep, Severity.HIGH)
            added.append(_finding(
                target,
                command.line_number,
                "pnpx-execution",
                dep,
                command.matched_text,
                severity,
                f"pnpx executes package on-demand (shadow download): {dep}",
            ))
            existing_keys.add(key)
        for dep in _extract_uv_tool_install_deps(command.command):
            key = (command.line_number, "uv-tool-install", dep)
            if key in existing_keys:
                continue
            added.append(_finding(
                target,
                command.line_number,
                "uv-tool-install",
                dep,
                command.command,
                _mutable_tag_severity(dep, Severity.HIGH),
                f"uv tool install fetches binary from PyPI: {dep}",
            ))
            existing_keys.add(key)
    return added


def _scan_resolved_azure_cli_extensions(
    target: FileTarget,
    lines: list[str],
    existing: list[Finding],
) -> list[Finding]:
    if target.file_type not in set(_UNMANAGED_SCRIPTABLE):
        return []
    existing_keys = {
        (f.line_number, f.pattern_id, f.extracted_dep)
        for f in existing
    }
    resolved = (
        _powershell_psitem_azure_cli_extension_deps(lines)
        + _shell_azure_cli_extension_wrapper_calls(lines)
    )
    added: list[Finding] = []
    for line_number, dep in resolved:
        key = (line_number, "azure-cli-extension-install", dep)
        if key in existing_keys:
            continue
        added.append(_finding(
            target,
            line_number,
            "azure-cli-extension-install",
            dep,
            lines[line_number - 1],
            Severity.MEDIUM,
            f"Azure CLI extension installed outside manifest: {dep}",
        ))
        existing_keys.add(key)
    return added


def _resolved_azure_cli_extension_deps_at_line(lines: list[str], line_number: int) -> list[str]:
    return _unique([
        dep
        for resolved_line, dep in (
            _powershell_psitem_azure_cli_extension_deps(lines)
            + _shell_azure_cli_extension_wrapper_calls(lines)
        )
        if resolved_line == line_number
    ])


def _scan_resolved_vscode_extensions(
    target: FileTarget,
    lines: list[str],
    existing: list[Finding],
) -> list[Finding]:
    if target.file_type not in set(_UNMANAGED_SCRIPTABLE):
        return []
    existing_keys = {
        (f.line_number, f.pattern_id, f.extracted_dep)
        for f in existing
    }
    arrays = _vscode_extension_array_deps(lines)
    resolved = _powershell_vscode_extension_wrapper_calls(lines)
    if arrays:
        for line_number, line in enumerate(lines, start=1):
            if not re.search(_VSCODE_EXTENSION_INSTALL_COMMAND_RE, line, re.IGNORECASE):
                continue
            if _extract_vscode_extension_deps(line):
                continue
            resolved.extend((line_number, dep) for dep in _resolved_vscode_extension_deps(line, arrays))
    if not resolved:
        return []
    added: list[Finding] = []
    for line_number, dep in _unique_tuples(resolved):
        key = (line_number, "vscode-extension-install", dep)
        if key in existing_keys:
            continue
        added.append(_finding(
            target,
            line_number,
            "vscode-extension-install",
            dep,
            lines[line_number - 1],
            Severity.MEDIUM,
            f"VS Code extension installed outside manifest: {dep}",
        ))
        existing_keys.add(key)
    return added


def _scan_helm_remote_artifacts(
    target: FileTarget,
    lines: list[str],
    existing: list[Finding],
) -> list[Finding]:
    if target.file_type not in set(_UNMANAGED_SCRIPTABLE):
        return []
    existing_keys = {
        (f.line_number, f.pattern_id, f.extracted_dep)
        for f in existing
    }
    added: list[Finding] = []
    specs = (
        (
            "helm-repo-add",
            _extract_helm_repo_add_deps,
            Severity.MEDIUM,
            "Helm repository added outside manifest: {dep}",
        ),
        (
            "helm-chart-pull",
            _extract_helm_chart_pull_deps,
            Severity.MEDIUM,
            "Helm pulls chart artifact outside manifest: {dep}",
        ),
        (
            "helm-plugin-install",
            _extract_helm_plugin_install_deps,
            Severity.MEDIUM,
            "Helm plugin installed outside manifest: {dep}",
        ),
    )
    for line_number, line in enumerate(lines, start=1):
        if _is_manual_scan_comment_line(target, line):
            continue
        if _looks_like_printed_help(line):
            continue
        for pattern_id, extractor, severity, description_template in specs:
            for dep in extractor(line):
                key = (line_number, pattern_id, dep)
                if key in existing_keys:
                    continue
                added.append(_finding(
                    target,
                    line_number,
                    pattern_id,
                    dep,
                    line,
                    severity,
                    description_template.format(dep=dep),
                ))
                existing_keys.add(key)
    return added


def _scan_powershell_install_modules(
    target: FileTarget,
    lines: list[str],
    existing: list[Finding],
) -> list[Finding]:
    if target.file_type not in set(_UNMANAGED_SCRIPTABLE):
        return []
    foreach_bindings = _powershell_foreach_literal_arrays(lines)
    wrapper_calls = _powershell_install_module_wrapper_calls(lines)
    existing_keys = {
        (f.line_number, f.pattern_id, f.extracted_dep)
        for f in existing
    }
    added: list[Finding] = []
    for line_number, line in enumerate(lines, start=1):
        if _is_manual_scan_comment_line(target, line):
            continue
        for dep in _extract_powershell_install_module_deps(line, foreach_bindings):
            key = (line_number, "powershell-install-module", dep)
            if key in existing_keys:
                continue
            added.append(_finding(
                target,
                line_number,
                "powershell-install-module",
                dep,
                line,
                Severity.MEDIUM,
                f"PowerShell module installed outside manifest: {dep}",
            ))
            existing_keys.add(key)
    for line_number, dep in wrapper_calls:
        key = (line_number, "powershell-install-module", dep)
        if key in existing_keys:
            continue
        added.append(_finding(
            target,
            line_number,
            "powershell-install-module",
            dep,
            lines[line_number - 1],
            Severity.MEDIUM,
            f"PowerShell module installed outside manifest: {dep}",
        ))
        existing_keys.add(key)
    return added


def _scan_powershell_package_management(
    target: FileTarget,
    lines: list[str],
    existing: list[Finding],
) -> list[Finding]:
    if target.file_type not in set(_UNMANAGED_SCRIPTABLE):
        return []
    existing_keys = {
        (f.line_number, f.pattern_id, f.extracted_dep)
        for f in existing
    }
    added: list[Finding] = []
    specs = (
        (
            "powershell-install-package-provider",
            _extract_powershell_package_provider_deps,
            "PowerShell package provider installed outside manifest",
        ),
        (
            "powershell-install-package",
            _extract_powershell_package_deps,
            "PowerShell PackageManagement package installed outside manifest",
        ),
    )
    for line_number, line in enumerate(lines, start=1):
        if _is_manual_scan_comment_line(target, line) or _looks_like_printed_help(line):
            continue
        for pattern_id, extractor, description_prefix in specs:
            for dep in extractor(line):
                key = (line_number, pattern_id, dep)
                if key in existing_keys:
                    continue
                finding = _finding(
                    target,
                    line_number,
                    pattern_id,
                    dep,
                    line,
                    Severity.MEDIUM,
                    f"{description_prefix}: {dep}",
                )
                if _is_non_executable_metadata_or_list_item(target, finding, lines):
                    continue
                added.append(finding)
                existing_keys.add(key)
    return added


def _normalize_winget_install_findings(
    target: FileTarget,
    lines: list[str],
    findings: list[Finding],
) -> list[Finding]:
    if target.file_type not in set(_UNMANAGED_SCRIPTABLE):
        return findings

    resolved = [
        _finding(
            target,
            line_number,
            "winget-command-install",
            dep,
            lines[line_number - 1],
            Severity.MEDIUM,
            f"winget package installed outside manifest: {dep}",
        )
        for line_number, dep in _powershell_winget_install_deps(lines)
    ]
    filtered = [
        finding for finding in findings
        if not (
            finding.pattern_id == "winget-command-install"
            and _is_unresolved_package_variable(finding.extracted_dep)
        )
    ]
    return filtered + resolved


def _finding(
    target: FileTarget,
    line_number: int,
    pattern_id: str,
    dep: str,
    line: str,
    severity: Severity,
    description: str,
) -> Finding:
    return Finding(
        file_path=target.rel_path,
        line_number=line_number,
        category=Category.UNMANAGED_PACKAGE,
        severity=severity,
        pattern_id=pattern_id,
        matched_text=line.strip()[:200],
        extracted_dep=dep[:200],
        description=description,
        scanner_name=UnmanagedPackageScanner.name,
    )


def _extract_r_call_bodies(line: str, call_pattern: str) -> list[str]:
    bodies: list[str] = []
    for match in re.finditer(call_pattern, line, re.IGNORECASE):
        depth = 1
        quote = ""
        escaped = False
        body: list[str] = []
        for ch in line[match.end():]:
            if quote:
                body.append(ch)
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == quote:
                    quote = ""
                continue
            if ch in {"'", '"'}:
                quote = ch
                body.append(ch)
                continue
            if ch == "(":
                depth += 1
                body.append(ch)
                continue
            if ch == ")":
                depth -= 1
                if depth == 0:
                    bodies.append("".join(body))
                    break
                body.append(ch)
                continue
            body.append(ch)
    return bodies


def _extract_r_install_package_deps(body: str) -> list[str]:
    first_arg = _r_first_argument_body(body)
    return _unique([
        value
        for value in _r_string_literals(first_arg)
        if _is_r_package_name(value)
    ])


def _extract_r_install_github_deps(body: str) -> list[str]:
    first_arg = _r_first_argument_body(body)
    deps: list[str] = []
    for value in _r_string_literals(first_arg):
        dep = value.strip()
        if not _is_r_github_repo_spec(dep):
            continue
        deps.append(dep)
    return _unique(deps)


def _r_first_argument_body(body: str) -> str:
    depth = 0
    quote = ""
    escaped = False
    for index, ch in enumerate(body):
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = ""
            continue
        if ch in {"'", '"'}:
            quote = ch
            continue
        if ch == "(":
            depth += 1
            continue
        if ch == ")":
            depth = max(0, depth - 1)
            continue
        if ch == "," and depth == 0:
            return body[:index]
    return body


def _r_string_literals(text: str) -> list[str]:
    values: list[str] = []
    for match in re.finditer(r"""(?P<quote>['"])(?P<value>(?:\\.|(?!\1).)*?)(?P=quote)""", text):
        values.append(match.group("value"))
    return values


def _is_r_package_name(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z][A-Za-z0-9._-]*", value))


def _is_r_github_repo_spec(value: str) -> bool:
    if re.fullmatch(r"https?://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:[/.#@][^\s'\"`]+)?", value):
        return True
    return bool(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:[@#][^\s'\"`]+)?", value))


def _powershell_foreach_literal_arrays(lines: list[str]) -> dict[str, list[str]]:
    bindings: dict[str, list[str]] = {}
    string_arrays = _powershell_string_array_bindings(lines)
    foreach_array_re = re.compile(
        r"\bforeach\s*\(\s*\$(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s+in\s+@\((?P<body>.*?)\)\s*\)",
        re.IGNORECASE,
    )
    foreach_literal_re = re.compile(
        r"""\bforeach\s*\(\s*\$(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s+in\s+"""
        r"""(?P<body>(?:['"][A-Za-z0-9_.-]+['"]\s*,?\s*)+)\)""",
        re.IGNORECASE,
    )
    foreach_variable_re = re.compile(
        r"\bforeach\s*\(\s*\$(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s+in\s+\$(?P<array>[A-Za-z_][A-Za-z0-9_]*)\s*\)",
        re.IGNORECASE,
    )
    for line in lines:
        for match in foreach_array_re.finditer(line):
            values = _powershell_string_literals(match.group("body"))
            if values:
                bindings[match.group("var").lower()] = values
        for match in foreach_literal_re.finditer(line):
            values = _powershell_string_literals(match.group("body"))
            if values:
                bindings[match.group("var").lower()] = values
        for match in foreach_variable_re.finditer(line):
            values = string_arrays.get(match.group("array").lower())
            if values:
                bindings[match.group("var").lower()] = values
    return bindings


def _powershell_string_array_bindings(lines: list[str]) -> dict[str, list[str]]:
    arrays: dict[str, list[str]] = {}
    inline_re = re.compile(
        r"^\s*\$(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*@\((?P<body>.*?)\)\s*;?\s*$",
        re.IGNORECASE,
    )
    multiline_start_re = re.compile(
        r"^\s*\$(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*@\(\s*$",
        re.IGNORECASE,
    )
    index = 0
    while index < len(lines):
        inline = inline_re.match(lines[index])
        if inline:
            values = _powershell_string_literals(inline.group("body"))
            if values:
                arrays[inline.group("name").lower()] = values
            index += 1
            continue
        start = multiline_start_re.match(lines[index])
        if not start:
            index += 1
            continue
        body: list[str] = []
        index += 1
        while index < len(lines):
            line = lines[index]
            if line.strip().startswith(")"):
                index += 1
                break
            body.append(line)
            index += 1
        values = _powershell_string_literals("\n".join(body))
        if values:
            arrays[start.group("name").lower()] = values
    return arrays


def _powershell_winget_install_deps(lines: list[str]) -> list[tuple[int, str]]:
    scalar_bindings = _powershell_scalar_string_bindings(lines)
    property_bindings = _powershell_foreach_property_bindings(lines)
    wrapper_calls = _powershell_winget_wrapper_calls(lines, scalar_bindings, property_bindings)
    deps: list[tuple[int, str]] = []
    for line_number, line in enumerate(lines, start=1):
        if _is_line_comment_or_blank(line) or _looks_like_printed_help(line):
            continue
        for value in _winget_install_values(line):
            for dep in _resolve_winget_dep_value(value, scalar_bindings, property_bindings):
                deps.append((line_number, dep))
    deps.extend(wrapper_calls)
    return _unique_tuples(deps)


def _winget_install_values(line: str) -> list[str]:
    values: list[str] = []
    for match in re.finditer(r"\bwinget\s+install\b(?P<body>[^#\n;|]*)", line, re.IGNORECASE):
        if _looks_like_printed_help(line[:match.start()]):
            continue
        tokens = _simple_shell_tokens(match.group("body"))
        i = 0
        positional_allowed = True
        while i < len(tokens):
            token = tokens[i].rstrip(",`")
            lower = token.lower()
            value: str | None = None
            name, inline_value = _powershell_named_arg(token)
            if name in {"id", "-id"}:
                if inline_value is not None:
                    value = inline_value
                    i += 1
                elif i + 1 < len(tokens):
                    value = tokens[i + 1].rstrip(",`")
                    i += 2
                else:
                    i += 1
            elif lower in _WINGET_VALUE_FLAGS:
                i += 2
                positional_allowed = False
            elif any(lower.startswith(f"{flag}:") or lower.startswith(f"{flag}=") for flag in _WINGET_VALUE_FLAGS):
                i += 1
                positional_allowed = False
            elif token.startswith("-"):
                i += 1
            elif positional_allowed:
                value = token
                i += 1
                positional_allowed = False
            else:
                i += 1
            if value:
                values.append(value)
    return _unique(values)


_WINGET_VALUE_FLAGS = {
    "-source",
    "--source",
    "-version",
    "--version",
    "-architecture",
    "--architecture",
    "-location",
    "--location",
    "-locale",
    "--locale",
    "-scope",
    "--scope",
    "-override",
    "--override",
    "-log",
    "--log",
}


def _powershell_scalar_string_bindings(lines: list[str]) -> dict[str, str]:
    bindings: dict[str, str] = {}
    assignment_re = re.compile(
        r"""^\s*\$(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<quote>['"])(?P<value>[A-Za-z0-9_.-]+)(?P=quote)\s*;?\s*$"""
    )
    for line in lines:
        match = assignment_re.match(line)
        if match:
            bindings[match.group("name").lower()] = match.group("value")
    return bindings


def _powershell_foreach_property_bindings(lines: list[str]) -> dict[str, list[str]]:
    arrays = _powershell_hashtable_array_values(lines)
    bindings: dict[str, list[str]] = {}
    foreach_re = re.compile(
        r"\bforeach\s*\(\s*\$(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s+in\s+\$(?P<array>[A-Za-z_][A-Za-z0-9_]*)\s*\)",
        re.IGNORECASE,
    )
    for line in lines:
        for match in foreach_re.finditer(line):
            values = arrays.get(match.group("array").lower())
            if not values:
                continue
            foreach_var = match.group("var").lower()
            for property_name, property_values in values.items():
                bindings[f"{foreach_var}.{property_name}"] = property_values
    return bindings


def _powershell_hashtable_array_values(lines: list[str]) -> dict[str, dict[str, list[str]]]:
    arrays: dict[str, dict[str, list[str]]] = {}
    index = 0
    start_re = re.compile(r"^\s*\$(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*@\(\s*$")
    while index < len(lines):
        match = start_re.match(lines[index])
        if not match:
            index += 1
            continue
        name = match.group("name").lower()
        body: list[str] = []
        depth = 1
        index += 1
        while index < len(lines) and depth > 0:
            line = lines[index]
            depth += line.count("@(")
            if line.strip() == ")":
                depth -= 1
                index += 1
                continue
            body.append(line)
            index += 1
        arrays.setdefault(name, {})
        for key, values in _powershell_hashtable_string_values("\n".join(body)).items():
            arrays[name].setdefault(key, [])
            arrays[name][key].extend(value for value in values if value not in arrays[name][key])
    return arrays


def _powershell_hashtable_string_values(body: str) -> dict[str, list[str]]:
    values: dict[str, list[str]] = {}
    for table in re.finditer(r"@\{(?P<body>.*?)\}", body, re.DOTALL):
        for entry in re.finditer(
            r"""(?P<key>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<quote>['"])(?P<value>[A-Za-z0-9_.-]+)(?P=quote)""",
            table.group("body"),
        ):
            key = entry.group("key").lower()
            values.setdefault(key, [])
            value = entry.group("value")
            if value not in values[key]:
                values[key].append(value)
    return values


def _resolve_winget_dep_value(
    value: str,
    scalar_bindings: dict[str, str],
    property_bindings: dict[str, list[str]],
) -> list[str]:
    value = value.strip("'\"`")
    member = re.fullmatch(r"\$(?P<name>[A-Za-z_][A-Za-z0-9_]*)\.(?P<property>[A-Za-z_][A-Za-z0-9_]*)", value)
    if member:
        return property_bindings.get(f"{member.group('name').lower()}.{member.group('property').lower()}", [])
    variable = re.fullmatch(r"\$(?P<name>[A-Za-z_][A-Za-z0-9_]*)", value)
    if variable:
        dep = scalar_bindings.get(variable.group("name").lower())
        return [dep] if dep and _is_winget_package_id(dep) else []
    if _is_winget_package_id(value):
        return [value]
    return []


def _powershell_winget_wrapper_calls(
    lines: list[str],
    scalar_bindings: dict[str, str],
    property_bindings: dict[str, list[str]],
) -> list[tuple[int, str]]:
    wrappers, function_ranges = _powershell_winget_wrappers(lines)
    if not wrappers:
        return []
    calls: list[tuple[int, str]] = []
    for line_number, line in enumerate(lines, start=1):
        if any(start <= line_number <= end for start, end in function_ranges):
            continue
        if _is_line_comment_or_blank(line) or _looks_like_printed_help(line):
            continue
        for function_name, package_params in wrappers.items():
            for dep in _extract_powershell_winget_wrapper_call_deps(
                line,
                function_name,
                package_params,
                scalar_bindings,
                property_bindings,
            ):
                calls.append((line_number, dep))
    return _unique_tuples(calls)


def _powershell_winget_wrappers(lines: list[str]) -> tuple[dict[str, set[str]], list[tuple[int, int]]]:
    wrappers: dict[str, set[str]] = {}
    ranges: list[tuple[int, int]] = []
    for name, start, end, body in _powershell_function_blocks(lines):
        package_params: set[str] = set()
        for line in body:
            for value in _winget_install_values(line):
                for variable in re.finditer(r"\$(?P<name>[A-Za-z_][A-Za-z0-9_]*)", value):
                    package_params.add(variable.group("name").lower())
        if package_params:
            wrappers[name.lower()] = package_params
            ranges.append((start, end))
    return wrappers, ranges


def _extract_powershell_winget_wrapper_call_deps(
    line: str,
    function_name: str,
    package_params: set[str],
    scalar_bindings: dict[str, str],
    property_bindings: dict[str, list[str]],
) -> list[str]:
    tokens = _simple_shell_tokens(line)
    if not tokens:
        return []
    command_index = 1 if tokens[0] in {"&", "."} else 0
    if command_index >= len(tokens):
        return []
    command = tokens[command_index].strip("&.").lower()
    if command != function_name:
        return []

    deps: list[str] = []
    i = command_index + 1
    positional_allowed = len(package_params) == 1
    while i < len(tokens):
        token = tokens[i].rstrip(",;")
        if token.startswith("-"):
            name, inline_value = _powershell_named_arg(token)
            if name in package_params:
                if inline_value is not None:
                    values = [inline_value]
                    i += 1
                elif i + 1 < len(tokens):
                    values = [tokens[i + 1].rstrip(",;")]
                    i += 2
                else:
                    values = []
                    i += 1
            else:
                values = []
                i += 1
        elif positional_allowed:
            values = [token]
            i += 1
            positional_allowed = False
        else:
            values = []
            i += 1
        for value in values:
            deps.extend(_resolve_winget_dep_value(value, scalar_bindings, property_bindings))
    return _unique(deps)


def _is_winget_package_id(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*(?:\.[A-Za-z0-9][A-Za-z0-9_-]*)+", value))


def _is_unresolved_package_variable(dep: str) -> bool:
    dep = dep.strip()
    return bool(
        re.fullmatch(r"\$[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?", dep)
        or re.fullmatch(r"\$\{[A-Za-z_][A-Za-z0-9_]*\}", dep)
    )


def _extract_powershell_install_module_deps(
    line: str,
    foreach_bindings: dict[str, list[str]] | None = None,
) -> list[str]:
    deps: list[str] = []
    for value in _powershell_install_module_values(line):
        deps.extend(_resolve_powershell_module_dep(value, foreach_bindings or {}))
    return _unique(deps)


def _powershell_install_module_values(line: str) -> list[str]:
    values: list[str] = []
    command_re = re.compile(
        r"\b(?:Install-Module|Install-PSResource|Save-Module|Save-PSResource)\b(?P<body>[^#\n;|]*)",
        re.IGNORECASE,
    )
    for match in command_re.finditer(line):
        if _command_match_is_inert_quoted_string(line, match.start()):
            continue
        if _looks_like_printed_help(line[:match.start()]):
            continue
        tokens = _simple_shell_tokens(match.group("body"))
        i = 0
        positional_allowed = True
        while i < len(tokens):
            raw_token = tokens[i]
            token = raw_token.rstrip(",")
            lower = token.lower()
            value: str | None = None
            if lower in {"-name", "-fullyqualifiedname"} and i + 1 < len(tokens):
                value = tokens[i + 1].rstrip(",")
                i += 2
            elif lower.startswith("-name:") or lower.startswith("-name="):
                value = token.split(":", 1)[1] if ":" in token else token.split("=", 1)[1]
                i += 1
            elif lower.startswith("-fullyqualifiedname:") or lower.startswith("-fullyqualifiedname="):
                value = token.split(":", 1)[1] if ":" in token else token.split("=", 1)[1]
                i += 1
            elif lower in _POWERSHELL_INSTALL_MODULE_VALUE_FLAGS:
                i += 2
                positional_allowed = False
            elif lower.startswith(tuple(f"{flag}:" for flag in _POWERSHELL_INSTALL_MODULE_VALUE_FLAGS)) or lower.startswith(tuple(f"{flag}=" for flag in _POWERSHELL_INSTALL_MODULE_VALUE_FLAGS)):
                i += 1
                positional_allowed = False
            elif token.startswith("-"):
                i += 1
                positional_allowed = False
            elif positional_allowed:
                value = token
                i += 1
            else:
                i += 1
            if value:
                values.extend(_powershell_module_name_values(value))
                positional_allowed = raw_token.endswith(",")
    return _unique(values)


def _command_match_is_inert_quoted_string(line: str, match_start: int) -> bool:
    prefix = line[:match_start].strip()
    if _POWERSHELL_EXECUTION_PREFIX_RE.search(prefix):
        return False
    quote_start = _unclosed_quote_start(line, match_start)
    if quote_start is not None:
        before_quote = line[:quote_start].strip()
        if re.search(r"(?:^|\s)(?:-[A-Za-z]*c|/c|--command)\s*$", before_quote, re.IGNORECASE):
            return False
        if re.search(r"&\s*$", before_quote):
            return False
        return True
    if not prefix:
        return False
    if re.search(r"[&|;]\s*$", prefix):
        return False
    if prefix in {"'", '"'}:
        return True
    if re.fullmatch(r"\$[A-Za-z_][A-Za-z0-9_]*\s*=\s*['\"]", prefix):
        return True
    return False


_POWERSHELL_EXECUTION_PREFIX_RE = re.compile(
    r"(?<![\w.-])(?:iex|Invoke-Expression|powershell(?:\.exe)?|pwsh(?:\.exe)?)(?![\w.-])",
    re.IGNORECASE,
)


def _unclosed_quote_start(line: str, end: int) -> int | None:
    quote: str | None = None
    quote_start: int | None = None
    index = 0
    while index < end:
        char = line[index]
        if quote is None:
            if char in {"'", '"'}:
                quote = char
                quote_start = index
        elif char == "`" and quote == '"':
            index += 1
        elif char == quote:
            if quote == "'" and index + 1 < end and line[index + 1] == "'":
                index += 1
            else:
                quote = None
                quote_start = None
        index += 1
    return quote_start


_POWERSHELL_INSTALL_MODULE_VALUE_FLAGS = {
    "-credential",
    "-destinationpath",
    "-erroraction",
    "-informationaction",
    "-maximumversion",
    "-minimumversion",
    "-path",
    "-proxy",
    "-proxycredential",
    "-repository",
    "-requiredversion",
    "-scope",
    "-version",
    "-warningaction",
}


def _powershell_module_name_values(value: str) -> list[str]:
    return [
        part.strip().strip("'\"").rstrip(",")
        for part in value.split(",")
        if part.strip().strip("'\"").rstrip(",")
    ]


def _resolve_powershell_module_dep(value: str, foreach_bindings: dict[str, list[str]]) -> list[str]:
    value = value.strip("'\"")
    variable = re.fullmatch(r"\$(?P<name>[A-Za-z_][A-Za-z0-9_]*)", value)
    if variable:
        return foreach_bindings.get(variable.group("name").lower(), [])
    if _is_powershell_module_name(value):
        return [value]
    return []


def _extract_powershell_package_provider_deps(line: str) -> list[str]:
    deps: list[str] = []
    command_re = re.compile(r"\bInstall-PackageProvider\b(?P<body>[^#\n;|]*)", re.IGNORECASE)
    for match in command_re.finditer(line):
        if _command_match_is_inert_quoted_string(line, match.start()):
            continue
        if _looks_like_printed_help(line[:match.start()]):
            continue
        values = _powershell_command_name_values(match.group("body"), require_package_source_flag=False)
        deps.extend(value for value in values if _is_powershell_package_dep(value))
    return _unique(deps)


def _extract_powershell_package_deps(line: str) -> list[str]:
    deps: list[str] = []
    command_re = re.compile(r"\bInstall-Package\b(?P<body>[^#\n;|]*)", re.IGNORECASE)
    for match in command_re.finditer(line):
        if _command_match_is_inert_quoted_string(line, match.start()):
            continue
        if _looks_like_printed_help(line[:match.start()]):
            continue
        values = _powershell_command_name_values(match.group("body"), require_package_source_flag=True)
        deps.extend(value for value in values if _is_powershell_package_dep(value))
    return _unique(deps)


def _powershell_command_name_values(body: str, *, require_package_source_flag: bool) -> list[str]:
    tokens = _simple_shell_tokens(body)
    values: list[str] = []
    positional_allowed = True
    saw_package_source_flag = not require_package_source_flag
    i = 0
    while i < len(tokens):
        raw_token = tokens[i]
        token = raw_token.rstrip(",")
        lower = token.lower()
        value: str | None = None
        if lower in {"-name"} and i + 1 < len(tokens):
            value = tokens[i + 1].rstrip(",")
            i += 2
        elif lower.startswith("-name:") or lower.startswith("-name="):
            value = token.split(":", 1)[1] if ":" in token else token.split("=", 1)[1]
            i += 1
        elif lower in _POWERSHELL_PACKAGE_MANAGEMENT_SOURCE_FLAGS:
            saw_package_source_flag = True
            i += 2
            positional_allowed = False
        elif lower.startswith(tuple(f"{flag}:" for flag in _POWERSHELL_PACKAGE_MANAGEMENT_SOURCE_FLAGS)) or lower.startswith(tuple(f"{flag}=" for flag in _POWERSHELL_PACKAGE_MANAGEMENT_SOURCE_FLAGS)):
            saw_package_source_flag = True
            i += 1
            positional_allowed = False
        elif lower in _POWERSHELL_PACKAGE_MANAGEMENT_VALUE_FLAGS:
            i += 2
            positional_allowed = False
        elif lower.startswith(tuple(f"{flag}:" for flag in _POWERSHELL_PACKAGE_MANAGEMENT_VALUE_FLAGS)) or lower.startswith(tuple(f"{flag}=" for flag in _POWERSHELL_PACKAGE_MANAGEMENT_VALUE_FLAGS)):
            i += 1
            positional_allowed = False
        elif token.startswith("-"):
            i += 1
            positional_allowed = False
        elif positional_allowed:
            value = token
            i += 1
        else:
            i += 1
        if value:
            values.extend(_powershell_module_name_values(value))
            positional_allowed = raw_token.endswith(",")
    return _unique(values) if saw_package_source_flag else []


_POWERSHELL_PACKAGE_MANAGEMENT_SOURCE_FLAGS = {
    "-providername",
    "-source",
}


_POWERSHELL_PACKAGE_MANAGEMENT_VALUE_FLAGS = {
    "-credential",
    "-destination",
    "-erroraction",
    "-informationaction",
    "-maximumversion",
    "-minimumversion",
    "-proxy",
    "-proxycredential",
    "-requiredversion",
    "-scope",
    "-warningaction",
}


def _is_powershell_package_dep(value: str) -> bool:
    value = value.strip("'\"")
    if not value or value.startswith(("-", "$", "%", ".", "/", "\\")):
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*(?:\[[A-Za-z0-9_,.-]+\])?", value))


def _powershell_install_module_wrapper_calls(lines: list[str]) -> list[tuple[int, str]]:
    wrappers, function_ranges = _powershell_install_module_wrappers(lines)
    if not wrappers:
        return []

    calls: list[tuple[int, str]] = []
    for line_number, line in enumerate(lines, start=1):
        if any(start <= line_number <= end for start, end in function_ranges):
            continue
        if _is_line_comment_or_blank(line) or _looks_like_printed_help(line):
            continue
        for function_name, module_params in wrappers.items():
            for dep in _extract_powershell_wrapper_call_deps(line, function_name, module_params):
                calls.append((line_number, dep))
    return _unique_tuples(calls)


def _powershell_install_module_wrappers(lines: list[str]) -> tuple[dict[str, set[str]], list[tuple[int, int]]]:
    wrappers: dict[str, set[str]] = {}
    ranges: list[tuple[int, int]] = []
    for name, start, end, body in _powershell_function_blocks(lines):
        module_params: set[str] = set()
        for line in body:
            for value in _powershell_install_module_values(line):
                variable = re.fullmatch(r"\$(?P<name>[A-Za-z_][A-Za-z0-9_]*)", value.strip("'\""))
                if variable:
                    module_params.add(variable.group("name").lower())
        if module_params:
            wrappers[name.lower()] = module_params
            ranges.append((start, end))
    return wrappers, ranges


def _powershell_function_blocks(lines: list[str]) -> list[tuple[str, int, int, list[str]]]:
    blocks: list[tuple[str, int, int, list[str]]] = []
    function_re = re.compile(r"^\s*function\s+(?P<name>[A-Za-z_][A-Za-z0-9_-]*)\b", re.IGNORECASE)
    index = 0
    while index < len(lines):
        match = function_re.match(lines[index])
        if not match:
            index += 1
            continue
        start = index + 1
        end = start
        body = [lines[index]]
        depth = _powershell_brace_delta(lines[index])
        seen_open = "{" in lines[index]
        cursor = index
        while cursor + 1 < len(lines):
            if seen_open and depth <= 0:
                break
            cursor += 1
            body.append(lines[cursor])
            if "{" in lines[cursor]:
                seen_open = True
            depth += _powershell_brace_delta(lines[cursor])
            end = cursor + 1
            if seen_open and depth <= 0:
                break
        blocks.append((match.group("name"), start, end, body))
        index = max(cursor + 1, index + 1)
    return blocks


def _powershell_brace_delta(line: str) -> int:
    quote = ""
    delta = 0
    for ch in line:
        if quote:
            if ch == quote:
                quote = ""
            continue
        if ch in {"'", '"'}:
            quote = ch
        elif ch == "{":
            delta += 1
        elif ch == "}":
            delta -= 1
    return delta


def _extract_powershell_wrapper_call_deps(
    line: str,
    function_name: str,
    module_params: set[str],
) -> list[str]:
    tokens = _simple_shell_tokens(line)
    if not tokens:
        return []
    command_index = 1 if tokens[0] in {"&", "."} else 0
    if command_index >= len(tokens):
        return []
    command = tokens[command_index].strip("&.").lower()
    if command != function_name:
        return []

    deps: list[str] = []
    i = command_index + 1
    positional_allowed = len(module_params) == 1
    while i < len(tokens):
        token = tokens[i].rstrip(",;")
        lower = token.lower()
        value: str | None = None
        if lower.startswith("-"):
            name, inline_value = _powershell_named_arg(token)
            if name in module_params:
                if inline_value is not None:
                    value = inline_value
                    i += 1
                elif i + 1 < len(tokens):
                    value = tokens[i + 1].rstrip(",;")
                    i += 2
                else:
                    i += 1
            else:
                i += 1
        elif positional_allowed:
            value = token
            i += 1
            positional_allowed = False
        else:
            i += 1
        if value:
            dep = value.strip("'\"")
            if _is_powershell_module_name(dep):
                deps.append(dep)
    return _unique(deps)


def _powershell_named_arg(token: str) -> tuple[str, str | None]:
    token = token.lstrip("-")
    for sep in (":", "="):
        if sep in token:
            name, value = token.split(sep, 1)
            return name.lower(), value.strip("'\"")
    return token.lower(), None


def _is_line_comment_or_blank(line: str) -> bool:
    stripped = line.strip()
    return not stripped or stripped.startswith("#")


def _unique_tuples(values: list[tuple[int, str]]) -> list[tuple[int, str]]:
    seen: set[tuple[int, str]] = set()
    out: list[tuple[int, str]] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def _powershell_string_literals(text: str) -> list[str]:
    return [
        match.group("value")
        for match in re.finditer(r"""['"](?P<value>[A-Za-z0-9_.-]+)['"]""", text)
    ]


def _is_powershell_module_name(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]*", value))


def _extract_pip_install_deps(line: str) -> list[str]:
    deps: list[str] = []
    for match in re.finditer(r"\bpip3?\s+install\s+(?P<body>[^;&|\n]*)", line, re.IGNORECASE):
        if _pip_match_is_printed_hint(line, match.start()):
            continue
        deps.extend(_extract_pip_install_body_deps(match.group("body")))
    return _unique(deps)


def _extract_uv_pip_install_deps(line: str) -> list[str]:
    deps: list[str] = []
    for match in re.finditer(r"\buv\s+pip\s+install\s+(?P<body>[^;&|\n]*)", line, re.IGNORECASE):
        if _pip_match_is_printed_hint(line, match.start()):
            continue
        deps.extend(_extract_pip_install_body_deps(match.group("body")))
    return _unique(deps)


def _extract_uv_tool_install_deps(line: str) -> list[str]:
    deps: list[str] = []
    for match in re.finditer(r"\buv\s+tool\s+(?:install|run)\s+(?P<body>[^;&|\n]*)", line, re.IGNORECASE):
        if _pip_match_is_printed_hint(line, match.start()):
            continue
        tokens = _merge_github_expression_tokens(_simple_shell_tokens(_trim_pip_install_body(match.group("body"))))
        if _uv_tool_install_uses_local_from(tokens):
            continue
        i = 0
        while i < len(tokens):
            token = tokens[i].rstrip(",;\\\"'")
            next_i = _skip_uv_tool_option(tokens, i)
            if next_i != i:
                i = next_i
                continue
            if _is_uv_tool_package_token(token):
                deps.append(token)
            break
    return _unique(deps)


def _skip_uv_tool_option(tokens: list[str], index: int) -> int:
    token = tokens[index].rstrip(",")
    name = token.split("=", 1)[0]
    if name in {
        "--config-setting",
        "--constraint",
        "--default-index",
        "--extra-index-url",
        "--from",
        "--index",
        "--index-url",
        "--keyring-provider",
        "--python",
        "--refresh-package",
        "--with",
        "--with-editable",
        "--with-requirements",
        "-c",
        "-p",
        "-r",
    }:
        return index + 1 if "=" in token else min(index + 2, len(tokens))
    if token.startswith("-"):
        return index + 1
    return index


def _uv_tool_install_uses_local_from(tokens: list[str]) -> bool:
    for index, token in enumerate(tokens):
        token = token.rstrip(",")
        name, sep, inline_value = token.partition("=")
        if name != "--from":
            continue
        value = inline_value if sep else (tokens[index + 1] if index + 1 < len(tokens) else "")
        value = value.strip("'\"")
        if value == "." or value.startswith(("./", "../", "$PWD", "${PWD}")):
            return True
    return False


def _is_uv_tool_package_token(token: str) -> bool:
    if "..." in token:
        return False
    if token.lower() in _UV_TOOL_PROSE_DEPS:
        return False
    if token.startswith("git+https://"):
        return True
    if token.startswith(("http://", "https://", "git+", "file:")):
        return False
    return _is_pip_package_token(token)


def _extract_pip_install_body_deps(body: str) -> list[str]:
    deps: list[str] = []
    tokens = _simple_shell_tokens(_collapse_github_expressions(_trim_pip_install_body(body)))
    if _pip_install_uses_local_no_index(tokens):
        return []
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if token.startswith(("--requirement=", "--editable=", "--constraint=")):
            i += 1
            continue
        if token in {"-r", "--requirement", "-e", "--editable", "-c", "--constraint"}:
            i = _skip_pip_value_option(tokens, i)
            continue
        if token.startswith((
            "--index-strategy=", "--keyring-provider=", "--link-mode=", "--prerelease=",
            "--project=", "--python=", "--torch-backend=",
        )):
            i += 1
            continue
        if token in {
            "--index-strategy", "--keyring-provider", "--link-mode", "--prerelease",
            "--project", "--python", "--torch-backend",
        }:
            i += 2
            continue
        if token.startswith("--find-links=") or token.startswith("-f="):
            i += 1
            continue
        if token in {"--find-links", "-f"}:
            i += 2
            continue
        if token.startswith("--index-url") or token.startswith("--extra-index-url"):
            i += 1 if "=" in token else 2
            continue
        if token.startswith("-"):
            i += 1
            continue
        if not deps and _is_malformed_pip_install_leading_token(token):
            return []
        if _is_pip_package_token(token):
            deps.append(token)
        i += 1
    return _unique(deps)


def _extract_pip_custom_indexes(line: str) -> list[str]:
    deps: list[str] = []
    for match in re.finditer(r"(?:\buv\s+)?\bpip3?\s+install\s+(?P<body>[^;&|\n]*)", line, re.IGNORECASE):
        tokens = _simple_shell_tokens(_collapse_github_expressions(_trim_pip_install_body(match.group("body"))))
        i = 0
        while i < len(tokens):
            token = tokens[i].rstrip(",")
            name, sep, inline_value = token.partition("=")
            if name in {"--index-url", "--extra-index-url", "--index", "--default-index", "-i"}:
                value = inline_value if sep else (tokens[i + 1] if i + 1 < len(tokens) else "")
                dep = _clean_pip_index_url(value)
                if _is_pip_index_url(dep):
                    deps.append(dep)
                i += 1 if sep else 2
                continue
            i += 1
    return _unique(deps)


def _pip_install_continuation_line(lines: list[str] | None, line_number: int, fallback: str = "") -> str:
    if lines is None or not (0 < line_number <= len(lines)):
        return fallback
    parts: list[str] = []
    index = line_number - 1
    while index < len(lines) and len(parts) < 12:
        current = lines[index].strip()
        continued = current.endswith("\\")
        current_part = current[:-1].rstrip() if continued else current
        parts.append(current_part)
        if not continued:
            break
        next_index = index + 1
        if re.search(r"(?:&&|\|\||[;|])\s*$", current_part):
            break
        if next_index < len(lines) and re.match(r"\s*(?:&&|\|\||[;|])\s*", lines[next_index]):
            break
        index = next_index
    return " ".join(parts)


def _pip_index_continuation_line(lines: list[str] | None, line_number: int, fallback: str = "") -> str:
    return _pip_install_continuation_line(lines, line_number, fallback)


def _clean_pip_index_url(value: str) -> str:
    return value.strip().strip("'\"").rstrip(",;\\")


def _is_pip_index_url(value: str) -> bool:
    return bool(re.fullmatch(r"https?://[^\s'\";]+", value))


def _pip_install_uses_local_no_index(tokens: list[str]) -> bool:
    if "--no-index" not in tokens:
        return False
    external_find_links = False
    i = 0
    while i < len(tokens):
        token = tokens[i]
        value: str | None = None
        if token.startswith("--find-links=") or token.startswith("-f="):
            value = token.split("=", 1)[1]
        elif token in {"--find-links", "-f"} and i + 1 < len(tokens):
            value = tokens[i + 1]
            i += 1
        if value and value.startswith(("http://", "https://")):
            external_find_links = True
            break
        i += 1
    return not external_find_links


def _skip_pip_value_option(tokens: list[str], index: int) -> int:
    value_index = index + 1
    if value_index >= len(tokens):
        return value_index
    value = tokens[value_index]
    if value == "${{" or (value.startswith("${{") and "}}" not in value):
        return _skip_github_expression_value(tokens, value_index + 1)
    return value_index + 1


def _is_malformed_pip_install_leading_token(token: str) -> bool:
    token = token.rstrip(",")
    if token in {"+", "=", ":", ")"}:
        return True
    return ")" in token


def _trim_pip_install_body(body: str) -> str:
    body = re.split(r"\s+#", body, maxsplit=1)[0]
    body = _trim_shell_redirection(body)
    body = re.split(r"\s+\(", body, maxsplit=1)[0]
    body = _trim_after_unmatched_body_quote(body)
    if "`" in body:
        body = body.split("`", 1)[0]
    return body


def _trim_after_unmatched_body_quote(body: str) -> str:
    for index, char in enumerate(body):
        if char not in {"'", '"'}:
            continue
        if body[:index].count(char) != 0:
            continue
        if index > 0 and not body[index - 1].isspace() and (
            index + 1 == len(body) or body[index + 1].isspace()
        ):
            return body[:index]
    return body


def _pip_match_is_printed_hint(line: str, match_start: int) -> bool:
    prefix = line[:match_start]
    segment = re.split(r"(?:&&|\|\||[;|{}])", prefix)[-1]
    if "$(" in segment or "`" in segment:
        return False
    return _looks_like_printed_help(segment)


def _is_markdown_inline_pip_install_prose(line: str) -> bool:
    if re.search(
        r"\bpip3?\s+install\s+"
        r"(?:command|commands|packages?|targets?|runs?|uses?|use|is|are|with|of|literal|registered|failing|fails?)\b",
        line,
        re.IGNORECASE,
    ):
        return True
    for match in re.finditer(r"`\s*(?:python3?\s+-m\s+)?pip3?\s+install\b[^`]*`", line, re.IGNORECASE):
        prefix = line[:match.start()].strip()
        if not prefix:
            return False
        if re.fullmatch(r"(?:[-*]\s*)?(?:\d+\.\s*)?(?:run|execute|type|enter|use)\s*:?", prefix, re.IGNORECASE):
            return False
        if re.fullmatch(r"\|(?:[^|]*\|)+\s*", prefix):
            return False
        return True
    return False


def _extract_system_package_install_deps(line: str) -> list[str]:
    deps: list[str] = []
    for match in re.finditer(_SYSTEM_PACKAGE_COMMAND_RE + r"\s+(?P<body>[^;&|\n]*)", line, re.IGNORECASE):
        body = _collapse_github_expressions(_trim_system_package_install_body(match.group("body")))
        tokens = _simple_shell_tokens(body)
        install_deps: list[str] = []
        i = 0
        while i < len(tokens):
            token = tokens[i].rstrip(",")
            next_i = _skip_system_package_option(tokens, i)
            if next_i != i:
                i = next_i
                continue
            if token.startswith("-"):
                i += 1
                continue
            if _is_system_package_token(token):
                install_deps.append(token)
            i += 1
        deps.extend(install_deps)
    return _unique(deps)


def _extract_conda_custom_channels(line: str) -> list[str]:
    deps: list[str] = []
    for match in _CONDA_CUSTOM_CHANNEL_COMMAND_RE.finditer(line):
        body = re.split(r"(?:&&|\|\||[;|])", line[match.end():], maxsplit=1)[0]
        body = re.split(r"\s+#", body, maxsplit=1)[0]
        body = _trim_shell_redirection(body)
        if "`" in body:
            body = body.split("`", 1)[0]
        tokens = _merge_github_expression_tokens(_simple_shell_tokens(body))
        i = 0
        while i < len(tokens):
            token = tokens[i].rstrip(",")
            if token == "--":
                break
            if token in {"-c", "--channel"}:
                if i + 1 < len(tokens):
                    channel = _clean_conda_channel(tokens[i + 1])
                    if _is_conda_custom_channel(channel):
                        deps.append(channel)
                i += 2
                continue
            if token.startswith("-c=") or token.startswith("--channel="):
                channel = _clean_conda_channel(token.split("=", 1)[1])
                if _is_conda_custom_channel(channel):
                    deps.append(channel)
                i += 1
                continue
            if token.startswith("-c") and len(token) > 2 and not token.startswith("--"):
                channel = _clean_conda_channel(token[2:])
                if _is_conda_custom_channel(channel):
                    deps.append(channel)
            i += 1
    return _unique(deps)


def _conda_continuation_line(lines: list[str] | None, line_number: int, fallback: str = "") -> str:
    if lines is None or not (0 < line_number <= len(lines)):
        return fallback
    parts: list[str] = []
    index = line_number - 1
    while index < len(lines) and len(parts) < 8:
        current = lines[index].strip()
        continued = current.endswith("\\")
        parts.append(current[:-1].rstrip() if continued else current)
        if not continued:
            break
        index += 1
    return " ".join(parts)


def _clean_conda_channel(channel: str) -> str:
    return channel.strip().strip("'\"").rstrip(",;\\")


def _is_conda_custom_channel(channel: str) -> bool:
    if not channel or channel.startswith(("$", "%", "@", "-", ".", "/", "\\")):
        return False
    if any(ch in channel for ch in "*{}[]"):
        return False
    lower = channel.lower().rstrip("/")
    if lower in {"defaults", "default", "main", "r", "local"}:
        return False
    if lower.startswith(("http://repo.anaconda.com/", "https://repo.anaconda.com/", "file:")):
        return False
    if lower.startswith(("http://", "https://")):
        return bool(re.fullmatch(r"https?://[A-Za-z0-9._~:/?#@!$&'()*+,;=%-]+", channel))
    return bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*(?:/[A-Za-z0-9][A-Za-z0-9_.-]*)*", channel))


def _extract_gem_install_deps(line: str) -> list[str]:
    deps: list[str] = []
    for match in re.finditer(r"\bgem\s+install\s+(?P<body>[^;&|\n]*)", line, re.IGNORECASE):
        if _pip_match_is_printed_hint(line, match.start()):
            continue
        body = _trim_shell_redirection(match.group("body"))
        if "`" in body:
            body = body.split("`", 1)[0]
        tokens = _simple_shell_tokens(body)
        i = 0
        while i < len(tokens):
            token = tokens[i].rstrip(",")
            next_i = _skip_gem_install_option(tokens, i)
            if next_i != i:
                i = next_i
                continue
            if _is_gem_package_token(token):
                deps.append(token)
            i += 1
    return _unique(deps)


_GEM_INSTALL_VALUE_FLAGS = {
    "--bindir",
    "--document",
    "--env-shebang",
    "--format-executable",
    "--http-proxy",
    "--install-dir",
    "--platform",
    "--source",
    "--trust-policy",
    "--version",
    "-i",
    "-n",
    "-p",
    "-P",
    "-s",
    "-v",
}


def _skip_gem_install_option(tokens: list[str], index: int) -> int:
    token = tokens[index].rstrip(",")
    name = token.split("=", 1)[0]
    if name in _GEM_INSTALL_VALUE_FLAGS:
        return index + 1 if "=" in token else min(index + 2, len(tokens))
    if token.startswith("-"):
        return index + 1
    return index


def _is_gem_package_token(token: str) -> bool:
    if not token or token.startswith(("$", "@", "%", "-", ".", "/", "\\")):
        return False
    if token.startswith(("http://", "https://", "git+")):
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", token))


def _extract_brew_install_deps(line: str) -> list[str]:
    deps: list[str] = []
    for match in re.finditer(r"\bbrew\s+install\s+(?P<body>[^;&|\n]*)", line, re.IGNORECASE):
        if _is_brew_install_hint_prefix(line[:match.start()]):
            continue
        body = _trim_brew_install_body(match.group("body"))
        tokens = _simple_shell_tokens(body)
        for token in tokens:
            dep = token.rstrip(",")
            if not dep or dep.startswith("-"):
                continue
            if re.fullmatch(r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|[\w@/.-]+", dep):
                deps.append(dep)
    return _unique(deps)


def _extract_brew_tap_deps(line: str) -> list[str]:
    deps: list[str] = []
    for match in re.finditer(r"\bbrew\s+tap\s+(?P<body>[^;&|\n]*)", line, re.IGNORECASE):
        if _is_brew_install_hint_prefix(line[:match.start()]):
            continue
        body = _trim_brew_install_body(match.group("body"))
        tokens = _simple_shell_tokens(body)
        for token in tokens:
            dep = token.rstrip(",")
            if not dep or dep.startswith("-"):
                continue
            if re.fullmatch(r"[\w.-]+/[\w.-]+|https?://[^\s'\";]+", dep):
                deps.append(dep)
                break
    return _unique(deps)


def _extract_azure_cli_extension_deps(line: str) -> list[str]:
    return _unique([
        dep
        for dep in _azure_cli_extension_values(line)
        if _is_azure_cli_extension_dep(dep)
    ])


def _azure_cli_extension_values(line: str) -> list[str]:
    values: list[str] = []
    for match in re.finditer(_AZURE_CLI_EXTENSION_COMMAND_RE + r"(?P<body>[^;&|\n]*)", line, re.IGNORECASE):
        body = re.split(r"\s+#", match.group("body"), maxsplit=1)[0]
        body = _trim_shell_redirection(body)
        tokens = _simple_shell_tokens(body)
        i = 0
        while i < len(tokens):
            token = tokens[i].rstrip(",")
            value = ""
            if token.startswith("--name="):
                value = token.split("=", 1)[1]
            elif token in {"--name", "-n"} and i + 1 < len(tokens):
                value = tokens[i + 1].rstrip(",")
            if value:
                values.append(value.strip("'\""))
                break
            i += 1
    return _unique(values)


def _powershell_psitem_azure_cli_extension_deps(lines: list[str]) -> list[tuple[int, str]]:
    deps: list[tuple[int, str]] = []
    for index, line in enumerate(lines):
        if "@(" not in line or "|" not in line:
            continue
        values = [
            value
            for value in _powershell_string_literals(line)
            if _is_azure_cli_extension_dep(value)
        ]
        if not values:
            continue
        for offset, current in enumerate(lines[index:min(len(lines), index + 8)], start=0):
            if not re.search(_AZURE_CLI_EXTENSION_COMMAND_RE, current, re.IGNORECASE):
                continue
            if not any(value in {"$PSItem", "$_"} for value in _azure_cli_extension_values(current)):
                continue
            line_number = index + offset + 1
            deps.extend((line_number, value) for value in values)
            break
    return _unique_tuples(deps)


def _shell_azure_cli_extension_wrapper_calls(lines: list[str]) -> list[tuple[int, str]]:
    wrappers, function_ranges = _shell_azure_cli_extension_wrappers(lines)
    if not wrappers:
        return []
    calls: list[tuple[int, str]] = []
    for line_number, line in enumerate(lines, start=1):
        if any(start <= line_number <= end for start, end in function_ranges):
            continue
        if _is_line_comment_or_blank(line) or _looks_like_printed_help(line):
            continue
        tokens = _simple_shell_tokens(line)
        if not tokens:
            continue
        command = tokens[0].lower()
        if command not in wrappers or len(tokens) < 2:
            continue
        dep = tokens[1].rstrip(",;")
        if _is_azure_cli_extension_dep(dep):
            calls.append((line_number, dep))
    return _unique_tuples(calls)


def _shell_azure_cli_extension_wrappers(lines: list[str]) -> tuple[set[str], list[tuple[int, int]]]:
    wrappers: set[str] = set()
    ranges: list[tuple[int, int]] = []
    for name, start, end, body in _shell_function_blocks(lines):
        positional_vars = _shell_first_arg_bindings(body)
        if not positional_vars:
            continue
        for line in body:
            for value in _azure_cli_extension_values(line):
                variable = _shell_variable_name(value)
                if variable and variable in positional_vars:
                    wrappers.add(name.lower())
                    ranges.append((start, end))
                    break
            if name.lower() in wrappers:
                break
    return wrappers, ranges


def _shell_function_blocks(lines: list[str]) -> list[tuple[str, int, int, list[str]]]:
    blocks: list[tuple[str, int, int, list[str]]] = []
    start_re = re.compile(
        r"^\s*(?:function\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_-]*)\s*(?:\(\))?\s*\{"
    )
    index = 0
    while index < len(lines):
        match = start_re.match(lines[index])
        if not match:
            index += 1
            continue
        start = index + 1
        body = [lines[index]]
        depth = _shell_brace_delta(lines[index])
        cursor = index
        while cursor + 1 < len(lines) and depth > 0:
            cursor += 1
            body.append(lines[cursor])
            depth += _shell_brace_delta(lines[cursor])
        end = cursor + 1
        blocks.append((match.group("name"), start, end, body))
        index = max(cursor + 1, index + 1)
    return blocks


def _shell_brace_delta(line: str) -> int:
    without_expansions = re.sub(r"\$\{[^}]*\}", "", line)
    quote = ""
    delta = 0
    for ch in without_expansions:
        if quote:
            if ch == quote:
                quote = ""
            continue
        if ch in {"'", '"'}:
            quote = ch
        elif ch == "{":
            delta += 1
        elif ch == "}":
            delta -= 1
    return delta


def _shell_first_arg_bindings(lines: list[str]) -> set[str]:
    bindings: set[str] = set()
    assignment_re = re.compile(
        r"""\b(?:local\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*['"]?\$\{?1(?:[:}][^'"\s]*)?['"]?"""
    )
    for line in lines:
        match = assignment_re.search(line)
        if match:
            bindings.add(match.group("name"))
    return bindings


def _shell_variable_name(value: str) -> str:
    match = re.fullmatch(r"\$\{?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\}?", value.strip("'\""))
    return match.group("name") if match else ""


def _is_azure_cli_extension_dep(dep: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9][\w.-]*", dep))


def _extract_github_cli_extension_deps(line: str) -> list[str]:
    deps: list[str] = []
    for match in re.finditer(_GITHUB_CLI_EXTENSION_COMMAND_RE + r"(?P<body>[^;&|\n]*)", line, re.IGNORECASE):
        body = re.split(r"\s+#", match.group("body"), maxsplit=1)[0]
        body = _trim_shell_redirection(body)
        tokens = _simple_shell_tokens(body)
        i = 0
        while i < len(tokens):
            token = tokens[i].rstrip(",")
            next_i = _skip_github_cli_extension_option(tokens, i)
            if next_i != i:
                i = next_i
                continue
            if re.fullmatch(r"[\w.-]+/[\w.-]+", token):
                deps.append(token)
                break
            i += 1
    return _unique(deps)


_GITHUB_CLI_EXTENSION_VALUE_FLAGS = {"--pin"}


def _skip_github_cli_extension_option(tokens: list[str], index: int) -> int:
    token = tokens[index].rstrip(",")
    name = token.split("=", 1)[0]
    if name in _GITHUB_CLI_EXTENSION_VALUE_FLAGS:
        return index + 1 if "=" in token else min(index + 2, len(tokens))
    if token.startswith("-"):
        return index + 1
    return index


def _extract_vscode_extension_deps(line: str) -> list[str]:
    deps: list[str] = []
    for match in re.finditer(_VSCODE_EXTENSION_INSTALL_COMMAND_RE + r"(?P<body>[^;&|\n]*)", line, re.IGNORECASE):
        body = _trim_markdown_inline_code_body(line, match.start(), match.group("body"))
        body = re.split(r"\s+#", body, maxsplit=1)[0]
        body = _trim_shell_redirection(body)
        tokens = _simple_shell_tokens(body)
        i = 0
        while i < len(tokens):
            token = tokens[i].rstrip(",")
            next_i = _skip_vscode_extension_option(tokens, i)
            if next_i != i:
                i = next_i
                continue
            if _is_vscode_marketplace_extension_id(token):
                deps.append(token)
                break
            i += 1
    return _unique(deps)


_VSCODE_EXTENSION_VALUE_FLAGS = {"--extensions-dir", "--user-data-dir"}


def _skip_vscode_extension_option(tokens: list[str], index: int) -> int:
    token = tokens[index].rstrip(",")
    name = token.split("=", 1)[0]
    if name in _VSCODE_EXTENSION_VALUE_FLAGS:
        return index + 1 if "=" in token else min(index + 2, len(tokens))
    if token.startswith("-"):
        return index + 1
    return index


def _is_vscode_marketplace_extension_id(token: str) -> bool:
    token = token.strip("'\"").rstrip(",;\\")
    if not token or token.startswith((".", "/", "\\", "$")):
        return False
    if any(sep in token for sep in {"/", "\\"}):
        return False
    if token.lower().endswith(".vsix"):
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9][\w-]*(?:\.[A-Za-z0-9][\w-]*)+", token))


def _vscode_extension_array_deps(lines: list[str]) -> dict[str, list[str]]:
    arrays: dict[str, list[str]] = {}
    index = 0
    assignment_re = re.compile(r"^\s*\$?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*@?\(")
    while index < len(lines):
        line = lines[index]
        match = assignment_re.search(line)
        if not match or "extension" not in match.group("name").lower():
            index += 1
            continue
        name = match.group("name").lower()
        values: list[str] = []
        cursor = index
        while cursor < len(lines):
            values.extend(_quoted_vscode_extension_ids(lines[cursor]))
            if ")" in lines[cursor]:
                break
            cursor += 1
        if values:
            arrays[name] = _unique(arrays.get(name, []) + values)
        index = max(cursor + 1, index + 1)
    return arrays


def _quoted_vscode_extension_ids(line: str) -> list[str]:
    return [
        value
        for value in re.findall(r'''["']([^"']+)["']''', line)
        if _is_vscode_marketplace_extension_id(value)
    ]


def _resolved_vscode_extension_deps(line: str, arrays: dict[str, list[str]]) -> list[str]:
    deps: list[str] = []
    variable_names = _vscode_extension_install_variable_names(line)
    for variable_name in variable_names:
        lowered = variable_name.lower()
        deps.extend(arrays.get(lowered, []))
        if lowered in {"ext", "extension", "extensionid"} and len(arrays) == 1:
            deps.extend(next(iter(arrays.values())))
    return _unique(deps)


def _resolved_vscode_extension_deps_at_line(lines: list[str], line_number: int) -> list[str]:
    if not 0 < line_number <= len(lines):
        return []
    line = lines[line_number - 1]
    return _unique(
        _resolved_vscode_extension_deps(line, _vscode_extension_array_deps(lines))
        + [
            dep
            for resolved_line, dep in _powershell_vscode_extension_wrapper_calls(lines)
            if resolved_line == line_number
        ]
    )


def _vscode_extension_install_variable_names(line: str) -> list[str]:
    names: list[str] = []
    for match in re.finditer(_VSCODE_EXTENSION_INSTALL_COMMAND_RE + r"(?P<body>[^;&|\n]*)", line, re.IGNORECASE):
        body = _trim_shell_redirection(match.group("body"))
        tokens = _simple_shell_tokens(body)
        i = 0
        while i < len(tokens):
            token = tokens[i].rstrip(",")
            next_i = _skip_vscode_extension_option(tokens, i)
            if next_i != i:
                i = next_i
                continue
            variable_name = _shell_variable_name(token)
            if variable_name:
                names.append(variable_name)
            i += 1
    return _unique(names)


def _powershell_vscode_extension_wrapper_calls(lines: list[str]) -> list[tuple[int, str]]:
    wrappers, function_ranges = _powershell_vscode_extension_wrappers(lines)
    if not wrappers:
        return []
    calls: list[tuple[int, str]] = []
    for line_number, line in enumerate(lines, start=1):
        if any(start <= line_number <= end for start, end in function_ranges):
            continue
        if _is_line_comment_or_blank(line) or _looks_like_printed_help(line):
            continue
        for function_name, extension_params in wrappers.items():
            for dep in _extract_powershell_vscode_extension_wrapper_call_deps(
                line,
                function_name,
                extension_params,
            ):
                calls.append((line_number, dep))
    return _unique_tuples(calls)


def _powershell_vscode_extension_wrappers(lines: list[str]) -> tuple[dict[str, dict[str, int]], list[tuple[int, int]]]:
    wrappers: dict[str, dict[str, int]] = {}
    ranges: list[tuple[int, int]] = []
    for name, start, end, body in _powershell_function_blocks(lines):
        param_positions = _powershell_function_param_positions(body)
        if not param_positions:
            continue
        extension_params: dict[str, int] = {}
        for line in body:
            for variable_name in _vscode_extension_install_variable_names(line):
                lowered = variable_name.lower()
                if lowered in param_positions:
                    extension_params[lowered] = param_positions[lowered]
        if extension_params:
            wrappers[name.lower()] = extension_params
            ranges.append((start, end))
    return wrappers, ranges


def _powershell_function_param_positions(lines: list[str]) -> dict[str, int]:
    params: list[str] = []
    in_param_block = False
    depth = 0
    for line in lines:
        segment = line
        if not in_param_block:
            match = re.search(r"\bparam\s*\(", line, re.IGNORECASE)
            if not match:
                continue
            segment = line[match.end():]
            in_param_block = True
            depth = 1
        for variable in re.finditer(r"\$(?P<name>[A-Za-z_][A-Za-z0-9_]*)", segment):
            lowered = variable.group("name").lower()
            if lowered not in params:
                params.append(lowered)
        depth += segment.count("(") - segment.count(")")
        if in_param_block and depth <= 0:
            break
    return {name: index for index, name in enumerate(params)}


def _extract_powershell_vscode_extension_wrapper_call_deps(
    line: str,
    function_name: str,
    extension_params: dict[str, int],
) -> list[str]:
    tokens = _simple_shell_tokens(line)
    if not tokens:
        return []
    command_index = 1 if tokens[0] in {"&", "."} else 0
    if command_index >= len(tokens):
        return []
    command = tokens[command_index].strip("&.").lower()
    if command != function_name:
        return []

    deps: list[str] = []
    positional_index = 0
    extension_positions = set(extension_params.values())
    i = command_index + 1
    while i < len(tokens):
        token = tokens[i].rstrip(",;")
        value = ""
        if token.startswith("-"):
            name, inline_value = _powershell_named_arg(token)
            if name in extension_params:
                if inline_value is not None:
                    value = inline_value
                    i += 1
                elif i + 1 < len(tokens):
                    value = tokens[i + 1].rstrip(",;")
                    i += 2
                else:
                    i += 1
            else:
                i += 2 if i + 1 < len(tokens) and not tokens[i + 1].startswith("-") else 1
        else:
            if positional_index in extension_positions:
                value = token
            positional_index += 1
            i += 1
        value = value.strip("'\"")
        if _is_vscode_marketplace_extension_id(value):
            deps.append(value)
    return _unique(deps)


def _extract_krew_plugin_deps(line: str) -> list[str]:
    deps: list[str] = []
    for match in re.finditer(_KREW_PLUGIN_INSTALL_COMMAND_RE + r"(?P<body>[^;&|\n]*)", line, re.IGNORECASE):
        body = re.split(r"\s+#", match.group("body"), maxsplit=1)[0]
        body = _trim_shell_redirection(body)
        tokens = _simple_shell_tokens(body)
        i = 0
        while i < len(tokens):
            token = tokens[i].rstrip(",")
            next_i = _skip_krew_install_option(tokens, i)
            if next_i != i:
                i = next_i
                continue
            if _is_krew_plugin_dep(token):
                deps.append(token)
            i += 1
    return _unique(deps)


_KREW_INSTALL_VALUE_FLAGS = {"--manifest", "--archive", "--index"}


def _skip_krew_install_option(tokens: list[str], index: int) -> int:
    token = tokens[index].rstrip(",")
    name = token.split("=", 1)[0]
    if name in _KREW_INSTALL_VALUE_FLAGS:
        return index + 1 if "=" in token else min(index + 2, len(tokens))
    if token.startswith("-"):
        return index + 1
    return index


def _is_krew_plugin_dep(dep: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9][\w.-]*", dep))


def _extract_helm_repo_add_deps(line: str) -> list[str]:
    deps: list[str] = []
    for match in re.finditer(r"\bhelm\s+repo\s+add\s+(?P<body>[^;&|\n]*)", line, re.IGNORECASE):
        if _looks_like_printed_help(line[:match.start()]):
            continue
        tokens = _merge_github_expression_tokens(_simple_shell_tokens(match.group("body")))
        positional = _helm_positional_tokens(tokens, _HELM_REPO_ADD_VALUE_OPTIONS)
        if len(positional) < 2:
            continue
        dep = _clean_helm_ref(positional[1])
        if _is_helm_remote_ref(dep, allow_registry=False) and not _is_standard_helm_repo(dep):
            deps.append(dep)
    return _unique(deps)


def _extract_helm_chart_pull_deps(line: str) -> list[str]:
    deps: list[str] = []
    for match in re.finditer(r"\bhelm\s+(?:chart\s+)?pull\s+(?P<body>[^;&|\n]*)", line, re.IGNORECASE):
        if _looks_like_printed_help(line[:match.start()]):
            continue
        tokens = _merge_github_expression_tokens(_simple_shell_tokens(match.group("body")))
        repo_option = _helm_option_value(tokens, "--repo")
        if _is_helm_remote_ref(repo_option, allow_registry=True):
            deps.append(repo_option)
        positional = _helm_positional_tokens(tokens, _HELM_PULL_VALUE_OPTIONS)
        if not positional:
            continue
        dep = _clean_helm_ref(positional[0])
        if _is_helm_remote_ref(dep, allow_registry=True):
            deps.append(dep)
    return _unique(deps)


def _extract_helm_plugin_install_deps(line: str) -> list[str]:
    deps: list[str] = []
    for match in re.finditer(r"\bhelm\s+plugin\s+(?:install|add)\s+(?P<body>[^;&|\n]*)", line, re.IGNORECASE):
        if _looks_like_printed_help(line[:match.start()]):
            continue
        tokens = _merge_github_expression_tokens(_simple_shell_tokens(match.group("body")))
        positional = _helm_positional_tokens(tokens, _HELM_PLUGIN_VALUE_OPTIONS)
        if not positional:
            continue
        dep = _clean_helm_ref(positional[0])
        if _is_helm_remote_ref(dep, allow_registry=False):
            deps.append(dep)
    return _unique(deps)


_HELM_REPO_ADD_VALUE_OPTIONS = {
    "--ca-file",
    "--cert-file",
    "--key-file",
    "--password",
    "--repository-cache",
    "--repository-config",
    "--username",
}
_HELM_PULL_VALUE_OPTIONS = {
    "--ca-file",
    "--cert-file",
    "--destination",
    "--key-file",
    "--keyring",
    "--password",
    "--repo",
    "--untardir",
    "--username",
    "--version",
}
_HELM_PLUGIN_VALUE_OPTIONS = {"--version"}


def _helm_positional_tokens(tokens: list[str], value_options: set[str]) -> list[str]:
    positional: list[str] = []
    i = 0
    while i < len(tokens):
        token = tokens[i].rstrip(",")
        name = token.split("=", 1)[0]
        if name in value_options:
            i += 1 if "=" in token else 2
            continue
        if token.startswith("-"):
            i += 1
            continue
        positional.append(token)
        i += 1
    return positional


def _helm_option_value(tokens: list[str], option: str) -> str:
    for index, token in enumerate(tokens):
        token = token.rstrip(",")
        name, sep, inline_value = token.partition("=")
        if name != option:
            continue
        return _clean_helm_ref(inline_value if sep else (tokens[index + 1] if index + 1 < len(tokens) else ""))
    return ""


def _clean_helm_ref(value: str) -> str:
    return value.strip().strip("'\"`").rstrip(",;\\`")


def _is_helm_remote_ref(value: str, *, allow_registry: bool) -> bool:
    if not value or value.startswith((".", "/", "file:")):
        return False
    if value.startswith(("http://", "https://", "oci://")):
        return True
    if re.fullmatch(r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?", value):
        return True
    if "${{" in value:
        return True
    if allow_registry and re.fullmatch(r"[A-Za-z0-9_.-]+\.[A-Za-z0-9_.-]+(?:/[\w./-]+)+(?:[:@][\w.${}+-]+)?", value):
        return True
    return False


def _is_standard_helm_repo(value: str) -> bool:
    return bool(re.match(
        r"https?://(?:charts\.helm\.sh|charts\.bitnami\.com|kubernetes-charts\.storage\.googleapis\.com)(?:/|$)",
        value,
        re.IGNORECASE,
    ))


def _is_brew_install_hint_prefix(prefix: str) -> bool:
    if _looks_like_install_hint_storage(prefix) or _looks_like_js_install_hint_storage(prefix):
        return True
    segment = re.split(r"[{}]", prefix)[-1]
    return _looks_like_printed_help(segment)


def _trim_brew_install_body(body: str) -> str:
    body = re.split(r"\s+#", body, maxsplit=1)[0]
    body = _trim_shell_redirection(body)
    if "`" in body:
        body = body.split("`", 1)[0]
    return body


def _trim_system_package_install_body(body: str) -> str:
    body = re.split(r"\s+#", body, maxsplit=1)[0]
    body = _trim_shell_redirection(body)
    body = re.split(r"\s+\(", body, maxsplit=1)[0]
    body = re.split(r"\s+[—–]\s+", body, maxsplit=1)[0]
    body = re.split(r"\s+-\s+(?:name|uses|run|shell|with|env|if|id):\s+", body, maxsplit=1, flags=re.IGNORECASE)[0]
    if "`" in body:
        body = body.split("`", 1)[0]
    return body


def _trim_shell_redirection(body: str) -> str:
    return re.split(r"\s+(?:\d?>&\d+|\d?>>?|\d?>|>>?|<)\s*", body, maxsplit=1)[0]


_SYSTEM_PACKAGE_VALUE_FLAGS = {
    "--snapshottime",
    "--setopt",
    "--installroot",
    "--releasever",
    "--config",
    "--repo",
    "--repository",
}


def _skip_system_package_option(tokens: list[str], index: int) -> int:
    token = tokens[index].rstrip(",")
    if not _is_system_package_value_flag(token):
        return index
    if "=" in token:
        return _skip_github_expression_value(tokens, index + 1) if "${{" in token and "}}" not in token else index + 1
    if index + 1 >= len(tokens):
        return index + 1
    return _skip_github_expression_value(tokens, index + 2) if tokens[index + 1] == "${{" else index + 2


def _is_system_package_value_flag(token: str) -> bool:
    name = token.split("=", 1)[0]
    return name in _SYSTEM_PACKAGE_VALUE_FLAGS


def _skip_github_expression_value(tokens: list[str], index: int) -> int:
    while index < len(tokens):
        if "}}" in tokens[index]:
            return index + 1
        index += 1
    return index


def _collapse_github_expressions(text: str) -> str:
    return re.sub(
        r"\$\{\{\s*(?P<body>.*?)\s*\}\}",
        lambda match: "${{" + match.group("body").strip() + "}}",
        text,
    )


def _is_system_package_token(token: str) -> bool:
    if not token or token.startswith(("-", ".", "/", "{", "}")):
        return False
    if token.startswith("$") and not token.startswith("${{"):
        return False
    if any(ch in token for ch in "*\\"):
        return False
    if any(ch in token for ch in "{}") and not re.search(r"\$\{\{[^}]+\}\}", token):
        return False
    if re.search(r"\.(?:deb|rpm|apk)$", token, re.IGNORECASE):
        return False
    if token.lower() in {"true", "false", "null"}:
        return False
    github_expr = r"\$\{\{[^}]+\}\}"
    package_token = rf"(?:{github_expr}|[A-Za-z0-9_][A-Za-z0-9_.+:-]*(?:{github_expr}[A-Za-z0-9_.+:-]*)*)"
    return bool(re.fullmatch(package_token, token))


def _extract_cargo_install_deps(line: str) -> list[str]:
    deps: list[str] = []
    for match in re.finditer(r"\bcargo\s+(?:\+\S+\s+)?install\s+(?P<body>[^;&|\n]*)", line, re.IGNORECASE):
        tokens = _merge_github_expression_tokens(_simple_shell_tokens(_trim_cargo_install_body(match.group("body"))))
        if _cargo_install_uses_local_path(tokens):
            continue
        i = 0
        while i < len(tokens):
            token = tokens[i]
            if token in {"--version", "--vers", "--git", "--branch", "--tag", "--rev", "--path", "--root", "--target"}:
                i += 2
                continue
            if token.startswith((
                "--version=", "--vers=", "--git=", "--branch=", "--tag=", "--rev=", "--path=", "--root=", "--target=",
            )):
                i += 1
                continue
            if token.startswith("-"):
                i += 1
                continue
            if _is_cargo_crate_spec(token):
                deps.append(token)
            i += 1
    return _unique(deps)


def _extract_cargo_install_git_sources(line: str) -> list[str]:
    deps: list[str] = []
    for match in re.finditer(r"\bcargo\s+(?:\+\S+\s+)?install\s+(?P<body>[^;&|\n]*)", line, re.IGNORECASE):
        tokens = _merge_github_expression_tokens(_simple_shell_tokens(_trim_cargo_install_body(match.group("body"))))
        git_url = ""
        git_ref = ""
        i = 0
        while i < len(tokens):
            token = tokens[i].rstrip(",;\\\"'")
            if token == "--git" and i + 1 < len(tokens):
                git_url = tokens[i + 1].rstrip(",;\\\"'")
                i += 2
                continue
            if token.startswith("--git="):
                git_url = token.split("=", 1)[1].rstrip(",;\\\"'")
                i += 1
                continue
            for flag, ref_name in (("--rev", "rev"), ("--tag", "tag"), ("--branch", "branch")):
                if token == flag and i + 1 < len(tokens):
                    value = tokens[i + 1].rstrip(",;\\\"'")
                    if value and _is_concrete_cargo_git_ref(value):
                        git_ref = f"{ref_name}={value}"
                    i += 2
                    break
                if token.startswith(f"{flag}="):
                    value = token.split("=", 1)[1].rstrip(",;\\\"'")
                    if value and _is_concrete_cargo_git_ref(value):
                        git_ref = f"{ref_name}={value}"
                    i += 1
                    break
            else:
                i += 1
        if _is_concrete_cargo_git_url(git_url):
            deps.append(f"{git_url}#{git_ref}" if git_ref else git_url)
    return _unique(deps)


def _is_cargo_crate_spec(token: str) -> bool:
    token = token.rstrip(",;\\\"'")
    if not token or token.startswith((".", "$", "/", "\\")):
        return False
    crate = r"[A-Za-z0-9_-]+"
    shell_var = r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?"
    github_expr = r"\$\{\{[^}]+\}\}"
    version_part = rf"(?:[A-Za-z0-9_.!+~-]+|{shell_var}|{github_expr})"
    return bool(re.fullmatch(rf"{crate}(?:@{version_part}+)?", token))


def _is_concrete_cargo_git_url(value: str) -> bool:
    if not value or value.startswith(("$", "${{", ".", "/", "\\")):
        return False
    if any(part in value for part in ("${", "$(", "`", "<", ">")):
        return False
    return bool(re.fullmatch(r"(?:https?|ssh|git)://[^\s#]+|git@[^:\s]+:[^\s#]+", value))


def _is_concrete_cargo_git_ref(value: str) -> bool:
    if not value or value.startswith(("$", "${{")):
        return False
    if any(part in value for part in ("${", "$(", "`", "<", ">")):
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9._/+~-]+", value))


def _extract_cargo_binstall_deps(line: str) -> list[str]:
    deps: list[str] = []
    for match in re.finditer(r"\bcargo\s+(?:\+\S+\s+)?binstall\s+(?P<body>[^;&|\n]*)", line, re.IGNORECASE):
        tokens = _simple_shell_tokens(_trim_cargo_install_body(match.group("body")))
        i = 0
        while i < len(tokens):
            token = tokens[i]
            if token in {
                "--version",
                "--vers",
                "--git",
                "--branch",
                "--tag",
                "--rev",
                "--manifest-path",
                "--root",
                "--target",
                "--strategies",
                "--index",
                "--registry",
            }:
                i += 2
                continue
            if token.startswith((
                "--version=",
                "--vers=",
                "--git=",
                "--branch=",
                "--tag=",
                "--rev=",
                "--manifest-path=",
                "--root=",
                "--target=",
                "--strategies=",
                "--index=",
                "--registry=",
            )):
                i += 1
                continue
            if token.startswith("-"):
                i += 1
                continue
            if re.fullmatch(r"[A-Za-z0-9_-]+", token) and not token.startswith("."):
                deps.append(token)
            i += 1
    return _unique(deps)


def _cargo_install_uses_local_path(tokens: list[str]) -> bool:
    if not any(token == "--path" or token.startswith("--path=") for token in tokens):
        return False
    return not any(token == "--git" or token.startswith("--git=") for token in tokens)


def _trim_cargo_install_body(body: str) -> str:
    return re.split(r"\s+#", body, maxsplit=1)[0]


def _extract_go_install_deps(line: str) -> list[str]:
    deps: list[str] = []
    for match in re.finditer(r"\bgo\s+install\s+(?P<body>[^;&|\n]*)", line, re.IGNORECASE):
        tokens = _merge_github_expression_tokens(_simple_shell_tokens(match.group("body")))
        i = 0
        while i < len(tokens):
            token = tokens[i].rstrip(",;\\\"'")
            if _is_go_install_value_flag(token):
                i += 1 if "=" in token else 2
                continue
            if token.startswith("-"):
                i += 1
                continue
            if _is_go_install_dep_token(token):
                deps.append(token)
            i += 1
    return _unique(deps)


def _extract_go_run_remote_deps(line: str) -> list[str]:
    deps: list[str] = []
    for match in re.finditer(r"\bgo\s+run\s+(?P<body>[^;&|\n]*)", line, re.IGNORECASE):
        tokens = _merge_github_expression_tokens(_simple_shell_tokens(match.group("body")))
        i = 0
        while i < len(tokens):
            token = tokens[i]
            if _is_go_run_value_flag(token):
                i += 1 if "=" in token else 2
                continue
            if token.startswith("-"):
                i += 1
                continue
            if _is_go_run_remote_dep_token(token):
                deps.append(token.rstrip(",;\\"))
            break
    return _unique(deps)


def _go_install_continuation_line(lines: list[str], line_number: int) -> str:
    if not (0 < line_number <= len(lines)):
        return ""
    parts: list[str] = []
    index = line_number - 1
    while index < len(lines) and len(parts) < 8:
        current = lines[index].strip()
        continued = current.endswith("\\")
        parts.append(current[:-1].rstrip() if continued else current)
        if not continued:
            break
        index += 1
    return " ".join(parts)


_GO_INSTALL_VALUE_FLAGS = {
    "-asmflags",
    "-buildmode",
    "-compiler",
    "-gccgoflags",
    "-gcflags",
    "-installsuffix",
    "-ldflags",
    "-mod",
    "-modfile",
    "-overlay",
    "-p",
    "-pkgdir",
    "-tags",
    "-toolexec",
}


def _is_go_install_value_flag(token: str) -> bool:
    return token.split("=", 1)[0] in _GO_INSTALL_VALUE_FLAGS


def _is_go_run_value_flag(token: str) -> bool:
    return token.split("=", 1)[0] in _GO_INSTALL_VALUE_FLAGS


def _is_go_install_dep_token(token: str) -> bool:
    token = token.rstrip(",;\\")
    if not token or token.startswith(("-", ".", "/", "$")):
        return False
    if any(ch in token for ch in "*\\"):
        return False
    if token in {"true", "false"}:
        return False
    module, has_version, version = token.partition("@")
    if not _is_go_module_path(module):
        return False
    return not has_version or _is_go_install_version(version)


def _is_go_run_remote_dep_token(token: str) -> bool:
    token = token.rstrip(",;\\")
    return "@" in token and _is_go_install_dep_token(token)


def _is_go_module_path(module: str) -> bool:
    if "/" not in module or "." not in module.split("/", 1)[0]:
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+", module))


def _is_go_install_version(version: str) -> bool:
    if not version:
        return False
    if re.fullmatch(r"[A-Za-z0-9_.+/-]+", version):
        return True
    if re.fullmatch(r"\$\{[A-Za-z_][A-Za-z0-9_]*[^}\n]*\}", version):
        return True
    if re.fullmatch(r"\$\{\{[^}\n]+(?:\}[^}\n]+)*\}\}", version):
        return True
    return bool(re.fullmatch(r"\$\([^)\n]+\)", version))


def _simple_shell_tokens(text: str) -> list[str]:
    return [t.strip("'\"") for t in re.findall(r'''(?:"[^"]*"|'[^']*'|\S+)''', text) if t.strip("'\"")]


def _merge_github_expression_tokens(tokens: list[str]) -> list[str]:
    merged: list[str] = []
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if "${{" not in token or "}}" in token:
            merged.append(token)
            i += 1
            continue
        parts = [token]
        i += 1
        while i < len(tokens):
            parts.append(tokens[i])
            if "}}" in tokens[i]:
                i += 1
                break
            i += 1
        merged.append(" ".join(parts))
    return merged


def _normalize_dep_ws(dep: str) -> str:
    return " ".join(dep.split())


def _is_pip_package_token(token: str) -> bool:
    if "..." in token:
        return False
    if token.startswith(("http://", "https://", "git+", "file:")):
        return False
    if _pip_package_base_name(token) in {"pip", "setuptools", "wheel", "pip-tools", "uv"}:
        return False
    if token.lower() in {"requirements.txt", "constraints.txt", "requirements.in", "constraints.in"}:
        return False
    if re.search(r"\.(?:txt|in|lock|toml|cfg|ini|ya?ml|whl|zip|tar\.gz|tgz)$", token, re.IGNORECASE):
        return False
    if any(ch in token for ch in "/\\"):
        return False
    if token.startswith((".", "$")):
        return False
    package = r"[A-Za-z0-9_.-]+(?:\[[A-Za-z0-9_,.-]+\])?"
    shell_var = r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?"
    github_expr = r"\$\{\{[^}]+\}\}"
    version_part = rf"(?:[A-Za-z0-9_.!*+-]+|{github_expr}|{shell_var})"
    version_value = rf"(?:{version_part})+"
    version_operator = r"(?:===?|!=|~=|<=?|>=?)"
    version = rf"{version_operator}{version_value}(?:,{version_operator}{version_value})*"
    return bool(re.fullmatch(rf"{package}(?:{version})?", token))


def _pip_package_base_name(token: str) -> str:
    return re.split(r"\[|===?|!=|~=|<=?|>=?", token, maxsplit=1)[0].lower()


_DOCKERFILE_SYSTEM_TOOL_PACKAGES = {
    "curl",
    "wget",
    "git",
    "jq",
    "unzip",
    "zip",
    "gnupg",
    "gpg",
    "docker.io",
    "docker-buildx",
    "docker-compose",
    "docker-compose-v2",
    "podman",
    "podman-compose",
    "buildah",
    "skopeo",
    "nodejs",
    "npm",
}


def _dockerfile_system_packages_are_tooling(dep: str) -> bool:
    return bool(set(dep.split()) & _DOCKERFILE_SYSTEM_TOOL_PACKAGES)


def _has_cargo_toolchain_install(line: str) -> bool:
    return bool(re.search(r"\bcargo\s+\+\S+\s+install\b", line, re.IGNORECASE))


def _has_cargo_toolchain_binstall(line: str) -> bool:
    return bool(re.search(r"\bcargo\s+\+\S+\s+binstall\b", line, re.IGNORECASE))


def _looks_like_printed_help(line: str) -> bool:
    return bool(re.match(
        r"\s*@?(?:echo|printf|print|warn|fail|pass|log(?:[_-]?\w+)?|info|debug|error|"
        r"Write-[A-Za-z][A-Za-z0-9]*|throw)\b",
        line,
        re.IGNORECASE,
    ))


def _unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            out.append(value)
    return out


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    cargo_binstall_keys = {
        (finding.line_number, finding.extracted_dep)
        for finding in findings
        if finding.pattern_id == "cargo-binstall"
    }
    seen: set[tuple[int, str, str]] = set()
    out: list[Finding] = []
    for finding in findings:
        if (
            finding.pattern_id == "cargo-install"
            and (finding.line_number, finding.extracted_dep) in cargo_binstall_keys
        ):
            continue
        key = (finding.line_number, finding.pattern_id, finding.extracted_dep)
        if key not in seen:
            seen.add(key)
            out.append(finding)
    return out
