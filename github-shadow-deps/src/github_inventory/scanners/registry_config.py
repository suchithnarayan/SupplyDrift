"""Detect custom/private package registries in .npmrc, .yarnrc.yml, pip.conf, nuget.config."""
from __future__ import annotations

import re

from github_inventory.discovery import FileTarget
from github_inventory.models import Category, Finding, Severity
from github_inventory.scanners.base import BaseScanner, PatternRule

_URL_WITH_GITHUB_EXPR_RE = r"(?P<dep>https?://(?:\$\{\{\s*[^}]+?\s*\}\}|[^\s'\"$])+)"
_SHELL_HTTP_URL = r"https?://(?:(?:\$\([^)]*\))|[^\s'\"|\\])+"
_MICROSOFT_APT_REPO_PACKAGE_URL = (
    r"https?://packages\.microsoft\.com/config/(?:(?:\$\([^)]*\))|[^\s'\";&|])+?\.deb"
)
_APT_REPO_PACKAGE_INSTALL_CMD = r"(?:dpkg\s+-i|dpkg_install)"


class RegistryConfigScanner(BaseScanner):
    name = "registry-config"

    def scan_file_content(self, target: FileTarget, content: str, lines: list[str]) -> list[Finding]:
        if target.file_type in {"npmrc", "nuget_config", "pip_conf"} and _is_registry_test_fixture_file(target):
            return []
        if target.file_type == "npmrc" and _is_azure_pipelines_task_test_npmrc(target):
            return []
        if target.file_type == "nuget_config":
            lines = _strip_xml_comments(lines)
            content = "\n".join(lines)

        findings = super().scan_file_content(target, content, lines)
        findings.extend(_scan_powershell_repository_sources(target, lines, findings))
        findings.extend(_scan_dotnet_tool_add_source_urls(target, lines, findings))
        findings.extend(_scan_npm_cli_registry_variable_urls(target, lines, findings))
        findings.extend(_scan_variable_apt_signing_key_urls(target, lines, findings))
        findings.extend(_scan_apt_key_adv_imports(target, lines, findings))
        findings.extend(_scan_yum_repo_config_writes(target, lines, findings))
        findings = [
            finding for finding in findings
            if finding.pattern_id != "apt-signing-key-download"
            or _is_apt_signing_key_dependency(finding.extracted_dep)
        ]
        findings = [
            finding for finding in findings
            if not _is_local_registry_url(finding.extracted_dep)
        ]
        findings = [
            finding for finding in findings
            if finding.pattern_id not in {"pip-config-set-index", "pip-env-index-url"}
            or not _is_canonical_pypi_index(finding.extracted_dep)
        ]
        findings = [
            finding for finding in findings
            if finding.pattern_id not in {
                "npm-cli-registry",
                "npm-config-set-registry",
                "npm-env-registry",
                "npm-task-custom-command-registry",
                "yarn-config-set-registry",
            }
            or not _is_canonical_npm_registry(finding.extracted_dep)
        ]
        if target.file_type == "npmrc":
            findings = [
                finding for finding in findings
                if finding.pattern_id not in {"npmrc-global-registry", "yarnrc-npm-registry", "yarnrc-npm-scope"}
                or not _is_canonical_npm_registry(finding.extracted_dep)
            ]
            return _dedupe_yarn_registry_findings(findings)
        if target.file_type == "nuget_config":
            return [
                finding for finding in findings
                if finding.pattern_id not in {"nuget-custom-feed", "nuget-cli-source-url"}
                or not _is_canonical_nuget_feed(finding.extracted_dep)
            ]
        findings = [
            finding for finding in findings
            if finding.pattern_id != "nuget-cli-source-url"
            or not _is_canonical_nuget_feed(finding.extracted_dep)
        ]
        return findings

    def register_rules(self) -> None:
        # --- npm (.npmrc) ---

        self.add_rule(PatternRule(
            pattern_id="npmrc-scoped-registry",
            regex=re.compile(
                r"(?P<dep>@[\w.-]+:registry\s*=\s*https?://\S+)",
            ),
            severity=Severity.MEDIUM,
            description_template="npm scoped registry override (dependency confusion surface): {dep}",
            category=Category.REGISTRY_CONFIG,
            file_types=["npmrc"],
        ))

        self.add_rule(PatternRule(
            pattern_id="npmrc-global-registry",
            regex=re.compile(
                r"^\s*registry\s*=\s*(?P<dep>https?://\S+)",
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="npm global registry override (dependency confusion surface): {dep}",
            category=Category.REGISTRY_CONFIG,
            file_types=["npmrc"],
        ))

        self.add_rule(PatternRule(
            pattern_id="npmrc-auth-token",
            regex=re.compile(
                r"//(?P<host>\[[^\]]+\](?::\d+)?|[^/\s:]+(?::\d+)?)"
                r"(?:/[^\s:]*)?/:_authToken\s*=\s*\S+",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="npm registry auth token configured for registry {host}",
            category=Category.REGISTRY_CONFIG,
            file_types=["npmrc"],
            extract_group="host",
            extracted_dep_template="npm-auth-token@{host}",
            matched_text_template="//{host}/:_authToken=[REDACTED]",
            sensitive_metadata={
                "redacted": True,
                "kind": "registry-credential",
                "credential_type": "npm-auth-token",
                "host": "{host}",
            },
        ))

        self.add_rule(PatternRule(
            pattern_id="npm-config-set-registry",
            regex=re.compile(
                r"\bnpm\s+config\s+(?:set|add)\s+(?:registry|@[\w.-]+:registry)\s+"
                r"['\"]?(?P<dep>https?://[^\s'\"]+)",
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="npm config command sets package registry (dependency confusion surface): {dep}",
            category=Category.REGISTRY_CONFIG,
            file_types=["ci", "github_action", "script", "dockerfile", "build", "package_config"],
        ))

        self.add_rule(PatternRule(
            pattern_id="npm-cli-registry",
            regex=re.compile(
                r"\b(?:npm|pnpm|yarn)\s+(?:install|i|add|ci|update|upgrade)\b[^\n]*?"
                r"(?:--registry|--npm-registry-server)(?:=|\s+)['\"]?(?P<dep>https?://[^\s'\"\\]+)",
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="npm-compatible command uses custom registry: {dep}",
            category=Category.REGISTRY_CONFIG,
            file_types=["ci", "github_action", "script", "dockerfile", "build", "package_config"],
        ))

        self.add_rule(PatternRule(
            pattern_id="npm-env-registry",
            regex=re.compile(
                r"\b(?:NPM_CONFIG_REGISTRY|npm_config_registry|YARN_NPM_REGISTRY_SERVER|"
                r"YARN_REGISTRY|PNPM_CONFIG_REGISTRY)\s*(?:=|:)\s*"
                r"['\"]?(?P<dep>https?://[^\s'\"\\]+)",
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="npm-compatible environment variable sets package registry: {dep}",
            category=Category.REGISTRY_CONFIG,
            file_types=["ci", "github_action", "script", "dockerfile", "build", "package_config"],
        ))

        self.add_rule(PatternRule(
            pattern_id="npm-task-custom-command-registry",
            regex=re.compile(
                r"\bcustomCommand\s*:\s*['\"]?"
                r"(?:install|i|ci|publish)\b[^\n]*?"
                r"(?:--registry|--npm-registry-server)(?:=|\s+)['\"]?"
                r"(?P<dep>https?://[^\s'\"\\]+)",
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="Azure Pipelines npm task uses custom package registry: {dep}",
            category=Category.REGISTRY_CONFIG,
            file_types=["ci"],
        ))

        # --- Yarn Berry (.yarnrc.yml) ---

        self.add_rule(PatternRule(
            pattern_id="yarnrc-npm-registry",
            regex=re.compile(
                r"npmRegistryServer:\s*['\"]?(?P<dep>https?://[^\s'\"]+)",
            ),
            severity=Severity.MEDIUM,
            description_template="Yarn Berry custom npm registry server: {dep}",
            category=Category.REGISTRY_CONFIG,
            file_types=["npmrc"],
        ))

        self.add_rule(PatternRule(
            pattern_id="yarnrc-npm-scope",
            regex=re.compile(
                r"npmRegistryServer:\s*['\"]?(?P<dep>https?://[^\s'\"]+)",
            ),
            severity=Severity.MEDIUM,
            description_template="Yarn Berry scoped registry: {dep}",
            category=Category.REGISTRY_CONFIG,
            file_types=["npmrc"],
        ))

        self.add_rule(PatternRule(
            pattern_id="yarn-config-set-registry",
            regex=re.compile(
                r"\byarn\s+config\s+set\s+(?:registry|npmRegistryServer)\s+"
                r"['\"]?(?P<dep>https?://[^\s'\"]+)",
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="Yarn config command sets package registry (dependency confusion surface): {dep}",
            category=Category.REGISTRY_CONFIG,
            file_types=["ci", "github_action", "script", "dockerfile", "build", "package_config"],
        ))

        # --- pip (pip.conf / pip.ini) ---

        self.add_rule(PatternRule(
            pattern_id="pip-conf-custom-index",
            regex=re.compile(
                r"(?:index-url|extra-index-url)\s*=\s*(?P<dep>https?://\S+)",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="pip config uses custom package index (dependency confusion risk): {dep}",
            category=Category.REGISTRY_CONFIG,
            file_types=["pip_conf"],
        ))

        self.add_rule(PatternRule(
            pattern_id="pip-config-set-index",
            regex=re.compile(
                r"\b(?:python3?\s+-m\s+)?pip3?\s+config\s+(?:--(?:site|user|global)\s+)*"
                r"set\s+(?:global\.)?(?:index-url|extra-index-url)\s+"
                r"['\"]?(?P<dep>https?://[^\s'\"]+)",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="pip config command sets package index (dependency confusion risk): {dep}",
            category=Category.REGISTRY_CONFIG,
            file_types=["ci", "github_action", "script", "dockerfile", "build"],
        ))

        self.add_rule(PatternRule(
            pattern_id="pip-env-index-url",
            regex=re.compile(
                r"(?:^|\b|env:)\bPIP_(?:EXTRA_)?INDEX_URL\s*(?:=|:)\s*"
                r"['\"]?(?P<dep>https?://[^\s'\"\\]+)",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="pip environment variable sets package index (dependency confusion risk): {dep}",
            category=Category.REGISTRY_CONFIG,
            file_types=["ci", "github_action", "script", "dockerfile", "build"],
        ))

        # --- APT signing keys ---

        self.add_rule(PatternRule(
            pattern_id="apt-signing-key-download",
            regex=re.compile(
                r"\b(?:curl|wget)\b[^\n|]*?(?P<dep>" + _SHELL_HTTP_URL + r")[^\n|]*"
                r"\|\s*(?:"
                r"gpg\s+--dearmor[^\n]*(?:/etc/apt/(?:keyrings|trusted\.gpg\.d)/|/usr/share/keyrings/|apt/keyrings)"
                r"|tee\s+(?:/etc/apt/(?:keyrings|trusted\.gpg\.d)/|/usr/share/keyrings/|apt/keyrings)"
                r")",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="Downloaded APT signing key grants package install authority: {dep}",
            category=Category.REGISTRY_CONFIG,
            file_types=["ci", "dockerfile", "script", "github_action"],
        ))

        self.add_rule(PatternRule(
            pattern_id="apt-signing-key-download",
            regex=re.compile(
                r"\b(?:curl|wget)\b[^\n]*?(?P<dep>" + _SHELL_HTTP_URL + r")[^\n]*"
                r"(?:\n[^\n]*){0,3}\bgpg\s+--dearmor[^\n]*"
                r"(?:\n[^\n]*){0,3}"
                r"(?:/etc/apt/(?:keyrings|trusted\.gpg\.d)/|/usr/share/keyrings/|apt/keyrings)",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="Downloaded APT signing key grants package install authority: {dep}",
            category=Category.REGISTRY_CONFIG,
            file_types=["ci", "dockerfile", "script", "github_action"],
            multiline=True,
        ))

        self.add_rule(PatternRule(
            pattern_id="apt-signing-key-download",
            regex=re.compile(
                r"\b(?:curl|wget)\b[^\n]*?(?P<dep>" + _SHELL_HTTP_URL + r")[^\n]*"
                r"(?:\n[^\n]*){0,3}\btee\s+"
                r"(?:/etc/apt/(?:keyrings|trusted\.gpg\.d)/|/usr/share/keyrings/|apt/keyrings)",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="Downloaded APT signing key grants package install authority: {dep}",
            category=Category.REGISTRY_CONFIG,
            file_types=["ci", "dockerfile", "script", "github_action"],
            multiline=True,
        ))

        self.add_rule(PatternRule(
            pattern_id="apt-signing-key-download",
            regex=re.compile(
                r"\b(?:curl|wget)\b[^\n|]*?(?P<dep>" + _SHELL_HTTP_URL + r")[^\n|]*"
                r"\|\s*(?:\([^|\n]*?)?(?:sudo\s+)?apt-key\s+add\b",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="Downloaded APT signing key grants package install authority: {dep}",
            category=Category.REGISTRY_CONFIG,
            file_types=["ci", "dockerfile", "script", "github_action"],
        ))

        self.add_rule(PatternRule(
            pattern_id="apt-signing-key-download",
            regex=re.compile(
                r"\b(?:curl|wget)\b[^\n]*?"
                r"(?:-O\s+|--output-document(?:=|\s+)|-o\s+|--output(?:=|\s+))"
                r"['\"]?(?:/etc/apt/(?:keyrings|trusted\.gpg\.d)/|/usr/share/keyrings/|apt/keyrings)[^'\"\s]+['\"]?"
                r"[^\n]*?(?P<dep>https?://\S+)",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="Downloaded APT signing key grants package install authority: {dep}",
            category=Category.REGISTRY_CONFIG,
            file_types=["ci", "dockerfile", "script", "github_action"],
        ))

        self.add_rule(PatternRule(
            pattern_id="apt-signing-key-download",
            regex=re.compile(
                r"\b(?:curl|wget)\b[^\n]*?(?P<dep>https?://\S+)[^\n]*?"
                r"(?:-O\s+|--output-document(?:=|\s+)|-o\s+|--output(?:=|\s+))"
                r"['\"]?(?:/etc/apt/(?:keyrings|trusted\.gpg\.d)/|/usr/share/keyrings/|apt/keyrings)[^'\"\s]+['\"]?",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="Downloaded APT signing key grants package install authority: {dep}",
            category=Category.REGISTRY_CONFIG,
            file_types=["ci", "dockerfile", "script", "github_action"],
        ))

        self.add_rule(PatternRule(
            pattern_id="apt-signing-key-download",
            regex=re.compile(
                r"\b(?:curl|wget)\b[^\n|]*?(?P<dep>https?://\S+)[^\n|]*"
                r"\|\s*gpg\s+--dearmor\s*>\s*(?P<keyfile>[^\s;&|]+)"
                r"(?:\n[^\n]*){0,4}\n[^\n]*\binstall\b[^\n]*\b(?P=keyfile)\b[^\n]*"
                r"(?:/etc/apt/(?:keyrings|trusted\.gpg\.d)/|/usr/share/keyrings/|apt/keyrings)",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="Downloaded APT signing key grants package install authority: {dep}",
            category=Category.REGISTRY_CONFIG,
            file_types=["ci", "dockerfile", "script", "github_action"],
            multiline=True,
        ))

        self.add_rule(PatternRule(
            pattern_id="apt-signing-key-download",
            regex=re.compile(
                r"\b(?:curl|wget)\b[^\n]*?"
                r"(?:-O\s+|--output-document(?:=|\s+)|-o\s+|--output(?:=|\s+))"
                r"['\"]?(?P<keyfile>/tmp/[^'\"\s;&|]+\.(?:asc|gpg|key|pub))['\"]?"
                r"[^\n]*?(?P<dep>https?://\S+)"
                r"(?:\n[^\n]*){0,4}\n[^\n]*gpg\s+--dearmor[^\n]*"
                r"(?:/etc/apt/(?:keyrings|trusted\.gpg\.d)/|/usr/share/keyrings/|apt/keyrings)[^\n]*"
                r"(?P=keyfile)\b",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="Downloaded APT signing key grants package install authority: {dep}",
            category=Category.REGISTRY_CONFIG,
            file_types=["ci", "dockerfile", "script", "github_action"],
            multiline=True,
        ))

        self.add_rule(PatternRule(
            pattern_id="apt-repo-package-download",
            regex=re.compile(
                r"\b(?:curl|wget)\b[^\n]*?(?P<dep>" + _MICROSOFT_APT_REPO_PACKAGE_URL + r")[^\n]*"
                r"(?:\n[^\n]*){0,5}\b" + _APT_REPO_PACKAGE_INSTALL_CMD + r"\b[^\n]*(?:packages-microsoft-prod|mssql-release|ms)\S*\.deb",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="Downloaded APT repository package configures package install authority: {dep}",
            category=Category.REGISTRY_CONFIG,
            file_types=["ci", "dockerfile", "script", "github_action"],
            multiline=True,
        ))

        self.add_rule(PatternRule(
            pattern_id="apt-repo-package-download",
            regex=re.compile(
                r"\bADD\s+(?P<dep>" + _MICROSOFT_APT_REPO_PACKAGE_URL + r")\s+[^\n]*"
                r"(?:\n[^\n]*){0,80}\b" + _APT_REPO_PACKAGE_INSTALL_CMD + r"\b[^\n]*(?:packages-microsoft-prod|mssql-release|ms)\S*\.deb",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="Downloaded APT repository package configures package install authority: {dep}",
            category=Category.REGISTRY_CONFIG,
            file_types=["dockerfile"],
            multiline=True,
        ))

        # --- APK signing keys ---

        self.add_rule(PatternRule(
            pattern_id="apk-signing-key-download",
            regex=re.compile(
                r"\b(?:curl|wget)\b[^\n]*?"
                r"(?:-O\s+|--output-document(?:=|\s+)|-o\s+|--output(?:=|\s+))"
                r"['\"]?/etc/apk/keys/[^'\"\s]+['\"]?"
                r"[^\n]*?(?P<dep>https?://\S+)",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="Downloaded APK signing key grants package install authority: {dep}",
            category=Category.REGISTRY_CONFIG,
            file_types=["ci", "dockerfile", "script", "github_action"],
        ))

        self.add_rule(PatternRule(
            pattern_id="apk-signing-key-download",
            regex=re.compile(
                r"\b(?:curl|wget)\b[^\n]*?(?P<dep>https?://\S+)[^\n]*?"
                r"(?:-O\s+|--output-document(?:=|\s+)|-o\s+|--output(?:=|\s+))"
                r"['\"]?/etc/apk/keys/[^'\"\s]+['\"]?",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="Downloaded APK signing key grants package install authority: {dep}",
            category=Category.REGISTRY_CONFIG,
            file_types=["ci", "dockerfile", "script", "github_action"],
        ))

        # --- RPM/YUM signing keys and repository files ---

        self.add_rule(PatternRule(
            pattern_id="yum-repo-config-download",
            regex=re.compile(
                r"\b(?:curl|wget)\b[^\n]*?"
                r"(?:-P\s+|--directory-prefix(?:=|\s+))['\"]?/etc/yum\.repos\.d/?['\"]?"
                r"[^\n]*?(?P<dep>https?://[^\s'\";&|]+\.repo(?:[?#][^\s'\";&|]+)?)",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="Downloaded YUM repository config grants package install authority: {dep}",
            category=Category.REGISTRY_CONFIG,
            file_types=["ci", "dockerfile", "script", "github_action"],
        ))

        self.add_rule(PatternRule(
            pattern_id="yum-repo-config-download",
            regex=re.compile(
                r"\b(?:curl|wget)\b[^\n]*?(?P<dep>https?://[^\s'\";&|]+\.repo(?:[?#][^\s'\";&|]+)?)"
                r"[^\n]*?(?:-O\s+|--output-document(?:=|\s+)|-o\s+|--output(?:=|\s+))"
                r"['\"]?/etc/yum\.repos\.d/[^'\"\s;&|]+['\"]?",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="Downloaded YUM repository config grants package install authority: {dep}",
            category=Category.REGISTRY_CONFIG,
            file_types=["ci", "dockerfile", "script", "github_action"],
        ))

        self.add_rule(PatternRule(
            pattern_id="yum-repo-config-download",
            regex=re.compile(
                r"\b(?:curl|wget)\b[^\n]*?(?P<dep>https?://[^\s'\";&|]+\.repo(?:[?#][^\s'\";&|]+)?)"
                r"[^\n]*?>\s*['\"]?/etc/yum\.repos\.d/[^'\"\s;&|]+['\"]?",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="Downloaded YUM repository config grants package install authority: {dep}",
            category=Category.REGISTRY_CONFIG,
            file_types=["ci", "dockerfile", "script", "github_action"],
        ))

        self.add_rule(PatternRule(
            pattern_id="yum-repo-config-add",
            regex=re.compile(
                r"\b(?:dnf|yum)\s+config-manager\s+--add-repo(?:=|\s+)"
                r"['\"]?(?P<dep>https?://[^\s'\";&|]+(?:\.repo)?)",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="YUM/DNF repository config grants package install authority: {dep}",
            category=Category.REGISTRY_CONFIG,
            file_types=["ci", "dockerfile", "script", "github_action"],
        ))

        self.add_rule(PatternRule(
            pattern_id="zypper-repo-config-add",
            regex=re.compile(
                r"\bzypper\b[^\n]*?\b(?:ar|addrepo)\b[^\n]*?"
                r"(?P<dep>https?://[^\s'\";&|]+\.repo(?:[?#][^\s'\";&|]+)?)",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="Zypper repository config grants package install authority: {dep}",
            category=Category.REGISTRY_CONFIG,
            file_types=["ci", "dockerfile", "script", "github_action"],
        ))

        self.add_rule(PatternRule(
            pattern_id="rpm-signing-key-import",
            regex=re.compile(
                r"\b(?:rpmkeys|rpm)\s+--import\s+['\"]?(?P<dep>https?://[^\s'\";&|]+)",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="Imported RPM signing key grants package install authority: {dep}",
            category=Category.REGISTRY_CONFIG,
            file_types=["ci", "dockerfile", "script", "github_action"],
        ))

        self.add_rule(PatternRule(
            pattern_id="debsig-signing-key-download",
            regex=re.compile(
                r"\b(?:curl|wget)\b[^\n|]*?(?P<dep>https?://[^\s'\"|]+)[^\n|]*"
                r"\|\s*(?:sudo\s+)?gpg\s+--dearmor[^\n]*"
                r"(?:/usr/share/debsig/keyrings/|/etc/debsig/)",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="Downloaded debsig signing key grants package verification authority: {dep}",
            category=Category.REGISTRY_CONFIG,
            file_types=["ci", "dockerfile", "script", "github_action"],
        ))

        # --- NuGet (nuget.config) ---

        self.add_rule(PatternRule(
            pattern_id="nuget-custom-feed",
            regex=re.compile(
                r'<add\s+[^>]*value\s*=\s*["\'](?P<dep>https?://\S+?)["\']',
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="NuGet custom package feed: {dep}",
            category=Category.REGISTRY_CONFIG,
            file_types=["nuget_config"],
        ))

        self.add_rule(PatternRule(
            pattern_id="nuget-cli-source-url",
            regex=re.compile(
                r"\b(?:dotnet\s+nuget|nuget(?:\.exe)?)\s+push\b[^\n]*"
                r"(?:--source|-s|-Source)\b(?:\s+|=|:)"
                + _URL_WITH_GITHUB_EXPR_RE,
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="NuGet CLI command targets external package feed: {dep}",
            category=Category.REGISTRY_CONFIG,
            file_types=["ci", "github_action", "script", "dockerfile", "build"],
        ))

        self.add_rule(PatternRule(
            pattern_id="nuget-cli-source-url",
            regex=re.compile(
                r"\bdotnet\s+nuget\s+add\s+source\s+['\"]?"
                + _URL_WITH_GITHUB_EXPR_RE,
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="NuGet CLI command targets external package feed: {dep}",
            category=Category.REGISTRY_CONFIG,
            file_types=["ci", "github_action", "script", "dockerfile", "build"],
        ))

        self.add_rule(PatternRule(
            pattern_id="nuget-cli-source-url",
            regex=re.compile(
                r"\bnuget(?:\.exe)?\s+sources?\s+add\b[^\n]*"
                r"(?:--source|-source|-s)\b(?:\s+|=|:)"
                + _URL_WITH_GITHUB_EXPR_RE,
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="NuGet CLI command targets external package feed: {dep}",
            category=Category.REGISTRY_CONFIG,
            file_types=["ci", "github_action", "script", "dockerfile", "build"],
        ))


_REGISTRY_SCRIPTABLE = {"ci", "github_action", "script", "dockerfile", "build"}
_YUM_REPO_FILE_DEST_RE = re.compile(
    r"/etc/yum\.repos\.d/[^'\"\s;&|]+\.repo",
    re.IGNORECASE,
)
_YUM_REPO_BASEURL_RE = re.compile(
    r"(?:^|[^A-Za-z0-9_]|\\[rn])baseurl\s*=\s*['\"]?(?P<dep>https?://[^\s'\"\\]+)",
    re.IGNORECASE,
)
_YUM_REPO_WRITE_CONTEXT_RE = re.compile(
    r"(?:\b(?:echo|printf|tee|cat)\b|>\s*/etc/yum\.repos\.d/)",
    re.IGNORECASE,
)


def _scan_powershell_repository_sources(
    target: FileTarget,
    lines: list[str],
    existing: list[Finding],
) -> list[Finding]:
    if target.file_type not in _REGISTRY_SCRIPTABLE:
        return []
    existing_keys = {
        (finding.line_number, finding.pattern_id, finding.extracted_dep)
        for finding in existing
    }
    added: list[Finding] = []
    for line_number, line in enumerate(lines, start=1):
        if _is_script_comment_line(line):
            continue
        for dep in _extract_register_psrepository_sources(line):
            key = (line_number, "powershell-repository-source", dep)
            if key in existing_keys:
                continue
            added.append(Finding(
                file_path=target.rel_path,
                line_number=line_number,
                category=Category.REGISTRY_CONFIG,
                severity=Severity.MEDIUM,
                pattern_id="powershell-repository-source",
                matched_text=line,
                extracted_dep=dep,
                description=f"PowerShell repository source grants module install authority: {dep}",
                scanner_name=RegistryConfigScanner.name,
            ))
            existing_keys.add(key)
    return added


def _scan_dotnet_tool_add_source_urls(
    target: FileTarget,
    lines: list[str],
    existing: list[Finding],
) -> list[Finding]:
    if target.file_type not in _REGISTRY_SCRIPTABLE:
        return []
    existing_keys = {
        (finding.line_number, finding.pattern_id, finding.extracted_dep)
        for finding in existing
    }
    added: list[Finding] = []
    for line_number, line in enumerate(lines, start=1):
        if _is_script_comment_line(line) or not re.search(r"\bdotnet\s+tool\s+(?:install|update)\b", line, re.IGNORECASE):
            continue
        for source_line_number, source_line in _dotnet_tool_command_window(lines, line_number):
            for dep in _extract_dotnet_tool_add_source_urls(source_line):
                key = (source_line_number, "nuget-cli-source-url", dep)
                if key in existing_keys:
                    continue
                added.append(Finding(
                    file_path=target.rel_path,
                    line_number=source_line_number,
                    category=Category.REGISTRY_CONFIG,
                    severity=Severity.MEDIUM,
                    pattern_id="nuget-cli-source-url",
                    matched_text=source_line.strip()[:200],
                    extracted_dep=dep[:200],
                    description=f"NuGet CLI command targets external package feed: {dep}",
                    scanner_name=RegistryConfigScanner.name,
                ))
                existing_keys.add(key)
    return added


def _dotnet_tool_command_window(lines: list[str], line_number: int) -> list[tuple[int, str]]:
    start = line_number - 1
    window: list[tuple[int, str]] = []
    for index in range(start, min(len(lines), start + 10)):
        current = lines[index]
        if index > start and re.match(r"\s*-\s+(?:name|uses|run):\s+", current):
            break
        window.append((index + 1, current))
    return window


def _extract_dotnet_tool_add_source_urls(line: str) -> list[str]:
    values: list[str] = []
    for match in re.finditer(
        r"(?:--add-source)\b(?:\s+|=|:)" + _URL_WITH_GITHUB_EXPR_RE,
        line,
        re.IGNORECASE,
    ):
        values.append(match.group("dep").rstrip(",;\\\"'"))
    return _unique(values)


def _scan_npm_cli_registry_variable_urls(
    target: FileTarget,
    lines: list[str],
    existing: list[Finding],
) -> list[Finding]:
    if target.file_type not in _REGISTRY_SCRIPTABLE:
        return []
    registry_vars = _collect_npm_registry_variable_urls(lines)
    if not registry_vars:
        return []
    existing_keys = {
        (finding.line_number, finding.pattern_id, finding.extracted_dep)
        for finding in existing
    }
    added: list[Finding] = []
    for line_number, line in enumerate(lines, start=1):
        if _is_script_comment_line(line) or not _line_has_npm_registry_flag(line):
            continue
        for variable_name, dep in registry_vars.items():
            if not _line_references_registry_variable(line, variable_name):
                continue
            key = (line_number, "npm-cli-registry", dep)
            if key in existing_keys:
                continue
            added.append(Finding(
                file_path=target.rel_path,
                line_number=line_number,
                category=Category.REGISTRY_CONFIG,
                severity=Severity.MEDIUM,
                pattern_id="npm-cli-registry",
                matched_text=line.strip()[:200],
                extracted_dep=dep[:200],
                description=f"npm-compatible command uses custom registry: {dep}",
                scanner_name=RegistryConfigScanner.name,
            ))
            existing_keys.add(key)
    return added


def _scan_variable_apt_signing_key_urls(
    target: FileTarget,
    lines: list[str],
    existing: list[Finding],
) -> list[Finding]:
    if target.file_type not in {"ci", "dockerfile", "script", "github_action"}:
        return []
    existing_keys = {
        (finding.line_number, finding.pattern_id, finding.extracted_dep)
        for finding in existing
    }
    added: list[Finding] = []
    for line_number, line in enumerate(lines, 1):
        if _is_script_comment_line(line):
            continue
        dep = _extract_variable_apt_key_url(line)
        if not dep:
            continue
        key = (line_number, "apt-signing-key-download", dep)
        if key in existing_keys:
            continue
        added.append(Finding(
            file_path=target.rel_path,
            line_number=line_number,
            category=Category.REGISTRY_CONFIG,
            severity=Severity.HIGH,
            pattern_id="apt-signing-key-download",
            matched_text=line.strip()[:200],
            extracted_dep=dep[:200],
            description=f"Downloaded APT signing key grants package install authority: {dep}",
            scanner_name=RegistryConfigScanner.name,
        ))
        existing_keys.add(key)
    return added


def _scan_apt_key_adv_imports(
    target: FileTarget,
    lines: list[str],
    existing: list[Finding],
) -> list[Finding]:
    if target.file_type not in {"ci", "dockerfile", "script", "github_action"}:
        return []
    existing_keys = {
        (finding.line_number, finding.pattern_id, finding.extracted_dep)
        for finding in existing
    }
    added: list[Finding] = []
    for line_number, line in enumerate(lines, 1):
        if _is_script_comment_line(line):
            continue
        for pattern_id, dep, description in _extract_apt_key_adv_imports(line):
            key = (line_number, pattern_id, dep)
            if key in existing_keys:
                continue
            added.append(Finding(
                file_path=target.rel_path,
                line_number=line_number,
                category=Category.REGISTRY_CONFIG,
                severity=Severity.HIGH,
                pattern_id=pattern_id,
                matched_text=line.strip()[:200],
                extracted_dep=dep[:200],
                description=description.format(dep=dep[:200]),
                scanner_name=RegistryConfigScanner.name,
            ))
            existing_keys.add(key)
    return added


def _extract_apt_key_adv_imports(line: str) -> list[tuple[str, str, str]]:
    if not re.search(r"\bapt-key\s+adv\b", line, re.IGNORECASE):
        return []
    findings: list[tuple[str, str, str]] = []
    fetch_match = re.search(
        r"\bapt-key\s+adv\b[^\n]*?--fetch-keys(?:=|\s+)['\"]?(?P<dep>https?://[^\s'\";&|]+)",
        line,
        re.IGNORECASE,
    )
    if fetch_match:
        dep = fetch_match.group("dep").rstrip("'\"\\,")
        findings.append((
            "apt-signing-key-download",
            dep,
            "Downloaded APT signing key grants package install authority: {dep}",
        ))

    command_match = re.search(r"\bapt-key\s+adv\b(?P<body>[^\n]*)", line, re.IGNORECASE)
    if not command_match:
        return findings
    body = command_match.group("body")
    server_match = re.search(
        r"--keyserver(?:=|\s+)['\"]?(?P<server>[^'\"\s;&|]+)",
        body,
        re.IGNORECASE,
    )
    keys_match = re.search(
        r"--recv-keys?(?:=|\s+)(?P<keys>[^;&|\\]+)",
        body,
        re.IGNORECASE,
    )
    if not server_match or not keys_match:
        return findings
    server = server_match.group("server").rstrip("'\"\\,")
    for key_id in re.findall(r"\b[0-9A-Fa-f]{8,40}\b", keys_match.group("keys")):
        dep = f"{server}#{key_id.upper()}"
        findings.append((
            "apt-keyserver-key-import",
            dep,
            "APT keyserver import grants package install authority: {dep}",
        ))
    return findings


def _scan_yum_repo_config_writes(
    target: FileTarget,
    lines: list[str],
    existing: list[Finding],
) -> list[Finding]:
    if target.file_type not in {"ci", "dockerfile", "script", "github_action"}:
        return []
    existing_keys = {
        (finding.line_number, finding.pattern_id, finding.extracted_dep)
        for finding in existing
    }
    added: list[Finding] = []
    for line_number, line in enumerate(lines, 1):
        if _is_script_comment_line(line) or not _YUM_REPO_FILE_DEST_RE.search(line):
            continue
        start = max(0, line_number - 9)
        end = min(len(lines), line_number + 8)
        window = "\n".join(lines[start:end])
        if not _YUM_REPO_WRITE_CONTEXT_RE.search(window):
            continue
        for match in _YUM_REPO_BASEURL_RE.finditer(window):
            dep = match.group("dep").rstrip("'\"\\,;")
            if _is_local_registry_url(dep):
                continue
            key = (line_number, "yum-repo-config-write", dep)
            if key in existing_keys:
                continue
            added.append(Finding(
                file_path=target.rel_path,
                line_number=line_number,
                category=Category.REGISTRY_CONFIG,
                severity=Severity.HIGH,
                pattern_id="yum-repo-config-write",
                matched_text=line.strip()[:200],
                extracted_dep=dep[:200],
                description=f"YUM repository file grants package install authority: {dep}",
                scanner_name=RegistryConfigScanner.name,
            ))
            existing_keys.add(key)
    return added


_VARIABLE_APT_KEY_URL_RE = re.compile(
    r"""\b(?:curl|wget)\b[^\n]*?(?P<dep>(?:"?\$\{[A-Za-z_][A-Za-z0-9_]*\}"?|\$[A-Za-z_][A-Za-z0-9_]*)(?:/[^\s'"|\\]+)+)""",
    re.IGNORECASE,
)

_APT_KEY_AUTHORITY_CONTEXT_RE = re.compile(
    r"(?:apt-key\s+add\b|gpg\s+--dearmor|"
    r"(?:/etc/apt/(?:keyrings|trusted\.gpg\.d)/|/usr/share/keyrings/|apt/keyrings))",
    re.IGNORECASE,
)

_APT_SIGNING_KEY_DEP_RE = re.compile(
    r"(?:"
    r"/(?:keys?|gpgkey)/"
    r"|/(?:gpg|pubkey)(?:[?#]|$)"
    r"|[/.][^/?#]*(?:keyring|pubkey|archive-key|repo)[^/?#]*\.(?:asc|gpg|key|pub)(?:[?#]|$)"
    r"|\.(?:asc|gpg|key|pub)(?:[?#]|$)"
    r")",
    re.IGNORECASE,
)


def _extract_variable_apt_key_url(line: str) -> str | None:
    if not _APT_KEY_AUTHORITY_CONTEXT_RE.search(line):
        return None
    match = _VARIABLE_APT_KEY_URL_RE.search(line)
    if not match:
        return None
    dep = match.group("dep").strip("'\"")
    dep = dep.replace('}"/', "}/").replace("}'/", "}/")
    dep = dep.replace('"', "").replace("'", "")
    if not re.search(r"(?:/(?:keys?|gpgkey)/|[/.][^/?#]*(?:gpg|asc|key|pub)(?:[/?#]|$))", dep, re.IGNORECASE):
        return None
    return dep


def _is_apt_signing_key_dependency(dep: str) -> bool:
    dep = dep.strip("'\"")
    if dep.startswith(("${", "$")):
        return bool(re.search(r"(?:/(?:keys?|gpgkey)/|[/.][^/?#]*(?:gpg|asc|key|pub)(?:[/?#]|$))", dep, re.IGNORECASE))
    return bool(_APT_SIGNING_KEY_DEP_RE.search(dep))


def _collect_npm_registry_variable_urls(lines: list[str]) -> dict[str, str]:
    values: dict[str, str] = {}
    assignment_re = re.compile(
        r"""^\s*(?:export\s+)?(?:\$(?:env:)?(?P<ps>[A-Za-z_][A-Za-z0-9_]*)|(?P<sh>[A-Za-z_][A-Za-z0-9_]*))\s*=\s*['"](?P<url>https?://[^'"\s]+)['"]""",
        re.IGNORECASE,
    )
    for line in lines:
        if _is_script_comment_line(line):
            continue
        match = assignment_re.search(line)
        if not match:
            continue
        variable_name = match.group("ps") or match.group("sh") or ""
        dep = match.group("url").rstrip(",;\\\"'")
        if _is_npm_registry_variable_name(variable_name):
            values[variable_name] = dep
    return values


def _is_npm_registry_variable_name(name: str) -> bool:
    lowered = name.lower()
    return "npm" in lowered and ("registry" in lowered or "feed" in lowered)


def _line_has_npm_registry_flag(line: str) -> bool:
    return bool(
        re.search(r"\b(?:npm|pnpm|yarn)\s+(?:install|i|add|ci|update|upgrade)\b", line, re.IGNORECASE)
        and re.search(r"--(?:registry|npm-registry-server)(?:=|\s+)", line, re.IGNORECASE)
    )


def _line_references_registry_variable(line: str, variable_name: str) -> bool:
    escaped = re.escape(variable_name)
    return bool(re.search(
        rf"\$(?:env:)?{escaped}\b|\$\{{{escaped}\}}|%{escaped}%",
        line,
        re.IGNORECASE,
    ))


def _extract_register_psrepository_sources(line: str) -> list[str]:
    values: list[str] = []
    command_re = re.compile(r"\bRegister-PSRepository\b(?P<body>[^#\n;|]*)", re.IGNORECASE)
    for match in command_re.finditer(line):
        if _command_match_is_inert_quoted_string(line, match.start()):
            continue
        tokens = _simple_shell_tokens(match.group("body"))
        i = 0
        while i < len(tokens):
            token = tokens[i].rstrip(",;")
            lower = token.lower()
            value = ""
            if lower in {"-sourcelocation"} and i + 1 < len(tokens):
                value = tokens[i + 1].rstrip(",;")
                i += 2
            elif lower.startswith("-sourcelocation:") or lower.startswith("-sourcelocation="):
                value = token.split(":", 1)[1] if ":" in token else token.split("=", 1)[1]
                i += 1
            else:
                i += 1
            value = value.strip("'\"")
            if _is_external_powershell_repository_source(value):
                values.append(value)
    return _unique(values)


def _is_external_powershell_repository_source(value: str) -> bool:
    if re.match(r"https?://", value, re.IGNORECASE):
        return True
    if not value.startswith("$"):
        return False
    variable_name = value.strip("${}").replace("env:", "").replace("Env:", "")
    return bool(re.search(r"(?:url|source|feed|registry|repository|gallery)", variable_name, re.IGNORECASE))


def _simple_shell_tokens(text: str) -> list[str]:
    return [token.strip("'\"") for token in re.findall(r'''(?:"[^"]*"|'[^']*'|\S+)''', text) if token.strip("'\"")]


def _command_match_is_inert_quoted_string(line: str, match_start: int) -> bool:
    prefix = line[:match_start].strip()
    if re.search(r"\b(?:powershell(?:\.exe)?|pwsh(?:\.exe)?)\b", prefix, re.IGNORECASE):
        return False
    quote_start = _unclosed_quote_start(line, match_start)
    if quote_start is not None:
        before_quote = line[:quote_start].strip()
        if re.search(r"(?:^|\s)(?:-[A-Za-z]*c|/c|--command)\s*$", before_quote, re.IGNORECASE):
            return False
        return True
    return False


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


def _is_script_comment_line(line: str) -> bool:
    stripped = line.lstrip()
    return stripped.startswith("#") and not stripped.startswith("#!")


def _unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            out.append(value)
    return out


def _is_canonical_npm_registry(url: str) -> bool:
    return url.rstrip("/").lower() in {
        "https://registry.npmjs.org",
        "http://registry.npmjs.org",
        "https://registry.npmjs.com",
        "http://registry.npmjs.com",
    }


def _is_local_registry_url(url: str) -> bool:
    return bool(re.match(
        r"^https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[?::1\]?)(?:[:/]|$)",
        url,
        re.IGNORECASE,
    ))


def _is_canonical_pypi_index(url: str) -> bool:
    return url.rstrip("/").lower() in {
        "https://pypi.org/simple",
        "http://pypi.org/simple",
        "https://pypi.python.org/simple",
        "http://pypi.python.org/simple",
    }


def _is_azure_pipelines_task_test_npmrc(target: FileTarget) -> bool:
    if target.path.name != ".npmrc":
        return False
    parts = tuple(part for part in target.rel_path.replace("\\", "/").split("/") if part)
    for index, part in enumerate(parts[:-3]):
        if part in {"Tasks", "_generated"} and parts[index + 2:index + 4] == ("Tests", ".npmrc"):
            return True
    return False


def _is_registry_test_fixture_file(target: FileTarget) -> bool:
    parts = tuple(part.lower() for part in target.rel_path.replace("\\", "/").split("/") if part)
    if not parts:
        return False

    has_test_path = any(part in {"test", "tests", "__tests__"} or part.endswith("tests") for part in parts[:-1])
    if not has_test_path:
        return False

    return any(
        part in {"fixture", "fixtures", "__fixtures__", "mock", "mocks", "resource", "resources", "testdata", "test_data"}
        for part in parts[:-1]
    )


def _dedupe_yarn_registry_findings(findings: list[Finding]) -> list[Finding]:
    yarn_registry_keys = {
        (finding.line_number, finding.extracted_dep)
        for finding in findings
        if finding.pattern_id == "yarnrc-npm-registry"
    }
    return [
        finding for finding in findings
        if not (
            finding.pattern_id == "yarnrc-npm-scope"
            and (finding.line_number, finding.extracted_dep) in yarn_registry_keys
        )
    ]


def _is_canonical_nuget_feed(url: str) -> bool:
    return url.rstrip("/").lower() in {
        "https://api.nuget.org/v3/index.json",
        "https://www.nuget.org/api/v2",
        "http://www.nuget.org/api/v2",
    }


def _strip_xml_comments(lines: list[str]) -> list[str]:
    stripped_lines: list[str] = []
    in_comment = False
    for line in lines:
        cursor = 0
        kept = []
        while cursor < len(line):
            if in_comment:
                end = line.find("-->", cursor)
                if end == -1:
                    cursor = len(line)
                    break
                cursor = end + 3
                in_comment = False
                continue

            start = line.find("<!--", cursor)
            if start == -1:
                kept.append(line[cursor:])
                break
            kept.append(line[cursor:start])
            cursor = start + 4
            in_comment = True
        stripped_lines.append("".join(kept))
    return stripped_lines
