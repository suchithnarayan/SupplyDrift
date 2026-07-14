"""Category 6: Unpinned GitHub Actions, tool installs in CI run blocks, multi-platform CI."""
from __future__ import annotations

import re

from github_inventory.discovery import FileTarget
from github_inventory.models import Category, Finding, Severity
from github_inventory.scanners.base import BaseScanner, PatternRule

_SHA_PATTERN = r"[0-9a-f]{40}"
_MUTABLE_BRANCH = r"(?:main|master|develop|dev|HEAD|stable|trunk|edge|nightly|canary|latest)"
_LOCALHOST = r"localhost|127\.0\.0\.1|0\.0\.0\.0|::1"
_SHELL_SUBST = r"\$\([^)\n]*\)"
_URL_TOKEN = (
    r"https?://(?!" + _LOCALHOST + r")"
    r"(?:(?:\$\{\{.*?\}\})|(?:" + _SHELL_SUBST + r")|[^'\"\s])+"
)
_METADATA_DOC_URL_RE = re.compile(r"\.(?:json|ya?ml)(?:[?#]|$)", re.IGNORECASE)
_METADATA_DOC_OUTPUT_RE = re.compile(
    r"(?:^|\s)(?:-[A-Za-z]*o\b|--output(?:=|\s+))\s*['\"]?[^'\"\s|]+\.(?:json|ya?ml)(?:['\"]|\s|$)",
    re.IGNORECASE,
)
_MUTABLE_RUNNER_LABEL_RE = re.compile(
    r"(?:[\w-]+-)?(?:ubuntu|windows|macos)-latest|ubuntu-slim",
    re.IGNORECASE,
)
_TAIKI_E_INSTALL_ACTION_RE = re.compile(
    r"uses:\s*['\"]?(?P<action>taiki-e/(?:install-action|cache-cargo-install-action)@[^\s'\"]+)",
    re.IGNORECASE,
)
_ACTION_TOOL_INPUT_RE = re.compile(r"^\s*(?:tool|tools):\s*(?P<tools>.+?)\s*$", re.IGNORECASE)
_ACTION_GIT_SOURCE_INPUT_RE = re.compile(r"^\s*git:\s*(?P<git>.+?)\s*$", re.IGNORECASE)
_ACTION_GIT_REF_INPUT_RE = re.compile(r"^\s*(?P<key>rev|tag|branch):\s*(?P<value>.+?)\s*$", re.IGNORECASE)
_ACTION_TOOL_DEP_RE = re.compile(r"[\w][\w.+/-]*(?:@[\w.+-]+)?")


class CICDToolScanner(BaseScanner):
    name = "cicd-tools"

    def scan_file_content(self, target: FileTarget, content: str, lines: list[str]) -> list[Finding]:
        findings = super().scan_file_content(target, content, lines)
        findings.extend(_expand_mutable_runner_labels(target, lines, findings))
        findings.extend(_scan_action_tool_installer_inputs(target, lines, findings))
        findings = [
            f for f in findings
            if not (
                f.pattern_id in {"unpinned-github-action-1p", "unpinned-github-action-3p"}
                and "/.github/workflows/" in f.extracted_dep
            )
            and not (
                f.pattern_id == "mutable-github-runner"
                and ".github/workflows/" not in f.file_path
            )
            and not (
                f.pattern_id == "azure-pipelines-mutable-image"
                and ".github/workflows/" in f.file_path
            )
            and not _is_metadata_document_download(f)
        ]
        return _dedupe_findings_by_file_dependency(findings)

    def register_rules(self) -> None:
        # --- GitHub Actions ---

        self.add_rule(PatternRule(
            pattern_id="action-on-mutable-branch",
            regex=re.compile(
                r"uses:\s*['\"]?(?P<dep>[\w.-]+/[\w./-]+@" + _MUTABLE_BRANCH + r")['\"]?",
                re.IGNORECASE,
            ),
            severity=Severity.CRITICAL,
            description_template="GitHub Action pinned to mutable branch (supply chain risk): {dep}",
            category=Category.CICD_TOOL,
            file_types=["ci", "github_action"],
        ))

        # 1st-party actions (actions/*, github/*) -- lower risk, GitHub controls the namespace
        self.add_rule(PatternRule(
            pattern_id="unpinned-github-action-1p",
            regex=re.compile(
                r"uses:\s*['\"]?(?P<dep>"
                r"(?:actions|github)/[\w./-]+@"
                r"(?!" + _SHA_PATTERN + r")"
                r"(?!" + _MUTABLE_BRANCH + r")"
                r"[\w./-]+)['\"]?",
                re.IGNORECASE,
            ),
            severity=self._tag_severity("unpinned-github-action-1p", Severity.MEDIUM),
            description_template="GitHub 1st-party Action not pinned to SHA (tag can be moved): {dep}",
            category=Category.CICD_TOOL,
            file_types=["ci", "github_action"],
        ))

        # 3rd-party actions -- higher risk, external org controls the namespace
        self.add_rule(PatternRule(
            pattern_id="unpinned-github-action-3p",
            regex=re.compile(
                r"uses:\s*['\"]?(?P<dep>"
                r"(?!\./)(?!actions/|github/)[\w.-]+/[\w./-]+@"
                r"(?!" + _SHA_PATTERN + r")"
                r"(?!" + _MUTABLE_BRANCH + r")"
                r"[\w./-]+)['\"]?",
                re.IGNORECASE,
            ),
            severity=self._tag_severity("unpinned-github-action-3p", Severity.HIGH),
            description_template="GitHub 3rd-party Action not pinned to SHA (tag can be moved): {dep}",
            category=Category.CICD_TOOL,
            file_types=["ci", "github_action"],
        ))

        # Reusable workflows: uses: org/repo/.github/workflows/file.yml@ref
        self.add_rule(PatternRule(
            pattern_id="reusable-workflow-unpinned",
            regex=re.compile(
                r"uses:\s*['\"]?(?P<dep>[\w.-]+/[\w.-]+/\.github/workflows/[\w.-]+@"
                r"(?!" + _SHA_PATTERN + r")[\w./-]+)['\"]?",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="Reusable workflow not pinned to SHA: {dep}",
            category=Category.CICD_TOOL,
            file_types=["ci", "github_action"],
        ))

        # GHA hosted runner labels like ubuntu-latest are mutable execution
        # environments. Keep this to direct scalar values; matrix resolution is
        # a separate analysis pass.
        self.add_rule(PatternRule(
            pattern_id="mutable-github-runner",
            regex=re.compile(
                r"^\s*runs-on:\s*(?:.*?['\"])?"
                r"(?P<dep>(?:[\w-]+-)?(?:ubuntu|windows|macos)-latest|ubuntu-slim)"
                r"(?:['\"]?.*)$",
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="GitHub Actions hosted runner label is mutable: {dep}",
            category=Category.CICD_TOOL,
            file_types=["ci", "github_action"],
        ))

        # Azure Pipelines hosted image labels are mutable aliases, similar to
        # GitHub's hosted runner labels. Match only known hosted labels so pool
        # names and container image refs stay out of this CI-tool rule.
        self.add_rule(PatternRule(
            pattern_id="azure-pipelines-mutable-image",
            regex=re.compile(
                r"^\s*(?:vmImage|image):\s*(?:.*?['\"])?"
                r"(?P<dep>(?:ubuntu|windows|macos)-latest|ubuntu-slim)"
                r"(?:['\"]?.*)$",
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="Azure Pipelines hosted image label is mutable: {dep}",
            category=Category.CICD_TOOL,
            file_types=["ci"],
        ))

        # GHA job-level container: image
        self.add_rule(PatternRule(
            pattern_id="gha-container-image",
            regex=re.compile(
                r"^\s+container:\s*\n\s+image:\s*['\"]?(?P<dep>[\w./:@-]+)['\"]?",
                re.MULTILINE,
            ),
            severity=Severity.HIGH,
            description_template="GitHub Actions job container image (shadow dependency): {dep}",
            category=Category.CONTAINER_IMAGE,
            file_types=["ci", "github_action"],
            multiline=True,
        ))

        # GHA job-level container: <image> (short form)
        self.add_rule(PatternRule(
            pattern_id="gha-container-image-short",
            regex=re.compile(
                r"^\s+container:\s+['\"]?(?P<dep>[\w./:-]+(?:@sha256:[a-f0-9]+)?)['\"]?\s*$",
                re.MULTILINE,
            ),
            severity=Severity.HIGH,
            description_template="GitHub Actions job container image (shadow dependency): {dep}",
            category=Category.CONTAINER_IMAGE,
            file_types=["ci", "github_action"],
        ))

        self.add_rule(PatternRule(
            pattern_id="gha-docker-action-image",
            regex=re.compile(
                r"uses:\s*['\"]?docker://(?P<dep>[\w./:@-]+(?:@sha256:[a-f0-9]+)?)['\"]?",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="GitHub Action runs container image directly: {dep}",
            category=Category.CONTAINER_IMAGE,
            file_types=["ci", "github_action"],
        ))

        # GHA services: <name>: image: <image>
        self.add_rule(PatternRule(
            pattern_id="gha-service-image",
            regex=re.compile(
                r"services:\s*\n(?:\s+[\w-]+:\s*\n(?:\s+\w[^\n]*\n)*)*\s+image:\s*['\"]?(?P<dep>[\w./:@-]+)['\"]?",
                re.MULTILINE,
            ),
            severity=Severity.HIGH,
            description_template="GitHub Actions service container image (shadow dependency): {dep}",
            category=Category.CONTAINER_IMAGE,
            file_types=["ci"],
            multiline=True,
        ))

        # Tool download in CI step. Require an actual download verb (-o, -O,
        # > redirect, or pipe to extractor) to avoid false-positives on
        # curl-based API calls (e.g. POST/PATCH to api.github.com/repos/.../comments
        # for PR comment posting). Hostnames matching well-known *API* endpoints
        # are explicitly excluded.
        self.add_rule(PatternRule(
            pattern_id="tool-download-in-ci",
            regex=re.compile(
                r"(?:curl|wget)\b"
                # Negative lookahead: skip lines with -X POST/PATCH/PUT/DELETE
                # (these are API mutations, not downloads).
                r"(?![^\n|]*?-X\s+(?:POST|PATCH|PUT|DELETE))"
                # Negative lookahead: skip GitHub/Slack/PagerDuty API hosts.
                r"(?![^\n|]*?https?://(?:api\.github\.com|hooks\.slack\.com|events\.pagerduty\.com|api\.gitlab\.com|api\.bitbucket\.org)/)"
                r"[^\n|]*?"
                # Must look like a download: -o/-O flag, > redirect, or pipe
                # into tar/unzip/gunzip/install/sh/bash.
                r"(?:"
                # curl commonly combines flags: -LO, -fsSLO, -fsSLo <file>.
                r"-(?=(?-i:[A-Za-z]*O))[A-Za-z]+\s+"
                r"|-(?=(?-i:[A-Za-z]*o))[A-Za-z]+\s+[^\s|]+\s+"
                r"|--output(?:=|\s+)[^\s|]+\s+"
                r"|>\s*[^\s|]+"
                r"|\|\s*(?:tar|unzip|gunzip|install)"
                r")"
                r"[^\n]*?['\"]?(?P<dep>" + _URL_TOKEN + r")",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="Tool downloaded inside CI workflow step: {dep}",
            category=Category.CICD_TOOL,
            file_types=["ci", "github_action"],
        ))
        self.add_rule(PatternRule(
            pattern_id="tool-download-in-ci",
            regex=re.compile(
                r"\bbitsadmin(?:\.exe)?\b[^\n]*?/DOWNLOAD\b[^\n]*?['\"]?"
                r"(?P<dep>" + _URL_TOKEN + r")",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="Tool downloaded inside CI workflow step: {dep}",
            category=Category.CICD_TOOL,
            file_types=["ci", "github_action"],
        ))

        # --- GitLab CI ---

        self.add_rule(PatternRule(
            pattern_id="gitlab-remote-include",
            regex=re.compile(
                r"include:\s*\n(?:\s+-\s+[^\n]+\n)*\s+-\s+remote:\s*['\"]?(?P<dep>https?://\S+)['\"]?",
                re.IGNORECASE | re.MULTILINE,
            ),
            severity=Severity.HIGH,
            description_template="GitLab CI includes remote file: {dep}",
            category=Category.CICD_TOOL,
            file_types=["ci"],
            multiline=True,
        ))

        # --- Jenkins ---

        self.add_rule(PatternRule(
            pattern_id="jenkins-shared-library",
            regex=re.compile(
                r"@Library\s*\(\s*['\"](?P<dep>[^'\"]+)['\"]",
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="Jenkins shared library loaded externally: {dep}",
            category=Category.CICD_TOOL,
            file_types=["ci"],
        ))

        # --- CircleCI orbs ---
        # Multiline: match org/name@version lines only under an `orbs:` key.
        # This avoids false positives on GitHub Actions `uses:` lines.
        self.add_rule(PatternRule(
            pattern_id="circleci-orb",
            regex=re.compile(
                r"^orbs:\s*\n(?:\s+[\w-]+:\s*[^\n]*\n)*?\s+[\w-]+:\s*(?P<dep>[\w-]+/[\w-]+@\S+)",
                re.MULTILINE,
            ),
            severity=Severity.HIGH,
            description_template="CircleCI orb (third-party CI component): {dep}",
            category=Category.CICD_TOOL,
            file_types=["ci"],
            multiline=True,
        ))

        # --- Bitbucket Pipelines pipes ---

        self.add_rule(PatternRule(
            pattern_id="bitbucket-pipe",
            regex=re.compile(
                r"pipe:\s*(?P<dep>[\w-]+/[\w.-]+:[\w.-]+)",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="Bitbucket Pipelines pipe (third-party plugin): {dep}",
            category=Category.CICD_TOOL,
            file_types=["ci"],
        ))

        # --- Azure DevOps tasks ---

        self.add_rule(PatternRule(
            pattern_id="azure-devops-task",
            regex=re.compile(
                r"-\s*task:\s*(?P<dep>[\w]+@\d+)",
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="Azure DevOps marketplace task: {dep}",
            category=Category.CICD_TOOL,
            file_types=["ci"],
        ))

        # --- Drone / Woodpecker plugin images ---

        self.add_rule(PatternRule(
            pattern_id="drone-plugin-image",
            regex=re.compile(
                r"image:\s*['\"]?(?P<dep>plugins/[\w.-]+(?::[\w.-]+)?)['\"]?",
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="Drone/Woodpecker plugin image: {dep}",
            category=Category.CICD_TOOL,
            file_types=["ci"],
        ))

        # --- Buildkite plugins ---

        self.add_rule(PatternRule(
            pattern_id="buildkite-plugin",
            regex=re.compile(
                r"plugins:\s*\n(?:\s+-\s+[^\n]*\n)*?\s+-\s+(?P<dep>[\w.-]+/[\w.-]+#[\w.-]+)",
                re.MULTILINE,
            ),
            severity=Severity.MEDIUM,
            description_template="Buildkite plugin (third-party CI component): {dep}",
            category=Category.CICD_TOOL,
            file_types=["ci"],
            multiline=True,
        ))

        # --- GitHub Actions pull_request_target (code injection risk) ---

        self.add_rule(PatternRule(
            pattern_id="gha-pull-request-target",
            regex=re.compile(
                r"on:\s*(?:\n\s+)?(?P<dep>pull_request_target)\b",
                re.MULTILINE,
            ),
            severity=Severity.HIGH,
            description_template="GitHub Actions uses pull_request_target trigger (code injection risk): {dep}",
            category=Category.CICD_TOOL,
            file_types=["ci"],
        ))

        # --- Tekton bundle references ---

        self.add_rule(PatternRule(
            pattern_id="tekton-bundle-ref",
            regex=re.compile(
                r"(?:taskRef|pipelineRef):\s*\n\s+bundle:\s*['\"]?(?P<dep>[\w./:-]+)['\"]?",
                re.MULTILINE,
            ),
            severity=Severity.MEDIUM,
            description_template="Tekton references external OCI bundle: {dep}",
            category=Category.CICD_TOOL,
            file_types=["ci", "k8s"],
            multiline=True,
        ))

    def _tag_severity(self, pattern_id: str, default: Severity) -> Severity:
        for key in (pattern_id, "unpinned-github-action"):
            override = self.config.severity_overrides.get(key)
            if override:
                return Severity(override)
        return default


def _is_metadata_document_download(finding: Finding) -> bool:
    if finding.pattern_id != "tool-download-in-ci":
        return False
    return bool(
        _METADATA_DOC_URL_RE.search(finding.extracted_dep)
        and _METADATA_DOC_OUTPUT_RE.search(finding.matched_text)
    )


def _dedupe_findings_by_file_dependency(findings: list[Finding]) -> list[Finding]:
    deduped: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()
    for finding in findings:
        key = (finding.file_path, finding.pattern_id, finding.extracted_dep)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped


def _expand_mutable_runner_labels(
    target: FileTarget,
    lines: list[str],
    existing: list[Finding],
) -> list[Finding]:
    if target.file_type not in {"ci", "github_action"}:
        return []

    existing_keys = {
        (finding.line_number, finding.extracted_dep.lower())
        for finding in existing
        if finding.pattern_id == "mutable-github-runner"
    }
    added: list[Finding] = []
    for line_number, line in enumerate(lines, start=1):
        if "runs-on:" not in line:
            continue
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        for match in _MUTABLE_RUNNER_LABEL_RE.finditer(line):
            dep = match.group(0)
            key = (line_number, dep.lower())
            if key in existing_keys:
                continue
            added.append(Finding(
                file_path=target.rel_path,
                line_number=line_number,
                category=Category.CICD_TOOL,
                severity=Severity.MEDIUM,
                pattern_id="mutable-github-runner",
                matched_text=stripped[:200],
                extracted_dep=dep,
                description=f"GitHub Actions hosted runner label is mutable: {dep}",
                scanner_name=CICDToolScanner.name,
            ))
            existing_keys.add(key)
    return added


def _scan_action_tool_installer_inputs(
    target: FileTarget,
    lines: list[str],
    existing: list[Finding],
) -> list[Finding]:
    if target.file_type not in {"ci", "github_action"}:
        return []

    existing_keys = {
        (finding.line_number, finding.pattern_id, finding.extracted_dep)
        for finding in existing
        if finding.pattern_id in {
            "github-action-tool-installer",
            "github-action-tool-installer-git-source",
        }
    }
    added: list[Finding] = []
    for line_number, line in enumerate(lines, start=1):
        action_match = _TAIKI_E_INSTALL_ACTION_RE.search(line)
        if not action_match:
            continue
        action = action_match.group("action")
        git_line_number = 0
        git_input_line = ""
        git_url = ""
        git_ref = ""
        for input_line_number in range(line_number + 1, min(len(lines), line_number + 12) + 1):
            input_line = lines[input_line_number - 1]
            if input_line_number > line_number + 1 and re.match(r"\s*-\s+(?:name|uses|run):\s+", input_line):
                break
            input_match = _ACTION_TOOL_INPUT_RE.match(input_line)
            if input_match:
                for dep in _extract_action_tool_input_deps(input_match.group("tools")):
                    key = (input_line_number, "github-action-tool-installer", dep)
                    if key in existing_keys:
                        continue
                    added.append(Finding(
                        file_path=target.rel_path,
                        line_number=input_line_number,
                        category=Category.CICD_TOOL,
                        severity=Severity.MEDIUM,
                        pattern_id="github-action-tool-installer",
                        matched_text=input_line.strip()[:200],
                        extracted_dep=dep,
                        description=f"GitHub Action installs CI tool via input: {dep} ({action})",
                        scanner_name=CICDToolScanner.name,
                    ))
                    existing_keys.add(key)
                continue
            git_match = _ACTION_GIT_SOURCE_INPUT_RE.match(input_line)
            if git_match:
                git_url = _clean_action_input_scalar(git_match.group("git"))
                git_line_number = input_line_number
                git_input_line = input_line
                continue
            ref_match = _ACTION_GIT_REF_INPUT_RE.match(input_line)
            if ref_match:
                ref_value = _clean_action_input_scalar(ref_match.group("value"))
                if _is_concrete_action_git_ref(ref_value):
                    git_ref = f"{ref_match.group('key').lower()}={ref_value}"
        if _is_concrete_action_git_url(git_url) and git_line_number:
            dep = f"{git_url}#{git_ref}" if git_ref else git_url
            key = (git_line_number, "github-action-tool-installer-git-source", dep)
            if key not in existing_keys:
                added.append(Finding(
                    file_path=target.rel_path,
                    line_number=git_line_number,
                    category=Category.CICD_TOOL,
                    severity=Severity.MEDIUM,
                    pattern_id="github-action-tool-installer-git-source",
                    matched_text=git_input_line.strip()[:200],
                    extracted_dep=dep[:200],
                    description=f"GitHub Action installs CI tool from git source: {dep} ({action})",
                    scanner_name=CICDToolScanner.name,
                ))
                existing_keys.add(key)
    return added


def _extract_action_tool_input_deps(value: str) -> list[str]:
    value = _clean_action_input_scalar(value)
    if not value or value in {"|", ">", "[]"}:
        return []
    deps: list[str] = []
    for part in re.split(r"\s*,\s*", value):
        dep = part.strip().strip("'\"")
        if not dep or dep.startswith(("$", "${{")) or "${{" in dep or "}}" in dep:
            continue
        if _ACTION_TOOL_DEP_RE.fullmatch(dep):
            deps.append(dep)
    return deps


def _clean_action_input_scalar(value: str) -> str:
    return re.split(r"\s+#", value, maxsplit=1)[0].strip().strip("'\"")


def _is_concrete_action_git_url(value: str) -> bool:
    if not value or value.startswith(("$", "${{", ".", "/", "\\")):
        return False
    if any(part in value for part in ("${", "$(", "`", "<", ">")):
        return False
    return bool(re.fullmatch(r"(?:https?|ssh|git)://[^\s#]+|git@[^:\s]+:[^\s#]+", value))


def _is_concrete_action_git_ref(value: str) -> bool:
    if not value or value.startswith(("$", "${{")):
        return False
    if any(part in value for part in ("${", "$(", "`", "<", ">")):
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9._/+~-]+", value))
