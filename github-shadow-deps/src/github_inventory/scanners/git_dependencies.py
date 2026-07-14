"""Category 4: git clone, .gitmodules, pip git+https."""
from __future__ import annotations

import re

from github_inventory.discovery import FileTarget
from github_inventory.models import Category, Finding, Severity
from github_inventory.scanners.base import BaseScanner, PatternRule
from github_inventory.scanners.source_shell import iter_javascript_shell_commands, iter_python_shell_commands

_PYPI_INDEX_OR_UPLOAD_RE = re.compile(
    r"^https?://(?:(?:www\.|upload\.)?pypi\.org|test\.pypi\.org)/(?:simple|legacy)/?$",
    re.IGNORECASE,
)
_GHA_EXPRESSION_PATTERN = r"\$\{\{[^\n]*?\}\}"
_GIT_REMOTE_URL_PATTERN = (
    r"(?:(?:https?://|ssh://|git://)"
    rf"(?:{_GHA_EXPRESSION_PATTERN}|(?:(?!\$\{{\{{)[^\s'\"`)])+)+"
    r"|git@"
    rf"(?:{_GHA_EXPRESSION_PATTERN}|(?:(?!\$\{{\{{)[^\s'\"`)])+)+)"
)


class GitDependencyScanner(BaseScanner):
    name = "git-dependencies"

    def scan_file(self, target: FileTarget) -> list[Finding]:
        if target.file_type == "source_code" and target.path.suffix.lower() in {
            ".py", ".js", ".mjs", ".cjs", ".ts", ".mts", ".jsx", ".tsx",
        }:
            try:
                content = target.path.read_text(errors="replace")
            except OSError:
                return []
            return self.scan_file_content(target, content, content.splitlines())
        return super().scan_file(target)

    def scan_file_content(self, target: FileTarget, content: str, lines: list[str]) -> list[Finding]:
        findings = super().scan_file_content(target, content, lines)
        findings.extend(_scan_python_shell_git_clones(target, content, lines))
        findings.extend(self._scan_source_shell_git_dependencies(target, content, lines, findings))
        findings.extend(_scan_github_actions_checkout_repositories(target, lines))
        findings.extend(_scan_azure_pipelines_repository_resources(target, lines))
        _normalize_git_clone_deps(findings, lines)
        _normalize_git_url_deps(findings)
        findings = [
            finding for finding in findings
            if not _is_ci_metadata_finding(target, finding, lines)
            and not _is_package_config_comment_finding(target, finding, lines)
            and not _is_default_pyproject_package_index(finding)
            and not _is_pyproject_package_index_source_finding(target, finding, lines)
            and not _is_non_control_markdown_git_example(target, finding, lines)
        ]
        if _is_pyproject_file(target.rel_path):
            return _dedupe_findings_by_file_dependency(findings)
        return _dedupe_findings_by_file_dependency([
            finding for finding in findings
            if finding.pattern_id != "pyproject-git-source"
        ])

    def _scan_source_shell_git_dependencies(
        self,
        target: FileTarget,
        content: str,
        lines: list[str],
        existing: list[Finding],
    ) -> list[Finding]:
        if target.file_type != "source_code":
            return []
        existing_keys = {
            (finding.line_number, finding.pattern_id, finding.extracted_dep)
            for finding in existing
        }
        added: list[Finding] = []
        shell_target = FileTarget(path=target.path, rel_path=target.rel_path, file_type="script")
        commands = [
            *iter_python_shell_commands(target, content, lines),
            *iter_javascript_shell_commands(target, content, lines),
        ]
        for command in commands:
            for finding in super().scan_file_content(shell_target, command.command, [command.command]):
                key = (command.line_number, finding.pattern_id, finding.extracted_dep)
                if key in existing_keys:
                    continue
                finding.line_number = command.line_number
                finding.matched_text = command.command[:200]
                added.append(finding)
                existing_keys.add(key)
        return added

    def register_rules(self) -> None:
        # git clone https:// or git@
        self.add_rule(PatternRule(
            pattern_id="git-clone",
            regex=re.compile(
                r"git\s+clone\b[^\n]*?['\"]?(?P<dep>(?:https?://|ssh://|git://|git@)[^\s'\"]+)",
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="git clone pulls external repository: {dep}",
            category=Category.GIT_DEPENDENCY,
            file_types=["ci", "script", "build", "dockerfile", "agent_instruction"],
        ))

        # .gitmodules url entries
        self.add_rule(PatternRule(
            pattern_id="git-submodule-url",
            regex=re.compile(
                r"^\s*url\s*=\s*(?P<dep>\S+)",
                re.MULTILINE,
            ),
            severity=Severity.MEDIUM,
            description_template="Git submodule external reference: {dep}",
            category=Category.GIT_DEPENDENCY,
            file_types=["gitmodules"],
        ))

        # pip install git+https://
        self.add_rule(PatternRule(
            pattern_id="pip-git-install",
            regex=re.compile(
                r"pip3?\s+install\s+[^;&|\n]*?(?P<dep>git\+https?://[^\s'\"`]+)",
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="pip installing directly from git repository: {dep}",
            category=Category.GIT_DEPENDENCY,
            file_types=["ci", "script", "build", "dockerfile", "agent_instruction", "package_config"],
        ))

        # requirements.txt / constraints.txt: git+https lines
        self.add_rule(PatternRule(
            pattern_id="requirements-git-dep",
            regex=re.compile(
                r"^(?P<dep>git\+https?://\S+)",
                re.MULTILINE | re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="Git dependency in requirements/constraints file: {dep}",
            category=Category.GIT_DEPENDENCY,
            file_types=["pip_config"],
        ))

        # go get (older style)
        self.add_rule(PatternRule(
            pattern_id="go-get",
            regex=re.compile(
                r"\bgo\s+get\s+(?:-[\w-]+(?:=\S+)?\s+)*(?P<dep>(?![.-])\S+)",
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="go get pulls external module: {dep}",
            category=Category.GIT_DEPENDENCY,
            file_types=["ci", "script"],
        ))

        # git subtree add/pull/push — pulls third-party code into the repo
        # at a known prefix. Visible only because someone runs this command;
        # nothing in .gitmodules.
        self.add_rule(PatternRule(
            pattern_id="git-subtree",
            regex=re.compile(
                r"git\s+subtree\s+(?:add|pull|push)\s+(?:--[\w=-]+(?:\s+\S+)?\s+)*"
                r"(?P<dep>\S+)",
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="git subtree pulls/pushes external repo content: {dep}",
            category=Category.GIT_DEPENDENCY,
            file_types=["ci", "script", "build"],
        ))

        # git remote add — registers a new remote, often paired with subtree
        # or for fetching code outside the public origin.
        self.add_rule(PatternRule(
            pattern_id="git-remote-add",
            regex=re.compile(
                r"git\s+remote\s+add\s+(?:-\S+\s+)*\S+\s+['\"]?(?P<dep>"
                + _GIT_REMOTE_URL_PATTERN
                + r")",
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="git remote add registers external repo: {dep}",
            category=Category.GIT_DEPENDENCY,
            file_types=["ci", "script", "build"],
        ))

        # git submodule add <url> [path] — dynamic submodule registration
        # (vs. static .gitmodules which is covered by git-submodule-url).
        self.add_rule(PatternRule(
            pattern_id="git-submodule-add",
            regex=re.compile(
                r"git\s+submodule\s+add\s+(?:--[\w=-]+(?:\s+\S+)?\s+)*"
                r"(?P<dep>(?:https?://|git@|ssh://|git://)\S+)",
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="git submodule add registers external repo: {dep}",
            category=Category.GIT_DEPENDENCY,
            file_types=["ci", "script", "build"],
        ))

        # requirements.txt / constraints.txt: direct URL wheel/tarball deps
        self.add_rule(PatternRule(
            pattern_id="requirements-url-dep",
            regex=re.compile(
                r"^(?P<dep>https?://\S+\.(?:whl|tar\.gz|zip))",
                re.MULTILINE | re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="Direct URL dependency in requirements file: {dep}",
            category=Category.GIT_DEPENDENCY,
            file_types=["pip_config"],
        ))

        # pyproject.toml (Poetry) git/url source
        self.add_rule(PatternRule(
            pattern_id="pyproject-git-source",
            regex=re.compile(
                r'(?<![\w.-])(?:url|git)\s*=\s*"(?P<dep>(?:https?://|git\+https?://|git@)\S+?)"',
            ),
            severity=Severity.MEDIUM,
            description_template="pyproject.toml dependency from git/URL source: {dep}",
            category=Category.GIT_DEPENDENCY,
            file_types=["package_config"],
        ))


def _is_pyproject_file(path: str) -> bool:
    return path.replace("\\", "/").endswith("pyproject.toml")


def _is_default_pyproject_package_index(finding: Finding) -> bool:
    return finding.pattern_id == "pyproject-git-source" and bool(_PYPI_INDEX_OR_UPLOAD_RE.match(finding.extracted_dep))


def _is_pyproject_package_index_source_finding(
    target: FileTarget,
    finding: Finding,
    lines: list[str],
) -> bool:
    if finding.pattern_id != "pyproject-git-source" or not _is_pyproject_file(target.rel_path):
        return False
    if not (0 < finding.line_number <= len(lines)):
        return False
    if not re.match(r"\s*url\s*=", lines[finding.line_number - 1]):
        return False
    return _pyproject_table_for_line(lines, finding.line_number) in _PYPROJECT_PACKAGE_INDEX_TABLES


def _pyproject_table_for_line(lines: list[str], line_number: int) -> str:
    for index in range(line_number - 1, -1, -1):
        match = _PYPROJECT_TABLE_RE.match(lines[index])
        if match:
            return match.group("table").strip().strip("'\"")
    return ""


_GIT_CLONE_RE = re.compile(r"\bgit\s+clone\b", re.IGNORECASE)
_PIP_GIT_INSTALL_RE = re.compile(r"\bpip3?\s+install\b[^\n]*git\+https?", re.IGNORECASE)
_GIT_REMOTE_RE = re.compile(
    r"(?:https?://|ssh://|git://)[^\s'\"\)]+|git@[^\s'\"\)]+",
    re.IGNORECASE,
)
_GHA_CHECKOUT_RE = re.compile(r"^\s*-?\s*uses:\s*actions/checkout@", re.IGNORECASE)
_AZURE_REPOSITORY_RESOURCE_RE = re.compile(r"^\s*-\s*repository:\s*(?P<alias>[^\s#]+)", re.IGNORECASE)
_SIMPLE_GITHUB_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_YAML_SCALAR_RE = re.compile(r"^\s*(?P<key>[A-Za-z_][\w.-]*)\s*:\s*(?P<value>.*)$")
_MARKDOWN_EXTENSIONS = frozenset({".md", ".mdx"})
_AGENT_CONTROL_DOC_NAMES = frozenset({"AGENTS.md", "CLAUDE.md", "CODEX.md", "SKILL.md"})
_AGENT_CONTROL_DOC_DIRS = frozenset({".agents", ".claude", ".codex", ".cursor"})
_PYPROJECT_PACKAGE_INDEX_TABLES = frozenset({
    "tool.uv.index",
    "tool.poetry.source",
})
_PYPROJECT_TABLE_RE = re.compile(r"^\s*\[\[?\s*(?P<table>[^\]]+?)\s*\]\]?\s*(?:#.*)?$")


def _normalize_git_clone_deps(findings: list[Finding], lines: list[str]) -> None:
    for finding in findings:
        if finding.pattern_id != "git-clone":
            continue
        if finding.line_number < 1 or finding.line_number > len(lines):
            continue
        dep = _extract_git_clone_repo(lines[finding.line_number - 1])
        if not dep or dep == finding.extracted_dep:
            continue
        finding.extracted_dep = dep
        finding.description = f"git clone pulls external repository: {dep}"


def _normalize_git_url_deps(findings: list[Finding]) -> None:
    for finding in findings:
        if finding.category != Category.GIT_DEPENDENCY:
            continue
        dep = _clean_git_remote_url(finding.extracted_dep)
        if not dep or dep == finding.extracted_dep:
            continue
        finding.description = finding.description.replace(finding.extracted_dep, dep)
        finding.extracted_dep = dep


def _scan_python_shell_git_clones(
    target: FileTarget,
    content: str,
    lines: list[str],
) -> list[Finding]:
    findings: list[Finding] = []
    for command in iter_python_shell_commands(target, content, lines):
        dep = _extract_git_clone_repo(command.command)
        if not dep:
            continue
        findings.append(Finding(
            file_path=target.rel_path,
            line_number=command.line_number,
            category=Category.GIT_DEPENDENCY,
            severity=Severity.MEDIUM,
            pattern_id="git-clone",
            matched_text=command.matched_text,
            extracted_dep=dep[:200],
            description=f"git clone pulls external repository: {dep[:200]}",
            scanner_name=GitDependencyScanner.name,
        ))
    return findings


def _scan_github_actions_checkout_repositories(
    target: FileTarget,
    lines: list[str],
) -> list[Finding]:
    if target.file_type not in {"ci", "github_action"}:
        return []

    findings: list[Finding] = []
    for index, line in enumerate(lines):
        if not _GHA_CHECKOUT_RE.match(line):
            continue
        block = _yaml_step_block(lines, index)
        repository: tuple[int, str, str] | None = None
        ref = ""
        for line_number, block_line in block:
            scalar = _YAML_SCALAR_RE.match(block_line)
            if not scalar:
                continue
            key = scalar.group("key")
            value = _clean_yaml_scalar(scalar.group("value"))
            if key == "repository":
                repository = (line_number, value, block_line.strip())
            elif key == "ref":
                ref = value
        if not repository:
            continue
        line_number, repo, matched_text = repository
        dep = _compose_checkout_repository_dep(repo, ref)
        if not dep:
            continue
        findings.append(Finding(
            file_path=target.rel_path,
            line_number=line_number,
            category=Category.GIT_DEPENDENCY,
            severity=Severity.MEDIUM,
            pattern_id="github-actions-checkout-repository",
            matched_text=matched_text[:200],
            extracted_dep=dep[:200],
            description=f"GitHub Actions checkout pulls repository: {dep[:200]}",
            scanner_name=GitDependencyScanner.name,
        ))
    return findings


def _scan_azure_pipelines_repository_resources(
    target: FileTarget,
    lines: list[str],
) -> list[Finding]:
    if target.file_type != "ci":
        return []

    findings: list[Finding] = []
    for index, line in enumerate(lines):
        if not _AZURE_REPOSITORY_RESOURCE_RE.match(line):
            continue
        block = _yaml_list_item_block(lines, index)
        fields: dict[str, tuple[int, str, str]] = {}
        for line_number, block_line in block:
            scalar = _YAML_SCALAR_RE.match(block_line)
            if not scalar:
                continue
            key = scalar.group("key")
            if key not in {"type", "name", "ref"}:
                continue
            fields[key] = (line_number, _clean_yaml_scalar(scalar.group("value")), block_line.strip())
        name_field = fields.get("name")
        if not name_field:
            continue
        line_number, name, matched_text = name_field
        dep = _compose_azure_repository_resource_dep(name, fields.get("ref", (0, "", ""))[1])
        if not dep:
            continue
        findings.append(Finding(
            file_path=target.rel_path,
            line_number=line_number,
            category=Category.GIT_DEPENDENCY,
            severity=Severity.MEDIUM,
            pattern_id="azure-pipelines-repository-resource",
            matched_text=matched_text[:200],
            extracted_dep=dep[:200],
            description=f"Azure Pipelines repository resource pulls repo: {dep[:200]}",
            scanner_name=GitDependencyScanner.name,
        ))
    return findings


def _yaml_step_block(lines: list[str], start_index: int) -> list[tuple[int, str]]:
    base_indent = _indent_width(lines[start_index])
    inline_step = re.match(r"^\s*-\s*uses:", lines[start_index], re.IGNORECASE) is not None
    block: list[tuple[int, str]] = []
    for offset in range(start_index + 1, len(lines)):
        line = lines[offset]
        indent = _indent_width(line)
        if line.strip() and ((inline_step and indent <= base_indent) or (not inline_step and indent < base_indent)):
            break
        block.append((offset + 1, line))
    return block


def _yaml_list_item_block(lines: list[str], start_index: int) -> list[tuple[int, str]]:
    base_indent = _indent_width(lines[start_index])
    block: list[tuple[int, str]] = []
    for offset in range(start_index + 1, len(lines)):
        line = lines[offset]
        if line.strip() and _indent_width(line) <= base_indent:
            break
        block.append((offset + 1, line))
    return block


def _indent_width(line: str) -> int:
    return len(line) - len(line.lstrip())


def _clean_yaml_scalar(value: str) -> str:
    value = value.split(" #", 1)[0].strip()
    return value.strip("'\"")


def _compose_checkout_repository_dep(repo: str, ref: str) -> str:
    repo = repo.strip()
    if not repo or "${{" in repo or repo.startswith("$"):
        return ""
    if not _SIMPLE_GITHUB_REPO_RE.fullmatch(repo):
        return ""
    ref = ref.strip()
    if not ref or "${{" in ref or ref.startswith("$") or any(ch.isspace() for ch in ref):
        return repo
    return f"{repo}@{ref}"


def _compose_azure_repository_resource_dep(name: str, ref: str) -> str:
    name = name.strip()
    if not name or "${{" in name or name.startswith("$"):
        return ""
    if any(ch.isspace() for ch in name):
        return ""
    ref = ref.strip()
    if not ref or "${{" in ref or ref.startswith("$") or any(ch.isspace() for ch in ref):
        return name
    return f"{name}@{ref}"


def _extract_git_clone_repo(line: str) -> str:
    match = _GIT_CLONE_RE.search(line)
    if not match:
        return ""
    segment = _top_level_command_segment(line[match.start():])
    candidates = [
        _clean_git_remote_url(candidate.group(0))
        for candidate in _GIT_REMOTE_RE.finditer(segment)
        if _command_substitution_depth_at(segment, candidate.start()) == 0
    ]
    return candidates[-1] if candidates else ""


def _top_level_command_segment(text: str) -> str:
    quote = ""
    escaped = False
    depth = 0
    i = 0
    while i < len(text):
        ch = text[i]
        if escaped:
            escaped = False
            i += 1
            continue
        if ch == "\\":
            escaped = True
            i += 1
            continue
        if quote:
            if ch == quote:
                quote = ""
            i += 1
            continue
        if ch in {"'", '"'}:
            quote = ch
            i += 1
            continue
        if text.startswith("$(", i):
            depth += 1
            i += 2
            continue
        if depth:
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            i += 1
            continue
        if text.startswith("&&", i) or text.startswith("||", i) or ch in {";", "|"}:
            return text[:i]
        i += 1
    return text


def _command_substitution_depth_at(text: str, index: int) -> int:
    quote = ""
    escaped = False
    depth = 0
    i = 0
    while i < min(index, len(text)):
        ch = text[i]
        if escaped:
            escaped = False
            i += 1
            continue
        if ch == "\\":
            escaped = True
            i += 1
            continue
        if quote == "'":
            if ch == "'":
                quote = ""
            i += 1
            continue
        if quote == '"':
            if depth and ch == ")":
                depth -= 1
                i += 1
                continue
            if ch == '"' and depth == 0:
                quote = ""
                i += 1
                continue
            if text.startswith("$(", i):
                depth += 1
                i += 2
                continue
            i += 1
            continue
        if ch in {"'", '"'}:
            quote = ch
            i += 1
            continue
        if text.startswith("$(", i):
            depth += 1
            i += 2
            continue
        if depth and ch == ")":
            depth -= 1
        i += 1
    return depth


def _clean_git_remote_url(dep: str) -> str:
    return dep.strip("\"'`").rstrip(".,;\"'`")


def _is_ci_metadata_finding(target: FileTarget, finding: Finding, lines: list[str]) -> bool:
    if target.file_type not in {"ci", "github_action"}:
        return False
    if finding.pattern_id == "azure-pipelines-repository-resource":
        return False
    if not (0 < finding.line_number <= len(lines)):
        return False
    return bool(re.match(
        r"\s*(?:-\s*)?(?:displayName|name|description|title):\s+",
        lines[finding.line_number - 1],
        re.IGNORECASE,
    ))


def _is_package_config_comment_finding(target: FileTarget, finding: Finding, lines: list[str]) -> bool:
    if target.file_type != "package_config":
        return False
    if not (0 < finding.line_number <= len(lines)):
        return False
    return lines[finding.line_number - 1].lstrip().startswith("#")


def _is_non_control_markdown_git_example(
    target: FileTarget,
    finding: Finding,
    lines: list[str],
) -> bool:
    command_re = _git_markdown_command_re(finding.pattern_id)
    if command_re is None:
        return False
    if target.file_type != "agent_instruction" or target.path.suffix.lower() not in _MARKDOWN_EXTENSIONS:
        return False
    if target.path.name.lower() in {doc.lower() for doc in _AGENT_CONTROL_DOC_NAMES}:
        return False
    if any(part.lower() in _AGENT_CONTROL_DOC_DIRS for part in target.path.parts):
        return False
    return _is_markdown_code_example_line(lines, finding.line_number, command_re)


def _git_markdown_command_re(pattern_id: str) -> re.Pattern[str] | None:
    if pattern_id == "git-clone":
        return _GIT_CLONE_RE
    if pattern_id == "pip-git-install":
        return _PIP_GIT_INSTALL_RE
    return None


def _is_markdown_code_example_line(
    lines: list[str],
    line_number: int,
    command_re: re.Pattern[str],
) -> bool:
    if not (0 < line_number <= len(lines)):
        return False
    line = lines[line_number - 1]
    if line.startswith(("    ", "\t")):
        return True
    if _is_inline_code_example(line, command_re):
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


def _is_inline_code_example(line: str, command_re: re.Pattern[str]) -> bool:
    if "`" not in line or not command_re.search(line):
        return False

    start = 0
    while True:
        start = line.find("`", start)
        if start == -1:
            return False
        end = line.find("`", start + 1)
        if end == -1:
            return False
        if command_re.search(line[start + 1:end]):
            return True
        start = end + 1


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
