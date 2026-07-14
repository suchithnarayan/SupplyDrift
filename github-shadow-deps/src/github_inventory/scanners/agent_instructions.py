"""Agent/MCP generated instruction scanner.

Agent servers and skills often keep install commands as source-code data
(`InstallCommand: "npm install ..."`, tool response templates, etc.). Those
commands are not executed while building the repo, but an agent can later emit
them as actionable setup instructions. Scan only explicit agent/MCP-like source
files to avoid treating arbitrary application strings as dependency installs.
"""
from __future__ import annotations

import re
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover - pyyaml is a project dependency
    yaml = None  # type: ignore[assignment]

from github_inventory.discovery import FileTarget
from github_inventory.models import Category, Finding, Severity
from github_inventory.scanners.base import BaseScanner

_PATH_HINT_RE = re.compile(r"(?:^|[/_-])(?:agent|agents|mcp|skills?)(?:[/_.-]|$)", re.IGNORECASE)
_CONTENT_HINT_RE = re.compile(
    r"(?:\bInstallCommand\b|\binstallCommand\b|\bupdate_command\b|\bupdateCommand\b|"
    r"\bMCP\b|Model Context Protocol|\bmcpServers\b|\bOpenCLAW\b|\ballowed-tools\b|"
    r"\bnpx\s+skills\s+add\b)",
    re.IGNORECASE,
)
_AGENT_SOURCE_PROSE_DEPS = {
    "argument",
    "arguments",
    "command",
    "commands",
    "of",
    "package",
    "packages",
    "registered",
    "target",
    "targets",
    "use",
    "uses",
    "with",
}
_AGENT_SOURCE_JS_PROSE_DEPS = {
    "cache",
    "failed",
}

_PATTERNS: tuple[tuple[str, re.Pattern, Severity, str], ...] = (
    (
        "agent-source-npx-execution",
        re.compile(
            r"\b(?:npx|pnpx)\s+(?:--yes\s+|-y\s+|--no-install\s+)?"
            r"(?P<dep>(?:@[\w-]+/)?[\w][\w.-]*(?:@[\w.+\-]+)?)",
            re.IGNORECASE,
        ),
        Severity.HIGH,
        "Agent/MCP source emits npx execution instruction: {dep}",
    ),
    (
        "agent-source-npm-global-install",
        re.compile(
            r"\bnpm\s+(?:install|i)\s+(?:-g|--global)\s+"
            r"(?P<dep>(?:@[\w.-]+/)?[\w][\w./-]*(?:@[\w.+\-]+)?)",
            re.IGNORECASE,
        ),
        Severity.HIGH,
        "Agent/MCP source emits global npm install instruction: {dep}",
    ),
    (
        "agent-source-npm-install",
        re.compile(
            r"\bnpm\s+(?:install|i)\s+"
            r"(?!-g\b|--global\b|&&|;|$|\.{1,2}(?:\s|$))"
            r"(?:-{1,2}[\w-]+(?:[= ](?!-)\S+)?\s+)*"
            r"(?P<dep>(?!-)(?:@[\w.-]+/)?[\w][\w./-]*(?:@[\w.+\-]+)?)",
            re.IGNORECASE,
        ),
        Severity.HIGH,
        "Agent/MCP source emits npm install instruction: {dep}",
    ),
    (
        "agent-source-pip-install",
        re.compile(
            r"\bpip3?\s+install\s+"
            r"(?!-r\s|-e\s)"
            r"(?:-{1,2}[\w-]+(?:[= ](?!-)\S+)?\s+)*"
            r"(?P<dep>(?!-)[\w.-]+(?:\[[\w,]+\])?"
            r"(?:(?:===?|!=|~=|<=?|>=?)[A-Za-z0-9_.!*+,-]+)?)",
            re.IGNORECASE,
        ),
        Severity.MEDIUM,
        "Agent/MCP source emits pip install instruction: {dep}",
    ),
    (
        "agent-source-go-get",
        re.compile(
            r"\bgo\s+get\s+(?:-[\w-]+(?:=\S+)?\s+)*(?P<dep>(?![.-])\S+)",
            re.IGNORECASE,
        ),
        Severity.MEDIUM,
        "Agent/MCP source emits go get instruction: {dep}",
    ),
    (
        "agent-source-composer-require",
        re.compile(r"\bcomposer\s+(?:global\s+)?require\s+(?P<dep>[\w/.-]+)", re.IGNORECASE),
        Severity.MEDIUM,
        "Agent/MCP source emits composer require instruction: {dep}",
    ),
    (
        "agent-source-brew-install",
        re.compile(
            r"\bbrew\s+install\s+"
            r"(?:(?:--[\w-]+|-[A-Za-z]+)\s+)*"
            r"(?P<dep>(?!-)[\w@/.-]+)",
            re.IGNORECASE,
        ),
        Severity.LOW,
        "Agent/MCP source emits Homebrew install instruction: {dep}",
    ),
)


class AgentInstructionScanner(BaseScanner):
    name = "agent-instructions"

    def register_rules(self) -> None:
        # Custom structured scan; no broad regex rules.
        return None

    def scan_file_content(self, target: FileTarget, content: str, lines: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        if target.file_type == "agent_instruction" and target.path.name == "SKILL.md":
            findings.extend(_scan_skill_frontmatter(target, content))

        if target.file_type == "source_code" and _is_agent_instruction_source(target, content):
            for line_number, line in enumerate(lines, start=1):
                if _is_source_comment_line(line):
                    continue
                for pattern_id, regex, severity, description_template in _PATTERNS:
                    for match in regex.finditer(line):
                        if _is_negated_command_context(line, match.start()):
                            continue
                        if pattern_id == "agent-source-pip-install" and _is_python_docstring_requirement_hint(target, lines, line_number):
                            continue
                        for dep, dep_end in _agent_source_match_deps(pattern_id, line, match):
                            if not dep:
                                continue
                            if pattern_id in {
                                "agent-source-npx-execution",
                                "agent-source-npm-install",
                                "agent-source-npm-global-install",
                            } and dep.lower() in _AGENT_SOURCE_JS_PROSE_DEPS:
                                continue
                            if pattern_id == "agent-source-pip-install" and not _is_agent_source_pip_dep(dep):
                                continue
                            if pattern_id == "agent-source-pip-install" and _is_agent_source_pip_path_fragment(line, dep_end):
                                continue
                            if pattern_id == "agent-source-go-get" and _is_agent_source_placeholder_dep(dep):
                                continue
                            findings.append(Finding(
                                file_path=target.rel_path,
                                line_number=line_number,
                                category=Category.UNMANAGED_PACKAGE,
                                severity=severity,
                                pattern_id=pattern_id,
                                matched_text=line.strip()[:200],
                                extracted_dep=dep[:200],
                                description=description_template.format(dep=dep[:200]),
                                scanner_name=self.name,
                            ))
        return _dedupe(findings)


def _is_agent_instruction_source(target: FileTarget, content: str) -> bool:
    if _is_test_source_path(target.rel_path):
        return False
    if _PATH_HINT_RE.search(target.rel_path):
        return True
    if _is_generated_application_bundle(target.rel_path):
        return False
    return bool(_CONTENT_HINT_RE.search(content))


def _is_test_source_path(rel_path: str) -> bool:
    rel_lower = rel_path.replace("\\", "/").lower()
    path = f"/{rel_lower}"
    if any(segment in path for segment in ("/test/", "/tests/", "/testing/")):
        return True
    name = rel_lower.rsplit("/", 1)[-1]
    return (
        name.startswith("test_")
        or name.endswith("_test.py")
        or name.endswith(".test.ts")
        or name.endswith("test.ts")
    )


def _is_generated_application_bundle(rel_path: str) -> bool:
    rel_lower = rel_path.lower()
    if not rel_lower.endswith((".js", ".mjs", ".cjs", ".ts", ".tsx")):
        return False
    path = f"/{rel_lower}"
    if any(segment in path for segment in ("/assets/", "/static/", "/dist/", "/build/", "/vendor/")):
        return True
    return bool(re.search(r"[.-][a-z0-9_-]{8,}\.(?:js|mjs|cjs)$", rel_lower))


def _is_source_comment_line(line: str) -> bool:
    stripped = line.strip()
    return (
        stripped.startswith("//")
        or stripped.startswith("#")
        or stripped.startswith("*")
        or stripped.startswith("/*")
        or stripped.startswith("*/")
    )


def _is_negated_command_context(line: str, command_start: int) -> bool:
    prefix = line[:command_start]
    return bool(re.search(r"\b(?:no|without)\s+$", prefix, re.IGNORECASE))


def _agent_source_match_deps(
    pattern_id: str,
    line: str,
    match: re.Match[str],
) -> list[tuple[str, int]]:
    dep = (match.group("dep") or "").strip()
    if pattern_id != "agent-source-pip-install":
        return [(dep, match.end("dep"))]
    if not _is_agent_source_pip_dep(dep):
        return [(dep, match.end("dep"))]

    deps: list[tuple[str, int]] = [(dep, match.end("dep"))]
    for raw_match in re.finditer(r"\S+", line[match.end("dep"):]):
        raw = raw_match.group(0)
        if raw.startswith(("&&", "||", ";", "|")):
            break
        candidate = _clean_agent_source_arg_token(raw)
        if not candidate:
            break
        if candidate.startswith("-"):
            break
        if not _is_agent_source_pip_dep(candidate):
            break
        deps.append((candidate, match.end("dep") + raw_match.end()))
    return deps


def _clean_agent_source_arg_token(token: str) -> str:
    token = token.strip().strip("'\"`")
    token = token.rstrip(")]},")
    token = token.strip("'\"`")
    return token.rstrip(".:,;")


def _is_agent_source_placeholder_dep(dep: str) -> bool:
    if re.search(r"<\s*(?:module|package|dependency|target)\s*>", dep, re.IGNORECASE):
        return True
    clean = _clean_agent_source_arg_token(dep).strip("<>")
    return clean.lower() in {"module", "package", "dependency", "target"}


def _is_agent_source_pip_dep(dep: str) -> bool:
    if dep.startswith(("http://", "https://", "git+", "file:", "-", ".", "$")):
        return False
    if dep.endswith("."):
        return False
    if dep.lower() in _AGENT_SOURCE_PROSE_DEPS:
        return False
    if dep.lower() in {"requirements.txt", "constraints.txt", "requirements.in", "constraints.in"}:
        return False
    if "..." in dep:
        return False
    if re.search(r"\.(?:txt|in|lock|toml|cfg|ini|ya?ml|whl|zip|tar\.gz|tgz)$", dep, re.IGNORECASE):
        return False
    package = r"[A-Za-z0-9_.-]+(?:\[[A-Za-z0-9_,.-]+\])?"
    version = r"(?:===?|!=|~=|<=?|>=?)[A-Za-z0-9_.!*+,-]+"
    return bool(re.fullmatch(rf"{package}(?:{version})?", dep))


def _is_agent_source_pip_path_fragment(line: str, dep_end: int) -> bool:
    return dep_end < len(line) and line[dep_end] in {"/", "\\", "*"}


def _is_python_docstring_requirement_hint(
    target: FileTarget,
    lines: list[str],
    line_number: int,
) -> bool:
    if not target.rel_path.lower().endswith(".py"):
        return False
    if not _line_is_inside_python_triple_quote(lines, line_number):
        return False
    for index in range(line_number - 2, max(-1, line_number - 8), -1):
        stripped = lines[index].strip()
        if not stripped:
            continue
        return stripped.rstrip(":").lower() == "requirements"
    return False


def _line_is_inside_python_triple_quote(lines: list[str], line_number: int) -> bool:
    active_quote = ""
    for current_line_number, line in enumerate(lines, start=1):
        if active_quote:
            if current_line_number == line_number:
                return True
            if line.count(active_quote) % 2 == 1:
                active_quote = ""
            continue
        for quote in ('"""', "'''"):
            if line.count(quote) % 2 == 1:
                if current_line_number == line_number:
                    return True
                active_quote = quote
                break
    return False


def _scan_skill_frontmatter(target: FileTarget, content: str) -> list[Finding]:
    frontmatter = _frontmatter(content)
    if not frontmatter or yaml is None:
        return []
    try:
        data = yaml.safe_load(frontmatter) or {}
    except yaml.YAMLError:
        return []
    if not isinstance(data, dict):
        return []

    findings: list[Finding] = []
    for tool in _allowed_tools(data.get("allowed-tools")):
        findings.append(_make_finding(
            target=target,
            content=content,
            dep=tool,
            matched=tool,
            category=Category.AGENT_PLUGIN,
            severity=Severity.MEDIUM,
            pattern_id="skill-allowed-tool-runner",
            description=f"Skill grants agent access to external command runner: {tool}",
        ))

    metadata = data.get("metadata")
    openclaw = metadata.get("openclaw") if isinstance(metadata, dict) else None
    if not isinstance(openclaw, dict):
        return findings

    requires = openclaw.get("requires")
    if isinstance(requires, dict):
        for binary in _string_list(requires.get("bins")):
            findings.append(_make_finding(
                target=target,
                content=content,
                dep=binary,
                matched=binary,
                category=Category.AGENT_PLUGIN,
                severity=Severity.MEDIUM,
                pattern_id="skill-openclaw-required-bin",
                description=f"OpenCLAW skill requires host binary: {binary}",
            ))

    install = openclaw.get("install")
    if isinstance(install, dict):
        package = install.get("package")
        if isinstance(package, str) and package.strip():
            dep = package.strip()
            findings.append(_make_finding(
                target=target,
                content=content,
                dep=dep,
                matched=dep,
                category=Category.UNMANAGED_PACKAGE,
                severity=Severity.HIGH,
                pattern_id="skill-openclaw-install-package",
                description=f"OpenCLAW skill installs package outside a project manifest: {dep}",
            ))
        for binary in _string_list(install.get("bins")):
            findings.append(_make_finding(
                target=target,
                content=content,
                dep=binary,
                matched=binary,
                category=Category.AGENT_PLUGIN,
                severity=Severity.MEDIUM,
                pattern_id="skill-openclaw-install-bin",
                description=f"OpenCLAW skill install exposes binary: {binary}",
            ))

    return findings


def _frontmatter(content: str) -> str | None:
    if not content.startswith("---\n"):
        return None
    end = content.find("\n---", 4)
    if end == -1:
        return None
    return content[4:end]


def _allowed_tools(value: Any) -> list[str]:
    raw_values = _string_list(value)
    tools: list[str] = []
    for raw in raw_values:
        for match in re.finditer(r"\bBash\((?P<tool>[^:)\s]+)(?::[^)]*)?\)", raw):
            tool = match.group("tool").strip()
            if tool:
                tools.append(tool)
    return tools


def _string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []


def _make_finding(
    *,
    target: FileTarget,
    content: str,
    dep: str,
    matched: str,
    category: Category,
    severity: Severity,
    pattern_id: str,
    description: str,
) -> Finding:
    return Finding(
        file_path=target.rel_path,
        line_number=_line_number(content, matched),
        category=category,
        severity=severity,
        pattern_id=pattern_id,
        matched_text=matched[:200],
        extracted_dep=dep[:200],
        description=description,
        scanner_name=AgentInstructionScanner.name,
    )


def _line_number(content: str, token: str) -> int:
    idx = content.find(token)
    return content[:idx].count("\n") + 1 if idx >= 0 else 1


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, str]] = set()
    deduped: list[Finding] = []
    for finding in findings:
        key = (finding.file_path, finding.pattern_id, finding.extracted_dep)
        if key not in seen:
            seen.add(key)
            deduped.append(finding)
    return deduped
