from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from github_inventory.config import Config
from github_inventory.discovery import FileTarget
from github_inventory.models import Category, Finding, Severity

# File types that use # for comments (shell-style)
HASH_COMMENT_TYPES = frozenset({"ci", "script", "build", "dockerfile", "iac", "k8s",
                                 "gitmodules", "pip_config", "precommit_config",
                                 "build_wrapper", "toolversions", "nix",
                                 "github_action", "npmrc", "pip_conf",
                                 "meson_wrap", "sbt_build", "rebar_config",
                                 "agent_instruction"})


@dataclass
class PatternRule:
    pattern_id: str
    regex: re.Pattern
    severity: Severity
    description_template: str
    category: Category
    file_types: list[str]
    extract_group: str = "dep"
    multiline: bool = False
    multiple: bool = False
    # Optional templates used by credential rules to ensure secret values are
    # discarded before a Finding object is constructed.
    extracted_dep_template: str | None = None
    matched_text_template: str | None = None
    sensitive_metadata: dict[str, object] | None = None
    # If any of these sub-patterns match within the matched text, replace
    # `severity` with the paired escalated value. First match wins.
    # Use case: `npx pkg@latest` → escalate from HIGH to CRITICAL when the
    # match contains `@latest`/`@alpha`/`@next` etc., without needing N
    # separate pattern_ids.
    escalate_when: list[tuple[re.Pattern, Severity]] = field(default_factory=list)


# Categories where install-hint string literals are a known FP source.
# Conservative: only suppress in shell-script install-style categories,
# never in container/CDN/CI-config categories where strings ARE the data.
_STRING_LITERAL_FP_CATEGORIES = frozenset({
    "script-installation",
    "binary-download",
    "unmanaged-package",
})
_PLACEHOLDER_URL_DEP_RE = re.compile(
    r"^https?://(?:\.{3}(?:[/?#:]|$)|[^\s]*<[^>\s]+>[^\s]*)",
    re.IGNORECASE,
)


class BaseScanner(ABC):
    name: str = "base"

    def __init__(self, config: Config):
        self.config = config
        self._rules: list[PatternRule] = []
        self.register_rules()

    @abstractmethod
    def register_rules(self) -> None: ...

    def add_rule(self, rule: PatternRule) -> None:
        self._rules.append(rule)

    def scan_file(self, target: FileTarget) -> list[Finding]:
        """Scan a file, reading its content internally. Used by VendoredBinaryScanner."""
        applicable = [r for r in self._rules if "*" in r.file_types or target.file_type in r.file_types]
        if not applicable:
            return []
        try:
            content = target.path.read_text(errors="replace")
        except OSError:
            return []
        return self.scan_file_content(target, content, content.splitlines())

    def scan_file_content(self, target: FileTarget, content: str, lines: list[str]) -> list[Finding]:
        """Scan pre-read file content. Called by the engine for efficiency (read once)."""
        applicable = [r for r in self._rules if "*" in r.file_types or target.file_type in r.file_types]
        if not applicable:
            return []

        findings: list[Finding] = []
        for rule in applicable:
            if rule.multiline:
                findings.extend(self._scan_multiline(target, content, rule))
            else:
                findings.extend(self._scan_lines(target, lines, rule))
        return findings

    def _scan_lines(self, target: FileTarget, lines: list[str], rule: PatternRule) -> list[Finding]:
        findings = []
        for i, line in enumerate(lines, start=1):
            stripped = line.strip()
            if _is_comment(stripped, target.file_type):
                continue
            matches = list(rule.regex.finditer(line)) if rule.multiple else []
            if not rule.multiple:
                m = rule.regex.search(line)
                if m:
                    matches = [m]
            for m in matches:
                # Suppress download/install patterns inside function-arg help strings
                # (e.g. `"install with: curl ... | bash"` passed to a check() helper).
                # Only applies to script-installation / binary-download / unmanaged-package
                # categories — other categories (container, CDN) use these strings legitimately.
                if rule.category.value in _STRING_LITERAL_FP_CATEGORIES and _is_help_string_arg(
                    line, target.file_type, m.start()
                ):
                    continue
                # Severity escalation: if rule defines escalate_when sub-patterns
                # whose match within the matched text bumps severity, apply it.
                sev = rule.severity
                matched_text = m.group(0)
                if rule.escalate_when:
                    for sub_re, escalated_sev in rule.escalate_when:
                        if sub_re.search(matched_text):
                            sev = escalated_sev
                            break
                dep, public_matched, sensitive, context = _safe_finding_fields(
                    m, rule, stripped[:200]
                )
                findings.append(Finding(
                    file_path=target.rel_path,
                    line_number=i,
                    category=rule.category,
                    severity=sev,
                    pattern_id=rule.pattern_id,
                    matched_text=public_matched,
                    extracted_dep=dep,
                    description=rule.description_template.format(**context),
                    scanner_name=self.name,
                    sensitive=sensitive,
                ))
        return findings

    def _scan_multiline(self, target: FileTarget, content: str, rule: PatternRule) -> list[Finding]:
        findings = []
        for m in rule.regex.finditer(content):
            line_num = content[: m.start()].count("\n") + 1
            end_line = content[: m.end()].count("\n") + 1
            matched_full = m.group(0)
            dep, public_matched, sensitive, context = _safe_finding_fields(
                m, rule, matched_full.strip()[:200]
            )
            sev = rule.severity
            if rule.escalate_when:
                for sub_re, escalated_sev in rule.escalate_when:
                    if sub_re.search(matched_full):
                        sev = escalated_sev
                        break
            findings.append(Finding(
                file_path=target.rel_path,
                line_number=line_num,
                end_line=end_line if end_line != line_num else None,
                category=rule.category,
                severity=sev,
                pattern_id=rule.pattern_id,
                matched_text=public_matched,
                extracted_dep=dep,
                description=rule.description_template.format(**context),
                scanner_name=self.name,
                sensitive=sensitive,
            ))
        return findings


def _safe_finding_fields(
    match: re.Match,
    rule: PatternRule,
    default_matched_text: str,
) -> tuple[str, str, dict[str, object] | None, dict[str, str]]:
    """Render safe values before constructing a Finding."""
    context = {key: value or "" for key, value in match.groupdict().items()}
    extracted = _extract(match, rule.extract_group)
    if rule.extracted_dep_template is not None:
        extracted = rule.extracted_dep_template.format(**context)
    context["dep"] = extracted

    matched_text = default_matched_text
    if rule.matched_text_template is not None:
        matched_text = rule.matched_text_template.format(**context)

    sensitive = None
    if rule.sensitive_metadata is not None:
        sensitive = {
            key: value.format(**context) if isinstance(value, str) else value
            for key, value in rule.sensitive_metadata.items()
        }
    return extracted, matched_text, sensitive, context


def _extract(m: re.Match, group: str) -> str:
    try:
        val = m.group(group)
        return (val or "").strip()[:200]
    except IndexError:
        return m.group(0)[:200]


def is_placeholder_url_dependency(dep: str) -> bool:
    return bool(_PLACEHOLDER_URL_DEP_RE.match(dep.strip()))


def _is_comment(line: str, file_type: str) -> bool:
    if not line:
        return True
    if file_type in HASH_COMMENT_TYPES:
        # Skip # comments but preserve shebangs (#!) and YAML anchors (&)
        if line.startswith("#") and not line.startswith("#!"):
            return True
    if file_type == "script" and re.match(r"(?i)(?:rem(?:\s|$)|::)", line):
        return True
    if file_type == "build" and line.startswith("<!--"):
        return True
    return False


# Conservative heuristic for install-hint string FPs.
# After line continuations are joined (engine.py), a multi-arg helper
# call like `check "label" "cmd" "install with: curl ... | bash"` becomes
# one logical line. Detect when the curl/bash pattern is preceded on the
# same line by a quoted help-text marker — those strings are echo'd as
# error messages, never executed.
# `\s*` after the quote is important: real strings often have leading
# indentation inside the quote (`echo "  Install: brew install qemu"`).
_HELP_PHRASE_RE = re.compile(
    r"""(?:install\s+with|install\s+via|install\s+it:|run\s+with|see\s+also|usage|"""
    r"""tip:|hint:|example|try:|fix\s+with|to\s+install|install:|not\s+installed)""",
    re.IGNORECASE,
)

_PRINT_HELP_CALL_RE = re.compile(
    r"""^\s*(?:(?:\d?>&\d+|>&\d+|\d?>\S+)\s+)*"""
    r"""(?:echo|printf|warn|fail|pass|log|info|debug|error|"""
    r"""print_(?:cmd|info|warning|error|success|title)|"""
    r"""Write-[A-Za-z][\w-]*|throw)\b""",
    re.IGNORECASE,
)


def _is_help_string_arg(line: str, file_type: str, command_start: int | None = None) -> bool:
    if file_type not in {"script", "ci", "build", "github_action"}:
        return False
    if command_start is None:
        return False

    span = _quote_span_at(line, command_start)
    if span is None:
        return False

    quote_start, _, quote = span
    quoted_prefix = line[quote_start + 1:command_start]

    # Command substitution inside a quoted string is still executed by the
    # shell before the print/helper command runs, except inside single quotes.
    if quote != "'" and _has_command_substitution(quoted_prefix):
        return False

    if _HELP_PHRASE_RE.search(quoted_prefix):
        return True
    if _PRINT_HELP_CALL_RE.search(line[:quote_start]):
        return True
    return False


def _quote_span_at(line: str, pos: int) -> tuple[int, int, str] | None:
    """Return the single/double-quoted span containing pos, if any."""
    quote: str | None = None
    start = -1
    escaped = False

    for i, ch in enumerate(line):
        if escaped:
            escaped = False
            continue
        if ch == "\\":
            escaped = True
            continue
        if quote is None:
            if ch in {"'", '"'}:
                quote = ch
                start = i
            continue
        if ch == quote:
            if start < pos < i:
                return start, i, quote
            quote = None
            start = -1

    if quote is not None and start < pos < len(line):
        return start, len(line), quote
    return None


def _has_command_substitution(text: str) -> bool:
    return _has_unescaped_token(text, "$(") or _has_unescaped_token(text, "`")


def _has_unescaped_token(text: str, token: str) -> bool:
    start = 0
    while True:
        idx = text.find(token, start)
        if idx == -1:
            return False
        if not _is_escaped(text, idx):
            return True
        start = idx + len(token)


def _is_escaped(text: str, pos: int) -> bool:
    backslashes = 0
    i = pos - 1
    while i >= 0 and text[i] == "\\":
        backslashes += 1
        i -= 1
    return backslashes % 2 == 1
