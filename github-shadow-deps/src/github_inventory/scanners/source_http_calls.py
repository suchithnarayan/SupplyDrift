"""Detect fetch(), axios, requests, and urllib calls to external URLs in source code."""
from __future__ import annotations

import re

from github_inventory.discovery import FileTarget
from github_inventory.models import Category, Finding, Severity
from github_inventory.scanners.base import BaseScanner, PatternRule

# Hosts that aren't external — never count toward shadow-dependency findings.
# Test code commonly uses 127.0.0.1:${port}/... against a local server; flagging
# those was producing dozens of FPs in real-repo scans.
_LOCALHOST = r"localhost|127\.0\.0\.1|0\.0\.0\.0|::1|\[::1\]"


class SourceHTTPCallScanner(BaseScanner):
    name = "source-http-calls"

    def scan_file_content(self, target: FileTarget, content: str, lines: list[str]) -> list[Finding]:
        if target.file_type == "source_code" and (
            _is_test_source_path(target.rel_path)
            or _is_vendored_package_manager_bundle_path(target.rel_path)
        ):
            return []
        findings = [
            finding for finding in super().scan_file_content(target, content, lines)
            if not _is_source_comment_line(finding.matched_text)
            and not _is_language_mismatched_finding(target, finding.pattern_id)
        ]
        if (
            target.file_type == "source_code"
            and _is_js_source_path(target.rel_path)
            and not _looks_like_minified_js(lines)
        ):
            findings.extend(_scan_js_const_url_fetches(target, lines, findings))
        findings = [
            finding for finding in findings
            if not _is_reserved_example_url_in_example_source_path(target, finding)
            and not _has_placeholder_host_url(finding.extracted_dep)
        ]
        return _dedupe_findings(findings)

    def register_rules(self) -> None:
        # --- JavaScript / TypeScript ---

        self.add_rule(PatternRule(
            pattern_id="js-fetch-external",
            regex=re.compile(
                r"""fetch\s*\(\s*['"`](?P<dep>https?://(?!""" + _LOCALHOST + r""")[^'"`\s]+)['"`]""",
            ),
            severity=Severity.MEDIUM,
            description_template="JS/TS fetch() calls external URL: {dep}",
            category=Category.SOURCE_HTTP_CALL,
            file_types=["source_code"],
        ))

        self.add_rule(PatternRule(
            pattern_id="js-axios-external",
            regex=re.compile(
                r"""axios\.(?:get|post|put|patch|delete|request|head)\s*\(\s*['"`](?P<dep>https?://(?!""" + _LOCALHOST + r""")[^'"`\s]+)['"`]""",
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="JS/TS axios calls external URL: {dep}",
            category=Category.SOURCE_HTTP_CALL,
            file_types=["source_code"],
        ))

        # --- Python ---

        self.add_rule(PatternRule(
            pattern_id="python-requests-external",
            regex=re.compile(
                r"""requests\.(?:get|post|put|patch|delete|head)\s*\(\s*['"](?P<dep>https?://(?!""" + _LOCALHOST + r""")[^'"]+)['"]""",
            ),
            severity=Severity.MEDIUM,
            description_template="Python requests calls external URL: {dep}",
            category=Category.SOURCE_HTTP_CALL,
            file_types=["source_code"],
        ))

        self.add_rule(PatternRule(
            pattern_id="python-urllib-external",
            regex=re.compile(
                r"""urlopen\s*\(\s*['"](?P<dep>https?://(?!""" + _LOCALHOST + r""")[^'"]+)['"]""",
            ),
            severity=Severity.MEDIUM,
            description_template="Python urllib calls external URL: {dep}",
            category=Category.SOURCE_HTTP_CALL,
            file_types=["source_code"],
        ))


_JS_URL_CONST_ASSIGN_RE = re.compile(
    r"\b(?:const|let|var)\s+(?P<name>[A-Za-z_$][\w$]*)\s*=\s*(?P<expr>[^;]+)",
)
_JS_URL_CONST_START_RE = re.compile(
    r"\b(?:const|let|var)\s+(?P<name>[A-Za-z_$][\w$]*)\s*=\s*(?://.*)?$",
)
_JS_HTTP_CALL_RE = re.compile(
    r"(?:(?<![\w$.])fetch\s*\(|\b(?:window|globalThis|self)\.fetch\s*\(|\baxios\.(?:get|post|put|patch|delete|request|head)\s*\()",
    re.IGNORECASE,
)
_JS_FETCH_DECLARATION_RE = re.compile(r"^(?:export\s+)?(?:async\s+)?function\s+fetch\s*\(")


def _scan_js_const_url_fetches(
    target: FileTarget,
    lines: list[str],
    existing: list[Finding],
) -> list[Finding]:
    existing_keys = {
        (f.line_number, f.pattern_id, f.extracted_dep)
        for f in existing
    }
    added: list[Finding] = []
    constants: dict[str, tuple[str, int, int]] = {}
    brace_depth = 0
    for line_number, line in enumerate(lines, start=1):
        constants = {
            name: value
            for name, value in constants.items()
            if brace_depth >= value[2]
        }
        if _is_source_comment_line(line):
            brace_depth = max(0, brace_depth + _js_brace_delta(line))
            continue
        match = _JS_URL_CONST_ASSIGN_RE.search(line)
        if match:
            _add_js_url_constant(constants, match.group("name"), match.group("expr"), line_number, brace_depth)
        else:
            match = _JS_URL_CONST_START_RE.search(line.strip())
            if match:
                expr = _collect_multiline_js_assignment_expr(lines, line_number - 1)
                _add_js_url_constant(constants, match.group("name"), expr, line_number, brace_depth)

        if not _JS_HTTP_CALL_RE.search(line):
            brace_depth = max(0, brace_depth + _js_brace_delta(line))
            continue
        if _is_js_fetch_declaration_line(line):
            brace_depth = max(0, brace_depth + _js_brace_delta(line))
            continue
        for name, (dep, _, _) in constants.items():
            if not _line_references_identifier(line, name):
                continue
            if _line_shadows_identifier(line, name):
                continue
            key = (line_number, "js-fetch-const-external", dep)
            if key in existing_keys:
                continue
            added.append(Finding(
                file_path=target.rel_path,
                line_number=line_number,
                category=Category.SOURCE_HTTP_CALL,
                severity=Severity.MEDIUM,
                pattern_id="js-fetch-const-external",
                matched_text=line.strip()[:200],
                extracted_dep=dep[:200],
                description=f"JS/TS fetch() uses external URL from constant: {dep}",
                scanner_name=SourceHTTPCallScanner.name,
            ))
            existing_keys.add(key)
        brace_depth = max(0, brace_depth + _js_brace_delta(line))
    return added


def _add_js_url_constant(
    constants: dict[str, tuple[str, int, int]],
    name: str,
    expr: str,
    line_number: int,
    brace_depth: int,
) -> None:
    dep = _extract_js_url_constant_dep(expr)
    if dep and not _is_local_url(dep):
        constants[name] = (dep, line_number, brace_depth)


def _collect_multiline_js_assignment_expr(lines: list[str], index: int) -> str:
    parts: list[str] = []
    for next_line in lines[index + 1:index + 5]:
        stripped = next_line.strip()
        if not stripped or _is_source_comment_line(stripped):
            continue
        parts.append(stripped.rstrip(";"))
        if stripped.endswith(";"):
            break
    return " ".join(parts)


def _extract_js_url_constant_dep(expr: str) -> str:
    expr = expr.strip().rstrip(";")
    simple = re.match(r"['\"`](?P<dep>https?://[^'\"`\s]+)['\"`]$", expr)
    if simple:
        return simple.group("dep")

    parts = [part.strip() for part in expr.split("+")]
    if not parts:
        return ""
    dep_parts: list[str] = []
    for part in parts:
        literal = re.fullmatch(r"['\"`](?P<value>[^'\"`]*)['\"`]", part)
        if literal:
            dep_parts.append(literal.group("value"))
            continue
        identifier = re.fullmatch(r"[A-Za-z_$][\w$]*", part)
        if identifier:
            dep_parts.append("${" + part + "}")
            continue
        return ""
    dep = "".join(dep_parts)
    return dep if dep.startswith(("http://", "https://")) else ""


def _line_references_identifier(line: str, name: str) -> bool:
    return bool(re.search(rf"(?:\b{re.escape(name)}\b|\$\{{\s*{re.escape(name)}\s*\}})", line))


def _line_shadows_identifier(line: str, name: str) -> bool:
    escaped = re.escape(name)
    return bool(
        re.search(rf"\(\s*{escaped}\s*\)\s*=>", line)
        or re.search(rf"\bfunction\s+[A-Za-z_$][\w$]*\s*\([^)]*\b{escaped}\b", line)
    )


def _is_js_fetch_declaration_line(line: str) -> bool:
    return bool(_JS_FETCH_DECLARATION_RE.match(line.strip()))


def _js_brace_delta(line: str) -> int:
    delta = 0
    quote = ""
    escaped = False
    i = 0
    while i < len(line):
        ch = line[i]
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = ""
            i += 1
            continue
        if ch in ("'", '"', "`"):
            quote = ch
            i += 1
            continue
        if ch == "/" and i + 1 < len(line) and line[i + 1] == "/":
            break
        if ch == "{":
            delta += 1
        elif ch == "}":
            delta -= 1
        i += 1
    return delta


def _is_local_url(url: str) -> bool:
    return bool(re.match(rf"https?://(?:{_LOCALHOST})(?:[:/]|$)", url, re.IGNORECASE))


def _has_placeholder_host_url(url: str) -> bool:
    return bool(re.match(r"https?://\$\{[^}]+\}(?:[/:?#]|$)", url))


def _is_language_mismatched_finding(target: FileTarget, pattern_id: str) -> bool:
    if pattern_id.startswith("python-"):
        return not _is_python_source_path(target.rel_path)
    if pattern_id.startswith("js-"):
        return not _is_js_source_path(target.rel_path)
    return False


def _is_python_source_path(rel_path: str) -> bool:
    return rel_path.replace("\\", "/").lower().endswith(".py")


def _is_js_source_path(rel_path: str) -> bool:
    return rel_path.replace("\\", "/").lower().endswith(
        (".js", ".mjs", ".cjs", ".ts", ".mts", ".jsx", ".tsx")
    )


def _is_test_source_path(rel_path: str) -> bool:
    rel_norm = rel_path.replace("\\", "/")
    rel_lower = rel_norm.lower()
    path = f"/{rel_lower}"
    if any(segment in path for segment in ("/test/", "/tests/", "/testing/", "/testdata/")):
        return True
    name = rel_lower.rsplit("/", 1)[-1]
    original_name = rel_norm.rsplit("/", 1)[-1]
    return (
        name.startswith("test_")
        or bool(re.match(r"^(?:test|Test)(?:[-_.A-Z0-9]).*\.(?:[cm]?[jt]sx?|py)$", original_name))
        or name.endswith("_test.py")
        or name.endswith(".test.ts")
        or ".spec." in name
    )


def _is_reserved_example_url_in_example_source_path(target: FileTarget, finding: Finding) -> bool:
    if target.file_type != "source_code":
        return False
    if not _is_example_source_path(target.rel_path):
        return False
    return bool(re.match(
        r"^https?://(?:(?:[^/?#@]+\.)?example\.(?:com|org|net)|jsonplaceholder\.typicode\.com)(?:[/:?#]|$)",
        finding.extracted_dep,
        re.IGNORECASE,
    ))


def _is_example_source_path(rel_path: str) -> bool:
    path = "/" + rel_path.replace("\\", "/").lower()
    return any(
        segment in path
        for segment in (
            "/example/",
            "/examples/",
            "/sample/",
            "/samples/",
            "/demo/",
            "/demos/",
            "/quickstart/",
            "/quickstarts/",
        )
    )


def _is_vendored_package_manager_bundle_path(rel_path: str) -> bool:
    rel_lower = rel_path.replace("\\", "/").lower()
    return (
        "/.yarn/releases/" in f"/{rel_lower}"
        and rel_lower.endswith((".cjs", ".js"))
    )


def _looks_like_minified_js(lines: list[str]) -> bool:
    return any(len(line) > 1000 for line in lines[:20])


def _is_source_comment_line(line: str) -> bool:
    stripped = line.strip()
    return (
        stripped.startswith("//")
        or stripped.startswith("#")
        or stripped.startswith("*")
        or stripped.startswith("/*")
        or stripped.startswith("*/")
    )


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[int, str, str]] = set()
    out: list[Finding] = []
    for finding in findings:
        key = (finding.line_number, finding.pattern_id, finding.extracted_dep)
        if key in seen:
            continue
        seen.add(key)
        out.append(finding)
    return out
