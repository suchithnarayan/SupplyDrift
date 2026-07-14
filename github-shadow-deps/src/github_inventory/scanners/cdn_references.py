"""Detect external CDN script/link tags, CSS imports, and ES module imports from URLs."""
from __future__ import annotations

import re
from urllib.parse import urlparse

from github_inventory.models import Category, Severity
from github_inventory.scanners.base import BaseScanner, PatternRule


class CDNReferenceScanner(BaseScanner):
    name = "cdn-references"

    def scan_file_content(self, target, content: str, lines: list[str]):
        if target.file_type in {"web_asset", "source_code"} and _is_test_fixture_asset_path(target.rel_path):
            return []
        if _is_generated_static_site_html(target.rel_path, target.file_type, content):
            return []
        findings = super().scan_file_content(target, content, lines)
        if not findings:
            return findings
        findings = [
            finding for finding in findings
            if not _is_local_development_url(finding.extracted_dep)
            and not _is_html_commented_reference(lines, finding.line_number, finding.extracted_dep)
        ]
        if _is_generated_kotlin_playground_doc(target.rel_path, content):
            return [
                finding for finding in findings
                if "unpkg.com/kotlin-playground" not in finding.extracted_dep
            ]
        return findings

    def register_rules(self) -> None:
        # --- HTML ---

        self.add_rule(PatternRule(
            pattern_id="script-tag-external",
            regex=re.compile(
                r'<script\b[^>]+\bsrc\s*=\s*["\'](?P<dep>https?://[^"\'>\s]+)["\']',
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="External script loaded from CDN/URL (remote code execution): {dep}",
            category=Category.CDN_REFERENCE,
            file_types=["web_asset"],
        ))

        # Only fire on `<link rel="...">` values that ACTUALLY load a remote
        # resource. `preconnect` / `dns-prefetch` are performance hints (no
        # resource fetched), `icon` / `alternate` / `canonical` are metadata.
        # Real loaders: stylesheet, manifest, preload, prefetch, modulepreload.
        # Either order — `rel="x" href="..."` or `href="..." rel="x"` — must match.
        self.add_rule(PatternRule(
            pattern_id="link-tag-external",
            regex=re.compile(
                r'<link\b'
                r'(?=[^>]*\brel\s*=\s*["\'](?:stylesheet|manifest|preload|prefetch|modulepreload)\b)'
                r'[^>]*\bhref\s*=\s*["\'](?P<dep>https?://[^"\'>\s]+)["\']',
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="External stylesheet/resource loaded from CDN: {dep}",
            category=Category.CDN_REFERENCE,
            file_types=["web_asset"],
        ))

        # --- CSS ---

        self.add_rule(PatternRule(
            pattern_id="css-import-external",
            regex=re.compile(
                r'@import\s+(?:url\s*\(\s*)?["\']?(?P<dep>https?://[^\s"\')\]]+)',
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="CSS @import loads external resource: {dep}",
            category=Category.CDN_REFERENCE,
            file_types=["web_asset"],
        ))

        self.add_rule(PatternRule(
            pattern_id="css-font-face-external",
            regex=re.compile(
                r'src:\s*url\s*\(\s*["\']?(?P<dep>https?://[^\s"\')\]]+)',
                re.IGNORECASE,
            ),
            severity=Severity.LOW,
            description_template="CSS font-face loads external font file: {dep}",
            category=Category.CDN_REFERENCE,
            file_types=["web_asset"],
        ))

        # --- ES module imports from CDN (in JS/TS source) ---

        self.add_rule(PatternRule(
            pattern_id="es-module-cdn-import",
            regex=re.compile(
                r'import\s+.*?\s+from\s+["\'](?P<dep>https?://[^"\']+)["\']',
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="ES module imported from remote URL: {dep}",
            category=Category.CDN_REFERENCE,
            file_types=["source_code", "web_asset"],
        ))

        self.add_rule(PatternRule(
            pattern_id="dynamic-import-cdn",
            regex=re.compile(
                r'import\s*\(\s*["\'](?P<dep>https?://[^"\']+)["\']',
            ),
            severity=Severity.HIGH,
            description_template="Dynamic import() from remote URL: {dep}",
            category=Category.CDN_REFERENCE,
            file_types=["source_code", "web_asset"],
        ))


def _is_generated_kotlin_playground_doc(rel_path: str, content: str) -> bool:
    rel_lower = rel_path.lower()
    if "/docs/" not in f"/{rel_lower}" and "/documentation/" not in f"/{rel_lower}":
        return False
    lowered = content[:5000].lower()
    return "kotlin-playground" in content and ("dokka" in lowered or "kotlin" in lowered)


def _is_generated_static_site_html(rel_path: str, file_type: str, content: str) -> bool:
    if file_type != "web_asset" or not rel_path.lower().endswith((".html", ".htm")):
        return False
    head = content[:5000].lower()
    return bool(re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']mkdocs[-\d.]?', head))


def _is_local_development_url(url: str) -> bool:
    if "[[" in url and "]]" in url:
        return True
    try:
        host = urlparse(url).hostname or ""
    except ValueError:
        return False
    host = host.lower()
    return (
        host in {"localhost", "127.0.0.1", "0.0.0.0", "::1"}
        or host.endswith(".local")
        or ("." not in host and "local" in host)
    )


def _is_test_fixture_asset_path(rel_path: str) -> bool:
    parts = tuple(part.lower() for part in rel_path.replace("\\", "/").split("/") if part)
    if not parts:
        return False
    return any(
        part in {
            "test",
            "tests",
            "testing",
            "testdata",
            "test_data",
            "fixture",
            "fixtures",
            "__fixtures__",
            "functional_tests",
        }
        or part.endswith("-fixtures")
        for part in parts[:-1]
    )


def _is_html_commented_reference(lines: list[str], line_number: int, dep: str) -> bool:
    if not dep or not (0 < line_number <= len(lines)):
        return False
    line = lines[line_number - 1]
    dep_index = line.find(dep)
    if dep_index == -1:
        return False
    prefix = line[:dep_index]
    return prefix.rfind("<!--") > prefix.rfind("-->")
