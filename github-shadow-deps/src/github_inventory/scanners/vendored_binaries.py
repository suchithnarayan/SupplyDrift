"""Category 7: Vendored/checked-in binary files."""
from __future__ import annotations

from pathlib import Path

from github_inventory.discovery import FileTarget
from github_inventory.models import Category, Finding, Severity
from github_inventory.scanners.base import BaseScanner

# Threshold above which we report a binary as "large"
_LARGE_THRESHOLD = 100 * 1024  # 100 KB

# Directories where compiled artifacts are expected (not flagged as suspicious)
_NORMAL_BUILD_DIRS = ("build/", "target/", "out/", ".gradle/", "dist/", "bin/")

_EXEC_EXTENSIONS = frozenset({".exe", ".dll", ".so", ".dylib", ".wasm"})
_JAVA_EXTENSIONS = frozenset({".jar", ".class", ".war", ".ear"})
_ARCHIVE_EXTENSIONS = frozenset({".a", ".lib", ".o", ".obj"})
_FONT_EXTENSIONS = frozenset({".woff", ".woff2", ".ttf", ".otf", ".eot"})
# Fonts (.woff/.woff2/.ttf/.otf/.eot) are deliberately NOT tracked —
# browsers sandbox font loading, they aren't an executable supply-chain
# risk, and vendoring them is the norm in web apps.


class VendoredBinaryScanner(BaseScanner):
    name = "vendored-binaries"

    def register_rules(self) -> None:
        # This scanner is file-existence based, not regex-based
        pass

    def scan_file(self, target: FileTarget) -> list[Finding]:
        if target.file_type != "binary":
            return []

        findings: list[Finding] = []
        ext = target.path.suffix.lower()
        try:
            size = target.path.stat().st_size
        except OSError:
            return []

        in_build_dir = any(target.rel_path.startswith(d) for d in _NORMAL_BUILD_DIRS)

        if ext in _FONT_EXTENSIONS:
            return []

        if ext in _EXEC_EXTENSIONS:
            findings.append(Finding(
                file_path=target.rel_path,
                line_number=1,
                category=Category.VENDORED_BINARY,
                severity=Severity.LOW,
                pattern_id="vendored-executable",
                matched_text=f"Binary file ({ext}, {size} bytes)",
                extracted_dep=target.rel_path,
                description=f"Executable binary checked into repository ({ext}): {target.rel_path}",
                scanner_name=self.name,
            ))

        elif ext in _JAVA_EXTENSIONS:
            findings.append(Finding(
                file_path=target.rel_path,
                line_number=1,
                category=Category.VENDORED_BINARY,
                severity=Severity.LOW if in_build_dir else Severity.MEDIUM,
                pattern_id="vendored-java-artifact",
                matched_text=f"Java artifact ({ext}, {size} bytes)",
                extracted_dep=target.rel_path,
                description=f"Java artifact checked into repository ({ext}): {target.rel_path}",
                scanner_name=self.name,
            ))

        elif ext in _ARCHIVE_EXTENSIONS:
            findings.append(Finding(
                file_path=target.rel_path,
                line_number=1,
                category=Category.VENDORED_BINARY,
                severity=Severity.LOW,
                pattern_id="vendored-static-lib",
                matched_text=f"Static library ({ext}, {size} bytes)",
                extracted_dep=target.rel_path,
                description=f"Static library checked into repository ({ext}): {target.rel_path}",
                scanner_name=self.name,
            ))

        # Font files (.woff/.woff2/.ttf/.otf/.eot) intentionally NOT flagged.
        # They're not executable code paths in any meaningful threat model
        # (loaded by the browser font engine, not the JS runtime), and
        # ~every web app vendors them. The previous `vendored-font-file`
        # rule produced ~50 LOW noise findings per real-world web repo
        # without surfacing any actionable signal.

        # Large binary blob (any extension, above threshold, actually binary content)
        elif size > _LARGE_THRESHOLD and _is_binary(target.path):
            findings.append(Finding(
                file_path=target.rel_path,
                line_number=1,
                category=Category.VENDORED_BINARY,
                severity=Severity.LOW,
                pattern_id="large-binary-blob",
                matched_text=f"Large binary blob ({size} bytes)",
                extracted_dep=target.rel_path,
                description=f"Large binary blob checked into repository ({size} bytes): {target.rel_path}",
                scanner_name=self.name,
            ))

        if findings and _is_test_fixture_binary_path(target.rel_path):
            return []

        return findings


def _is_binary(path: Path) -> bool:
    """Heuristic: check for null bytes in first 8 KB."""
    try:
        with open(path, "rb") as f:
            return b"\x00" in f.read(8192)
    except OSError:
        return False


def _is_test_fixture_binary_path(rel_path: str) -> bool:
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
            "fixtures",
            "fixture",
            "__fixtures__",
            "testassets",
            "test-assets",
            "e2e",
            "e2e-test",
            "e2e-tests",
            "e2e-ports",
        }
        or part.startswith("test-")
        or part.startswith("tests-")
        or part.endswith("-tests")
        or part.endswith("e2etest")
        for part in parts[:-1]
    )
