from __future__ import annotations

import re
import time
from pathlib import Path

from github_inventory.config import Config
from github_inventory.discovery import FileDiscovery, FileTarget, FILE_RULES
from github_inventory.models import Category, Finding, ScanResult, Severity
from github_inventory.scanners import ALL_SCANNERS
from github_inventory.scanners.base import BaseScanner
from github_inventory.scanners.vendored_binaries import VendoredBinaryScanner

# AI scanners are imported lazily inside run() — never at module import time —
# so the regex path stays usable without the optional runtime AI SDK installed.

_LINE_CONTINUATION_RE = re.compile(r"\\\n\s*")
_CONTINUATION_FILE_TYPES = frozenset({
    "ci", "script", "build", "dockerfile", "build_wrapper", "github_action"
})

# Heredoc body detection for shell-like files.
# Strip heredoc bodies ONLY when the introducer is a print-only command
# (`cat`/`echo`/`printf` without a `>file` redirect) — those bodies are
# always documentation / usage text.
# Keep heredocs intact when the introducer line is:
#   - `bash`/`sh`/`zsh`/`eval`/`python`/`node` (body is executed as code)
#   - anything with a `>file` or `>>file` redirect (body written to file
#     that may later be executed)
#   - anything piped into another command (`cat <<EOF | node ...`)
#
# The capture requires the line to start (after optional whitespace) with
# one of the print-only keywords and NOT contain `>` before the heredoc.
_HEREDOC_RE = re.compile(
    r"(?m)^(?P<lead>[ \t]*(?:cat|echo|printf)(?:[ \t]+-\w+)*[ \t]*)"
    r"<<-?\s*['\"]?(?P<tag>[A-Za-z_][A-Za-z0-9_]*)['\"]?(?P<tail>[^\n]*)\n"
    r"(?P<body>.*?)\n\s*(?P=tag)\b",
    re.DOTALL,
)
_HEREDOC_FILE_TYPES = frozenset({"script", "ci", "build", "dockerfile"})


def _strip_heredocs(content: str) -> str:
    def _replace(m: re.Match) -> str:
        # Skip if the introducer line contains a `>` redirect — that
        # writes the body to a file, which may be executed later.
        tail = m.group("tail")
        if ">" in m.group("lead") or ">" in tail or "|" in tail:
            return m.group(0)
        body = m.group("body")
        return m.group(0).replace(body, "\n" * body.count("\n"))
    return _HEREDOC_RE.sub(_replace, content)


class ScanEngine:
    """Orchestrates file discovery, scanner execution, deduplication, and filtering."""

    def __init__(self, repo_root: Path, config: Config):
        self.repo_root = repo_root.resolve()
        self.config = config
        self.scanners: list[BaseScanner] = [cls(config) for cls in ALL_SCANNERS]

    def run(self) -> ScanResult:
        start = time.monotonic()
        discovery = FileDiscovery(self.repo_root, self.config)

        all_findings: list[Finding] = []
        files_scanned = 0
        scanned_files: set[str] = set()
        text_targets: list[FileTarget] = []

        # Phase 1: Initial text file scanning — read each file once, run all scanners
        for target in discovery.discover():
            files_scanned += 1
            scanned_files.add(target.rel_path)
            text_targets.append(target)
            all_findings.extend(self._scan_target(target))

        # Phase 1.5: Extract and scan referenced files (hybrid approach)
        referenced_files = self._extract_references(all_findings)

        # Phase 1.6 (optional): AI reference resolution for dynamic/variable refs.
        if self.config.ai_enabled:
            ai_refs = self._resolve_ai_references(text_targets)
            referenced_files |= ai_refs

        repo_root_resolved = self.repo_root.resolve()
        for ref_path in referenced_files:
            if ref_path in scanned_files:
                continue  # Already scanned, skip

            # Containment: a referenced path is attacker-controlled (it comes from a
            # scanned repo). Resolve it and refuse to read anything outside the repo
            # root — this blocks ../.. traversal, absolute paths, and escaping
            # symlinks that would otherwise exfiltrate host files into findings.
            abs_path = (self.repo_root / ref_path).resolve()
            if not abs_path.is_relative_to(repo_root_resolved):
                continue
            if not abs_path.exists() or not abs_path.is_file():
                continue  # Reference doesn't exist, skip

            # Create FileTarget for the referenced file
            target = FileTarget(
                path=abs_path,
                rel_path=ref_path,
                file_type=self._classify_file(ref_path),
            )
            scanned_files.add(ref_path)
            files_scanned += 1
            text_targets.append(target)

            all_findings.extend(self._scan_target(target))

        # Phase 2: Binary file detection (VendoredBinaryScanner only)
        vendored_scanner = next(s for s in self.scanners if isinstance(s, VendoredBinaryScanner))
        for target in discovery.discover_binaries():
            files_scanned += 1
            all_findings.extend(vendored_scanner.scan_file(target))

        # Phase 2.5 (optional): AI-powered analysis on candidate snippets.
        if self.config.ai_enabled:
            ai_findings = self._run_ai_analyzer(text_targets, all_findings)
            all_findings.extend(ai_findings)

        # Phase 2.7 (optional): structural lockfile parsing for transitive
        # postinstall hooks. Lockfiles aren't classified as text targets, so
        # we reuse the same FileDiscovery walk via a dedicated lockfile pass.
        if self.config.deep_lockfile:
            lockfile_findings = self._run_lockfile_analysis()
            all_findings.extend(lockfile_findings)

        # Phase 3: Apply config (ignore rules + severity overrides)
        filtered = []
        for finding in all_findings:
            if self.config.should_ignore(finding.extracted_dep):
                continue
            override = self.config.severity_overrides.get(finding.pattern_id)
            if override:
                finding.severity = Severity(override)
            filtered.append(finding)

        # Phase 3.5: Drop AI findings that overlap a regex finding (±1 line, same category).
        regex_findings = [f for f in filtered if f.analysis_source != "ai-assisted"]
        ai_findings_only = [f for f in filtered if f.analysis_source == "ai-assisted"]
        if ai_findings_only:
            from github_inventory.scanners.ai_analyzer import merge_ai_findings
            ai_findings_only = merge_ai_findings(regex_findings, ai_findings_only)
        filtered = regex_findings + ai_findings_only

        # Phase 4: Deduplicate exact repeated findings. Include extracted_dep
        # so one install command can inventory multiple package operands.
        seen: set[tuple] = set()
        deduped: list[Finding] = []
        for f in filtered:
            key = (f.file_path, f.line_number, f.pattern_id, f.extracted_dep)
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        # Findings cross a trust boundary from scanned content into optional
        # enrichment and every output/persistence path. Discard credentials
        # before enrichment sees them, while reporters repeat this operation
        # as defense in depth.
        deduped = [finding.public_copy() for finding in deduped]

        # Phase 5 (optional): enrich findings with AI-generated context.
        if self.config.ai_enabled and self.config.enrich_enabled:
            from github_inventory.enrichment import EnrichmentClient
            EnrichmentClient(self.config).enrich(deduped)

        # Model output is untrusted too; keep returned ScanResult safe even if
        # enrichment echoes or invents credential-shaped text.
        deduped = [finding.public_copy() for finding in deduped]

        # Sort: severity first, then file path, then line number
        deduped.sort(key=lambda f: (f.severity.sort_order, f.file_path, f.line_number))

        elapsed = (time.monotonic() - start) * 1000
        return ScanResult(findings=deduped, files_scanned=files_scanned, scan_duration_ms=elapsed)

    def _run_ai_analyzer(
        self,
        targets: list[FileTarget],
        existing_findings: list[Finding],
    ) -> list[Finding]:
        from github_inventory.scanners.ai_analyzer import AIAnalyzer
        return AIAnalyzer(self.config).analyze(self.repo_root, targets, existing_findings)

    def _resolve_ai_references(self, targets: list[FileTarget]) -> set[str]:
        from github_inventory.scanners.ai_reference_resolver import AIReferenceResolver
        return AIReferenceResolver(self.config).resolve(targets)

    def _run_lockfile_analysis(self) -> list[Finding]:
        from github_inventory.scanners.lockfile_analysis import LockfileAnalysisScanner
        # Discover lockfile-typed files explicitly (they're not in text_targets
        # because they aren't worth running 19 regex scanners against).
        discovery = FileDiscovery(self.repo_root, self.config)
        lock_targets = [t for t in discovery.discover() if t.file_type == "lockfile"]
        return LockfileAnalysisScanner(self.config).analyze(self.repo_root, lock_targets)

    def _scan_target(self, target: FileTarget) -> list[Finding]:
        """Read a file, join line continuations for shell-like types, and run all text scanners."""
        content = _read(target)
        if content is None:
            return []

        # Strip heredoc bodies BEFORE continuation join — heredoc bodies are
        # doc/usage text, flagging installs inside them is always an FP.
        if target.file_type in _HEREDOC_FILE_TYPES:
            content = _strip_heredocs(content)

        if target.file_type in _CONTINUATION_FILE_TYPES:
            joined = _LINE_CONTINUATION_RE.sub(" ", content)
        else:
            joined = content

        lines = joined.splitlines()
        findings: list[Finding] = []
        for scanner in self.scanners:
            if isinstance(scanner, VendoredBinaryScanner):
                continue
            findings.extend(scanner.scan_file_content(target, joined, lines))
        return findings

    def _extract_references(self, findings: list[Finding]) -> set[str]:
        """Extract file paths from SCRIPT_REFERENCE and FILE_REFERENCE findings."""
        refs: set[str] = set()
        for f in findings:
            if f.category in (Category.SCRIPT_REFERENCE, Category.FILE_REFERENCE):
                # extracted_dep contains the path (e.g., "./scripts/deploy.sh")
                # Normalize: remove leading ./ and make relative
                path = f.extracted_dep.lstrip("./")
                refs.add(path)
        return refs

    def _classify_file(self, rel_path: str) -> str:
        """Classify a file type based on its path/extension."""
        from fnmatch import fnmatch

        p = Path(rel_path)
        for file_type, patterns in FILE_RULES:
            for pattern in patterns:
                if fnmatch(rel_path, pattern) or fnmatch(p.name, pattern):
                    return file_type
        return "script"  # Default for unclassified files


def _read(target: FileTarget) -> str | None:
    try:
        return target.path.read_text(errors="replace")
    except OSError:
        return None
