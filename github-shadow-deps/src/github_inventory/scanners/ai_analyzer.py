"""
AI-powered shadow dependency analyzer (Task 5).

This is NOT a BaseScanner — it operates across the whole repository's findings
to pick "candidate" snippets that the regex scanners couldn't classify with
certainty, then asks an LLM to classify them.

SECURITY:
- Strips secrets via sanitizer.sanitize() before any content leaves the machine.
- Only activated when --ai is passed (Config.ai_enabled is True).
- Lazy-imports the current runtime AI SDK so the base scanner runs without it installed.
- API key from GITHUB_INVENTORY_AI_KEY then ANTHROPIC_API_KEY.
- Caps requests via Config.ai_max_files; rate-limits to 10 calls/minute.
- Never prints snippet content to stdout/stderr (only counts).
- Drops findings with confidence <= 0.7.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from collections import deque
from pathlib import Path
from typing import Optional

from github_inventory.config import Config
from github_inventory.discovery import FileTarget
from github_inventory.models import Category, Finding, Severity
from github_inventory.sanitizer import sanitize

PROMPT_PATH = Path(__file__).parent.parent / "prompts" / "shadow_dep_analysis.txt"
MAX_SNIPPET_LINES = 500
CONFIDENCE_THRESHOLD = 0.7
RATE_LIMIT_CALLS = 10
RATE_LIMIT_WINDOW_S = 60.0
BACKOFF_SCHEDULE = (1, 2, 4, 8)

# Trigger substrings that mark a regex-found dep as worth a closer AI look.
_AMBIGUOUS_TRIGGERS = ("curl", "wget", "install", "fetch", "download")
# File types worth scanning even with zero regex hits — common shadow-dep harbors.
_INTEREST_FILE_TYPES = frozenset({"script", "ci", "dockerfile", "build"})

_CATEGORY_LOOKUP = {c.value: c for c in Category}
_SEVERITY_LOOKUP = {s.value: s for s in Severity}


class AIAnalyzer:
    """Optional AI shadow-dep classifier. Called from ScanEngine."""

    name = "ai-analyzer"

    def __init__(self, config: Config):
        self.config = config
        self._client = None  # lazy
        self._call_times: deque[float] = deque()
        self._prompt: Optional[str] = None

    # ---------- public entrypoint -----------------------------------------

    def analyze(
        self,
        repo_root: Path,
        targets: list[FileTarget],
        existing_findings: list[Finding],
    ) -> list[Finding]:
        """Pick candidates, send to LLM, return new Findings."""
        if not self.config.ai_enabled:
            return []

        if not self._ensure_client():
            return []

        candidates = self._select_candidates(targets, existing_findings)
        candidates = candidates[: self.config.ai_max_files]

        prompt = self._load_prompt()
        out: list[Finding] = []
        for target in candidates:
            try:
                content = target.path.read_text(errors="replace")
            except OSError:
                continue
            snippet = _slice_snippet(content, MAX_SNIPPET_LINES)
            sanitized = sanitize(snippet)
            response = self._call_llm(prompt, target.rel_path, sanitized)
            if response is None:
                continue
            out.extend(self._parse_response(response, target.rel_path))
        return out

    # ---------- candidate selection ---------------------------------------

    def _select_candidates(
        self,
        targets: list[FileTarget],
        existing_findings: list[Finding],
    ) -> list[FileTarget]:
        findings_by_file: dict[str, list[Finding]] = {}
        for f in existing_findings:
            findings_by_file.setdefault(f.file_path, []).append(f)

        ambiguous: list[FileTarget] = []
        unclassified: list[FileTarget] = []

        for t in targets:
            file_findings = findings_by_file.get(t.rel_path, [])
            if file_findings:
                # Has regex hits but only sub-CRITICAL — re-examine if any extracted_dep
                # contains an ambiguous trigger.
                if not any(f.severity == Severity.CRITICAL for f in file_findings) and any(
                    any(trig in (f.extracted_dep or "").lower() for trig in _AMBIGUOUS_TRIGGERS)
                    for f in file_findings
                ):
                    ambiguous.append(t)
            else:
                if t.file_type in _INTEREST_FILE_TYPES:
                    unclassified.append(t)

        # Ambiguous first (they're more likely to yield real findings), then unclassified.
        return ambiguous + unclassified

    # ---------- LLM client ------------------------------------------------

    def _ensure_client(self) -> bool:
        if self._client is not None:
            return True
        try:
            import anthropic  # noqa: F401  (lazy import)
        except ImportError:
            print(
                "[ai-analyzer] current runtime AI SDK not installed — skipping AI analysis. "
                "Install with: pip install -r requirements-ai.txt",
                file=sys.stderr,
            )
            return False

        key = os.environ.get("GITHUB_INVENTORY_AI_KEY") or os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            print(
                "[ai-analyzer] no API key set (GITHUB_INVENTORY_AI_KEY or "
                "ANTHROPIC_API_KEY) — skipping AI analysis.",
                file=sys.stderr,
            )
            return False

        from anthropic import Anthropic
        self._client = Anthropic(api_key=key)
        return True

    def _load_prompt(self) -> str:
        if self._prompt is None:
            self._prompt = PROMPT_PATH.read_text()
        return self._prompt

    def _rate_limit(self) -> None:
        now = time.monotonic()
        # Drop entries older than the window.
        while self._call_times and now - self._call_times[0] > RATE_LIMIT_WINDOW_S:
            self._call_times.popleft()
        if len(self._call_times) >= RATE_LIMIT_CALLS:
            sleep_for = RATE_LIMIT_WINDOW_S - (now - self._call_times[0]) + 0.1
            if sleep_for > 0:
                time.sleep(sleep_for)
        self._call_times.append(time.monotonic())

    def _call_llm(self, system_prompt: str, file_label: str, snippet: str) -> Optional[str]:
        # Lazy-import error types so the regex path never sees them.
        try:
            from anthropic import APIStatusError, RateLimitError
        except ImportError:
            return None

        user_msg = f"File: {file_label}\n\n```\n{snippet}\n```"
        last_err: Optional[Exception] = None
        for delay in (0, *BACKOFF_SCHEDULE):
            if delay:
                time.sleep(delay)
            self._rate_limit()
            try:
                msg = self._client.messages.create(
                    model=self.config.ai_model,
                    max_tokens=2048,
                    system=system_prompt,
                    messages=[{"role": "user", "content": user_msg}],
                )
                # Concatenate text blocks.
                parts = []
                for block in msg.content:
                    text = getattr(block, "text", None)
                    if text:
                        parts.append(text)
                return "".join(parts)
            except RateLimitError as e:  # type: ignore[misc]
                last_err = e
                continue
            except APIStatusError as e:  # type: ignore[misc]
                last_err = e
                # 5xx → retry; 4xx other than 429 → bail.
                status = getattr(e, "status_code", 0)
                if status and 400 <= status < 500 and status != 429:
                    print(f"[ai-analyzer] API error {status} — bailing on {file_label}", file=sys.stderr)
                    return None
                continue
            except Exception as e:  # network / unknown
                last_err = e
                continue

        print(
            f"[ai-analyzer] giving up on {file_label} after retries: {type(last_err).__name__}",
            file=sys.stderr,
        )
        return None

    # ---------- response parsing ------------------------------------------

    def _parse_response(self, response: str, file_path: str) -> list[Finding]:
        items = _coerce_json_array(response)
        out: list[Finding] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            if not item.get("is_shadow_dependency"):
                continue
            try:
                conf = float(item.get("confidence", 0.0))
            except (TypeError, ValueError):
                continue
            if conf <= CONFIDENCE_THRESHOLD:
                continue

            cat_str = item.get("category", "")
            sev_str = item.get("severity", "")
            category = _CATEGORY_LOOKUP.get(cat_str)
            severity = _SEVERITY_LOOKUP.get(sev_str)
            if category is None or severity is None:
                continue

            try:
                line_no = int(item.get("line_number", 1))
            except (TypeError, ValueError):
                line_no = 1
            line_no = max(1, line_no)

            description = (item.get("description") or "")[:300]
            recommendation = (item.get("recommendation") or "")[:300]

            out.append(Finding(
                file_path=file_path,
                line_number=line_no,
                category=category,
                severity=severity,
                pattern_id="ai-shadow-dep",
                matched_text=description[:200],
                extracted_dep=description[:200],
                description=description or "AI-detected shadow dependency",
                scanner_name=self.name,
                analysis_source="ai-assisted",
                confidence=conf,
                enrichment={"recommendation": recommendation} if recommendation else None,
            ))
        return out


# ---------- helpers --------------------------------------------------------

_JSON_ARRAY_RE = re.compile(r"\[[\s\S]*\]")


def _coerce_json_array(text: str) -> list:
    """Be lenient: model may wrap JSON in code fences or add a sentence."""
    if not text:
        return []
    try:
        parsed = json.loads(text)
        return parsed if isinstance(parsed, list) else []
    except json.JSONDecodeError:
        pass
    m = _JSON_ARRAY_RE.search(text)
    if not m:
        return []
    try:
        parsed = json.loads(m.group(0))
        return parsed if isinstance(parsed, list) else []
    except json.JSONDecodeError:
        return []


def _slice_snippet(content: str, max_lines: int) -> str:
    lines = content.splitlines()
    if len(lines) <= max_lines:
        return content
    return "\n".join(lines[:max_lines])


def merge_ai_findings(
    existing: list[Finding],
    ai_findings: list[Finding],
    line_proximity: int = 1,
) -> list[Finding]:
    """Drop AI findings that duplicate a regex finding within ±N lines on the same file."""
    by_file_cat: dict[tuple[str, str], list[int]] = {}
    for f in existing:
        if f.analysis_source == "ai-assisted":
            continue
        by_file_cat.setdefault((f.file_path, f.category.value), []).append(f.line_number)

    keep: list[Finding] = []
    for ai in ai_findings:
        key = (ai.file_path, ai.category.value)
        regex_lines = by_file_cat.get(key, [])
        if any(abs(ai.line_number - rl) <= line_proximity for rl in regex_lines):
            continue
        keep.append(ai)
    return keep
