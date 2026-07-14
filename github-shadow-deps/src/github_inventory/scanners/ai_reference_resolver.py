"""
AI-powered reference resolver (Task 6).

Regex-based reference tracking misses dynamically-constructed paths
(`$SCRIPT_DIR/install.sh`, `source <(...)`, `eval ...`). This module
asks the LLM to enumerate the file paths and URLs that *would* be
referenced at runtime by such constructs.

It returns a set of additional repo-relative paths for the engine to
scan with the regex scanners. URLs are not fetched.

Activated only when Config.ai_enabled is True.
"""
from __future__ import annotations

import json
import os
import re
import sys
from typing import Optional

from github_inventory.config import Config
from github_inventory.discovery import FileTarget
from github_inventory.sanitizer import sanitize

DYNAMIC_HINT_RE = re.compile(
    r"(\$\{?[A-Z_][A-Z0-9_]*\}?\s*/|source\s+<\(|eval\s+|\.\s+<\()",
    re.MULTILINE,
)
MAX_FILES_PER_RUN = 10
MAX_SNIPPET_LINES = 200

SYSTEM_PROMPT = (
    "You are a build/CI script analyst. Given a script or config snippet, "
    "list every file path and URL that this code would *reference* at "
    "runtime. Do NOT classify danger; just enumerate.\n\n"
    "Respond with JSON only — an object with two arrays:\n"
    '{"files": ["relative/path.sh", ...], "urls": ["https://...", ...]}\n\n'
    "Rules:\n"
    "- Resolve common shell variables when context makes them obvious "
    "(e.g. $SCRIPT_DIR → the directory of the script; $PWD → repo root).\n"
    "- If a variable is unknowable, omit that reference rather than guess.\n"
    "- Only repo-relative paths in `files` (no leading /).\n"
    "- Empty arrays are fine. Output ONLY the JSON object."
)


class AIReferenceResolver:
    name = "ai-reference-resolver"

    def __init__(self, config: Config):
        self.config = config
        self._client = None

    def resolve(self, targets: list[FileTarget]) -> set[str]:
        if not self.config.ai_enabled:
            return set()
        if not self._ensure_client():
            return set()

        # Pick files that contain dynamic-reference hints and are likely
        # to invoke other scripts/binaries.
        candidates: list[FileTarget] = []
        for t in targets:
            if t.file_type not in {"script", "ci", "dockerfile", "build"}:
                continue
            try:
                content = t.path.read_text(errors="replace")
            except OSError:
                continue
            if DYNAMIC_HINT_RE.search(content):
                candidates.append(t)
            if len(candidates) >= MAX_FILES_PER_RUN:
                break

        resolved_files: set[str] = set()
        for t in candidates:
            try:
                content = t.path.read_text(errors="replace")
            except OSError:
                continue
            snippet = "\n".join(content.splitlines()[:MAX_SNIPPET_LINES])
            sanitized = sanitize(snippet)
            response = self._call_llm(t.rel_path, sanitized)
            if response is None:
                continue
            parsed = _safe_parse(response)
            for f in parsed.get("files", []) or []:
                if isinstance(f, str) and f and not f.startswith("/"):
                    resolved_files.add(f.lstrip("./"))
        return resolved_files

    # ---------- internals -------------------------------------------------

    def _ensure_client(self) -> bool:
        if self._client is not None:
            return True
        try:
            import anthropic  # noqa: F401
        except ImportError:
            print(
                "[ai-reference-resolver] current runtime AI SDK not installed — skipping.",
                file=sys.stderr,
            )
            return False
        key = os.environ.get("GITHUB_INVENTORY_AI_KEY") or os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            print(
                "[ai-reference-resolver] no API key set — skipping reference resolution.",
                file=sys.stderr,
            )
            return False
        from anthropic import Anthropic
        self._client = Anthropic(api_key=key)
        return True

    def _call_llm(self, file_label: str, snippet: str) -> Optional[str]:
        try:
            user_msg = f"File: {file_label}\n\n```\n{snippet}\n```"
            msg = self._client.messages.create(
                model=self.config.ai_model,
                max_tokens=1024,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_msg}],
            )
            parts = []
            for block in msg.content:
                text = getattr(block, "text", None)
                if text:
                    parts.append(text)
            return "".join(parts)
        except Exception as e:
            print(
                f"[ai-reference-resolver] error on {file_label}: {type(e).__name__}",
                file=sys.stderr,
            )
            return None


_JSON_OBJ_RE = re.compile(r"\{[\s\S]*\}")


def _safe_parse(text: str) -> dict:
    if not text:
        return {}
    try:
        v = json.loads(text)
        return v if isinstance(v, dict) else {}
    except json.JSONDecodeError:
        pass
    m = _JSON_OBJ_RE.search(text)
    if not m:
        return {}
    try:
        v = json.loads(m.group(0))
        return v if isinstance(v, dict) else {}
    except json.JSONDecodeError:
        return {}
