"""
Vulnerability context enrichment (Task 7).

Given a list of findings, ask the LLM what each unique dependency is, what
known supply-chain risks exist, and how to fix it. Enrichment data comes from
the model's training knowledge — we never fetch URLs from findings.

Activated only when both Config.ai_enabled and Config.enrich_enabled are True.
Findings are batched by `extracted_dep` so e.g. 12 `actions/checkout`
hits become a single API call.
"""
from __future__ import annotations

import json
import os
import re
import sys
from typing import Optional

from github_inventory.config import Config
from github_inventory.models import Finding
from github_inventory.sanitizer import sanitize

MAX_DEPS_PER_REQUEST = 10
SYSTEM_PROMPT = (
    "You are a supply chain security analyst. For each dependency reference "
    "I give you, return a brief assessment based on your training knowledge. "
    "Do NOT fetch URLs.\n\n"
    "Output JSON only — an array of objects in the same order as my input:\n"
    '[{"summary": "<1 sentence on what it is>", '
    '"risks": "<known supply-chain risks or empty string>", '
    '"recommendation": "<how to pin/replace, 1 sentence>"}]\n\n'
    "If you don't know the dependency, return an object with empty strings. "
    "Be concise — under 30 words per field."
)


class EnrichmentClient:
    name = "enrichment"

    def __init__(self, config: Config):
        self.config = config
        self._client = None

    def enrich(self, findings: list[Finding]) -> None:
        """Mutate findings in-place, attaching .enrichment dicts."""
        if not (self.config.ai_enabled and self.config.enrich_enabled):
            return
        if not findings:
            return
        if not self._ensure_client():
            return

        # Group by extracted_dep — one enrichment per unique dependency.
        groups: dict[str, list[Finding]] = {}
        for f in findings:
            dep = (f.public_copy().extracted_dep or "").strip()
            if not dep:
                continue
            groups.setdefault(dep, []).append(f)

        deps = list(groups.keys())
        for batch in _chunked(deps, MAX_DEPS_PER_REQUEST):
            results = self._call_llm(batch)
            if results is None:
                continue
            for dep, enr in zip(batch, results):
                if not isinstance(enr, dict):
                    continue
                if not any(enr.get(k) for k in ("summary", "risks", "recommendation")):
                    continue
                cleaned = {
                    "summary": (enr.get("summary") or "")[:300],
                    "risks": (enr.get("risks") or "")[:300],
                    "recommendation": (enr.get("recommendation") or "")[:300],
                }
                for f in groups[dep]:
                    # Merge with any pre-existing enrichment (e.g. from AI analyzer).
                    if f.enrichment is None:
                        f.enrichment = cleaned
                    else:
                        merged = dict(f.enrichment)
                        merged.update({k: v for k, v in cleaned.items() if v})
                        f.enrichment = merged

    # ---------- internals -------------------------------------------------

    def _ensure_client(self) -> bool:
        if self._client is not None:
            return True
        try:
            import anthropic  # noqa: F401
        except ImportError:
            print("[enrichment] current runtime AI SDK not installed — skipping.", file=sys.stderr)
            return False
        key = os.environ.get("GITHUB_INVENTORY_AI_KEY") or os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            print("[enrichment] no API key set — skipping enrichment.", file=sys.stderr)
            return False
        from anthropic import Anthropic
        self._client = Anthropic(api_key=key)
        return True

    def _call_llm(self, deps: list[str]) -> Optional[list]:
        sanitized = [sanitize(d) for d in deps]
        user_msg = "Dependencies (one per line):\n" + "\n".join(
            f"{i + 1}. {d}" for i, d in enumerate(sanitized)
        )
        try:
            msg = self._client.messages.create(
                model=self.config.ai_model,
                max_tokens=2048,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_msg}],
            )
            parts = []
            for block in msg.content:
                text = getattr(block, "text", None)
                if text:
                    parts.append(text)
            return _safe_parse_array("".join(parts))
        except Exception as e:
            print(f"[enrichment] error: {type(e).__name__}", file=sys.stderr)
            return None


def _chunked(items: list, n: int):
    for i in range(0, len(items), n):
        yield items[i : i + n]


_JSON_ARRAY_RE = re.compile(r"\[[\s\S]*\]")


def _safe_parse_array(text: str) -> list:
    if not text:
        return []
    try:
        v = json.loads(text)
        return v if isinstance(v, list) else []
    except json.JSONDecodeError:
        pass
    m = _JSON_ARRAY_RE.search(text)
    if not m:
        return []
    try:
        v = json.loads(m.group(0))
        return v if isinstance(v, list) else []
    except json.JSONDecodeError:
        return []
