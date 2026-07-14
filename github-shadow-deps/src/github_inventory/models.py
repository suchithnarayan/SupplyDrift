from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Optional


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def sort_order(self) -> int:
        return {"critical": 0, "high": 1, "medium": 2, "low": 3}[self.value]

    @property
    def exit_worthy(self) -> bool:
        return self in (Severity.CRITICAL, Severity.HIGH)


class Category(Enum):
    SCRIPT_INSTALLATION = "script-installation"
    BINARY_DOWNLOAD = "binary-download"
    UNMANAGED_PACKAGE = "unmanaged-package"
    GIT_DEPENDENCY = "git-dependency"
    CONTAINER_IMAGE = "container-image"
    CICD_TOOL = "cicd-tool"
    VENDORED_BINARY = "vendored-binary"
    BUILD_EXTERNAL = "build-external"
    SCRIPT_REFERENCE = "script-reference"
    FILE_REFERENCE = "file-reference"
    EMBEDDED_SCRIPT = "embedded-script"
    PRECOMMIT_HOOK = "precommit-hook"
    DEVCONTAINER = "devcontainer"
    TOOL_VERSION_MANAGER = "tool-version-manager"
    REGISTRY_CONFIG = "registry-config"
    CDN_REFERENCE = "cdn-reference"
    SOURCE_HTTP_CALL = "source-http-call"
    MCP_SERVER = "mcp-server"
    AGENT_PLUGIN = "agent-plugin"
    SYSTEM_PACKAGE_LIST = "system-package-list"
    PULUMI_RESOURCE = "pulumi-resource"
    PACKAGE_SCRIPT = "package-script"
    TRANSITIVE_HOOK = "transitive-hook"


@dataclass
class Finding:
    file_path: str
    line_number: int
    category: Category
    severity: Severity
    pattern_id: str
    matched_text: str
    extracted_dep: str
    description: str
    scanner_name: str
    end_line: Optional[int] = None
    # Set by AI scanner (Task 5/6). None for regex findings.
    analysis_source: Optional[str] = None
    confidence: Optional[float] = None
    # Set by enrichment (Task 7). Shape: {"summary": str, "risks": str, "recommendation": str}
    enrichment: Optional[dict] = None
    # Safe metadata about a credential finding. Credential values are never stored.
    sensitive: Optional[dict] = None

    def public_copy(self) -> "Finding":
        """Return a redacted copy safe for enrichment, output, or persistence."""
        from github_inventory.redaction import redact_text, redact_value

        return replace(
            self,
            file_path=redact_text(self.file_path),
            matched_text=redact_text(self.matched_text),
            extracted_dep=redact_text(self.extracted_dep),
            description=redact_text(self.description),
            enrichment=redact_value(self.enrichment),
            sensitive=redact_value(self.sensitive),
        )

    def to_dict(self) -> dict:
        public = self.public_copy()
        d = {
            "file": public.file_path,
            "line": public.line_number,
            "end_line": public.end_line,
            "category": public.category.value,
            "severity": public.severity.value,
            "pattern_id": public.pattern_id,
            "matched_text": public.matched_text,
            "extracted_dep": public.extracted_dep,
            "description": public.description,
            "scanner": public.scanner_name,
        }
        if public.analysis_source is not None:
            d["analysis_source"] = public.analysis_source
        if public.confidence is not None:
            d["confidence"] = public.confidence
        if public.enrichment is not None:
            d["enrichment"] = public.enrichment
        if public.sensitive is not None:
            d["sensitive"] = public.sensitive
        return d


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    scan_duration_ms: float = 0.0

    @property
    def has_blocking_findings(self) -> bool:
        return any(f.severity.exit_worthy for f in self.findings)

    def summary_by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts

    def summary_by_category(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.category.value] = counts.get(f.category.value, 0) + 1
        return counts
