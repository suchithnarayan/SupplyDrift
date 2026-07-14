"""Category 9: Reference Tracking - Detects file/script references in YAML configs."""
from __future__ import annotations

import re

from github_inventory.models import Category, Severity
from github_inventory.scanners.base import BaseScanner, PatternRule


class ReferenceTrackingScanner(BaseScanner):
    name = "reference-tracking"

    def scan_file_content(self, target, content: str, lines: list[str]):
        if _is_test_fixture_reference_path(getattr(target, "rel_path", "")):
            return []
        findings = super().scan_file_content(target, content, lines)
        _normalize_makefile_script_references(findings)
        findings = [
            finding for finding in findings
            if not _is_local_node_package_script_reference(finding)
            and not _is_url_makefile_script_reference(finding)
            and not _is_glob_makefile_script_reference(finding)
            and not _is_makefile_script_target_definition(finding)
            and not _is_cmake_makefile_script_reference(target, finding)
        ]
        return _dedupe_findings_by_file_dependency(findings)

    def register_rules(self) -> None:
        # Group 1: GitHub Actions run: blocks referencing scripts.
        # Skip paths that can never be in the repo and thus provide no
        # reference-tracking value:
        # - Absolute Unix paths: `/opt/...`, `/usr/...`
        # - Windows absolute paths: `C:\...`
        # - Quoted/shell-var-expanded runtime paths: `"${RUNNER_TEMP}/...`,
        #   `$GITHUB_WORKSPACE/...`
        self.add_rule(PatternRule(
            pattern_id="github-action-run-script",
            regex=re.compile(
                r"^\s*-?\s*run:\s*(?:bash\s+|sh\s+)?"
                r"(?P<dep>"
                r"(?![/\\])"              # no leading /, \
                r"(?!\w:[/\\])"           # no C:\ drive letters
                r'(?![\'"])'              # no leading quote (next token is a path)
                r"(?!\$)"                 # no leading $VAR
                r"[^\s]+\.(?:sh|bash|zsh|ps1))",
                re.IGNORECASE | re.MULTILINE,
            ),
            severity=Severity.MEDIUM,
            description_template="GitHub Actions workflow references local script: {dep}",
            category=Category.SCRIPT_REFERENCE,
            file_types=["ci"],
        ))

        # Group 2: Dockerfile COPY/ADD commands referencing scripts
        self.add_rule(PatternRule(
            pattern_id="dockerfile-copy-script",
            regex=re.compile(
                r"(?:COPY|ADD)\s+(?P<dep>[^\s]+\.(?:sh|bash|py|js|rb))\s+",
                re.IGNORECASE,
            ),
            severity=Severity.LOW,
            description_template="Dockerfile copies script file: {dep}",
            category=Category.SCRIPT_REFERENCE,
            file_types=["dockerfile"],
        ))

        # Group 3: docker-compose build: references
        self.add_rule(PatternRule(
            pattern_id="compose-build-reference",
            regex=re.compile(
                r"build:\s*['\"]?(?P<dep>\.?/[^\s'\"]+(?:Dockerfile)?)['\"]?",
                re.IGNORECASE,
            ),
            severity=Severity.LOW,
            description_template="docker-compose references build context/file: {dep}",
            category=Category.FILE_REFERENCE,
            file_types=["dockerfile"],
        ))

        # Group 4: Makefile script invocations
        self.add_rule(PatternRule(
            pattern_id="makefile-script-reference",
            regex=re.compile(
                r"^\s*(?:bash\s+|sh\s+|\.\/)?(?P<dep>[^\s]+\.(?:sh|bash))(?=$|[\s\"';&|)])",
                re.IGNORECASE | re.MULTILINE,
            ),
            severity=Severity.MEDIUM,
            description_template="Makefile invokes script: {dep}",
            category=Category.SCRIPT_REFERENCE,
            file_types=["build"],
        ))

        # Group 5: package.json scripts referencing files
        self.add_rule(PatternRule(
            pattern_id="npm-script-file-reference",
            regex=re.compile(
                r'"(?:pre|post)?(?:install|build|test|deploy|start)":\s*"(?:[^"]*\s)?(?P<dep>(?:\.?/)?[^\s"]+\.(?:sh|js|mjs|cjs))"',
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="package.json script references file: {dep}",
            category=Category.SCRIPT_REFERENCE,
            file_types=["package_config"],
        ))

        # Group 6: Kubernetes ConfigMap embedded scripts with shadow dependencies
        self.add_rule(PatternRule(
            pattern_id="k8s-configmap-embedded-script",
            regex=re.compile(
                r"kind:\s*ConfigMap.*?data:\s*\n\s+[\w.-]+:\s*\|.*?(?P<dep>(?:curl|wget|bash|npm|pip|git|go\s+install|cargo\s+install)\s+[^\n]+)",
                re.IGNORECASE | re.DOTALL,
            ),
            severity=Severity.HIGH,
            description_template="Kubernetes ConfigMap contains embedded script with command: {dep}",
            category=Category.EMBEDDED_SCRIPT,
            file_types=["k8s"],
            multiline=True,
        ))

        # Group 7: Kubernetes command arrays referencing scripts
        self.add_rule(PatternRule(
            pattern_id="k8s-command-script",
            regex=re.compile(
                r"command:\s*\[\s*['\"](?P<dep>/[^\s'\"]+\.(?:sh|bash|py))['\"]",
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="Kubernetes container command references script: {dep}",
            category=Category.SCRIPT_REFERENCE,
            file_types=["k8s"],
        ))

        # Additional: Detect volume mount references to scripts
        self.add_rule(PatternRule(
            pattern_id="docker-compose-volume-script",
            regex=re.compile(
                r"volumes?:\s*\n\s*-\s*['\"]?(?P<dep>\.?/[^\s:'\"]+(\.sh|\.bash|\.py|\.js))['\"]?:",
                re.IGNORECASE | re.MULTILINE,
            ),
            severity=Severity.LOW,
            description_template="docker-compose volume mounts script file: {dep}",
            category=Category.SCRIPT_REFERENCE,
            file_types=["dockerfile"],
            multiline=True,
        ))

        # Additional: Helm values.yaml script references
        self.add_rule(PatternRule(
            pattern_id="helm-script-reference",
            regex=re.compile(
                r"(?:script|command|entrypoint):\s*['\"]?(?P<dep>\.?/[^\s'\"]+\.(?:sh|bash|py))['\"]?",
                re.IGNORECASE,
            ),
            severity=Severity.LOW,
            description_template="Helm chart references script file: {dep}",
            category=Category.SCRIPT_REFERENCE,
            file_types=["k8s"],
        ))


def _is_local_node_package_script_reference(finding) -> bool:
    if finding.pattern_id != "npm-script-file-reference":
        return False
    dep = finding.extracted_dep.lower()
    if not dep.endswith((".js", ".mjs", ".cjs")):
        return False
    text = finding.matched_text
    script_key = _npm_script_key(text)
    if script_key in {"install", "preinstall", "postinstall"}:
        return False
    if script_key in {"build", "test", "start"}:
        return True
    if re.search(r"\.config\.(?:js|mjs|cjs)$", dep, re.IGNORECASE):
        return True
    return bool(re.search(
        r'(?:^|[";&|]\s*)(?:node|tsx|ts-node|mocha|jest|vitest|ava|nyc|c8)\b',
        text,
        re.IGNORECASE,
    ))


def _npm_script_key(text: str) -> str:
    match = re.search(r'"(?P<key>(?:pre|post)?(?:install|build|test|deploy|start))"\s*:', text, re.IGNORECASE)
    return match.group("key").lower() if match else ""


def _is_test_fixture_reference_path(rel_path: str) -> bool:
    parts = rel_path.replace("\\", "/").lower().split("/")
    has_test_path = any(part in {"test", "tests", "testing"} or part.endswith("tests") for part in parts[:-1])
    has_fixture_data = any(
        part in {
            "fixture",
            "fixtures",
            "__fixtures__",
            "resource",
            "resources",
            "testdata",
            "test-data",
            "testassets",
            "test-assets",
        }
        for part in parts[:-1]
    )
    return has_test_path and has_fixture_data


def _normalize_makefile_script_references(findings) -> None:
    for finding in findings:
        if finding.pattern_id != "makefile-script-reference":
            continue
        dep = finding.extracted_dep.lstrip("@-+")
        if dep == finding.extracted_dep:
            continue
        finding.extracted_dep = dep
        finding.description = f"Makefile invokes script: {dep}"


def _is_url_makefile_script_reference(finding) -> bool:
    return (
        finding.pattern_id == "makefile-script-reference"
        and finding.extracted_dep.lower().startswith(("http://", "https://"))
    )


def _is_glob_makefile_script_reference(finding) -> bool:
    return (
        finding.pattern_id == "makefile-script-reference"
        and "*" in finding.extracted_dep
    )


def _is_makefile_script_target_definition(finding) -> bool:
    return (
        finding.pattern_id == "makefile-script-reference"
        and bool(re.match(r"\S+\.(?:sh|bash)\s*:", finding.matched_text, re.IGNORECASE))
    )


def _is_cmake_makefile_script_reference(target, finding) -> bool:
    if finding.pattern_id != "makefile-script-reference":
        return False
    rel = getattr(target, "rel_path", "").replace("\\", "/").lower()
    return rel.endswith("cmakelists.txt") or rel.endswith(".cmake")


def _dedupe_findings_by_file_dependency(findings):
    deduped = []
    seen = set()
    for finding in findings:
        key = (finding.file_path, finding.pattern_id, finding.extracted_dep)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped
