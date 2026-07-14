"""Category 5: Unpinned/untagged container images, docker run in scripts, non-standard registries."""
from __future__ import annotations

import re

from github_inventory.discovery import FileTarget
from github_inventory.models import Category, Finding, Severity
from github_inventory.scanners.base import BaseScanner, PatternRule

# Mutable tags that indicate the image is not pinned to an immutable version
_MUTABLE_TAGS = r"(?:latest|main|master|develop|dev|stable|edge|nightly|canary|next|alpha|beta|rc)"
_MUTABLE_TAG = _MUTABLE_TAGS + r"(?:[._-][\w.-]+)?"
_SCRIPTABLE_TYPES = ["ci", "script", "build", "dockerfile", "github_action", "agent_instruction"]
_MARKDOWN_DOC_EXTENSIONS = frozenset({".md", ".mdx"})
_ORDINARY_MARKDOWN_DOC_NAMES = frozenset({
    "README.md",
    "INSTALL.md",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "PUBLISHING.md",
    "DEVELOPER.md",
    "MAC-README.md",
    "MOBILE-README.md",
    "WINDOWS-README.md",
})
_AGENT_CONTROL_DOC_NAMES = frozenset({"AGENTS.md", "CLAUDE.md", "CODEX.md", "SKILL.md"})
_AGENT_CONTROL_DOC_DIRS = frozenset({".agents", ".claude", ".codex", ".cursor"})

# Digests are safe: image@sha256:... — these should NOT be flagged
# Pattern for a valid semver-like tag to exclude from "mutable" check
_SEMVER_LIKE = r"(?:v?\d+(?:\.\d+){0,3}(?:-[a-zA-Z0-9.]+)?)"
_DOCKER_RUN_RE = re.compile(r"\bdocker\s+run\b", re.IGNORECASE)
_DOCKER_PULL_RE = re.compile(r"\bdocker\s+pull\b", re.IGNORECASE)
_CONTAINER_MARKDOWN_COMMAND_RE = re.compile(r"\b(?:docker|podman|nerdctl)\s+(?:run|pull)\b", re.IGNORECASE)
_DOCKERFILE_RUN_RE = re.compile(r"^\s*RUN(?:\s|$)", re.IGNORECASE)
_SHELL_SEPARATORS = {";", "&&", "||", "|", ">", ">>", "<", "2>", "2>>", "2>&1"}
_DOCKER_BOOL_FLAGS = {
    "--rm", "--init", "--privileged", "--tty", "--interactive", "--detach",
    "--read-only", "--oom-kill-disable", "--no-healthcheck", "--sig-proxy",
    "-d", "-i", "-t", "-it", "-ti",
}
_DOCKER_VALUE_FLAGS = {
    "--volume", "--mount", "--env", "--env-file", "--name", "--hostname",
    "--workdir", "--user", "--network", "--net", "--add-host", "--entrypoint",
    "--label", "--platform", "--publish", "--expose", "--pull", "--restart",
    "--device", "--dns", "--dns-search", "--security-opt", "--cap-add",
    "--cap-drop", "--group-add", "--ulimit", "--log-driver", "--log-opt",
    "--cidfile", "--gpus", "--attach",
}
_SHORT_VALUE_FLAGS = {"a", "v", "e", "p", "u", "w", "h", "l"}
_INVALID_IMAGE_TOKENS = {".", "\\", "$@", "$*", "${@}", "${*}"}
_IMAGE_VAR_RE = re.compile(r"(?:IMAGE|IMG|REGISTRY|REPOSITORY|REPO|TAG)", re.IGNORECASE)
_OPTION_VAR_RE = re.compile(r"(?:FLAGS|OPTS|ARGS|PARAMS|NETWORK|CONTAINER_NAME)", re.IGNORECASE)
_VAR_TOKEN_RE = re.compile(
    r"^\$"
    r"(?:\{(?P<brace>[A-Za-z_][A-Za-z0-9_]*)\}|\((?P<paren>[A-Za-z_][A-Za-z0-9_]*)\)|(?P<bare>[A-Za-z_][A-Za-z0-9_]*))$"
)
_PARAM_OPTION_EXPANSION_RE = re.compile(
    r"^\$\{(?P<name>[A-Za-z_][A-Za-z0-9_]*)(?P<op>:\+|:-)(?P<body>.*)\}$",
    re.DOTALL,
)
_PARAM_DEFAULT_EXPANSION_RE = re.compile(
    r"\$\{[A-Za-z_][A-Za-z0-9_]*:-(?P<default>[^}]+)\}"
)
_IMAGE_ENV_RE = re.compile(
    r"^\s*(?:-\s*)?(?P<key>[A-Za-z_][A-Za-z0-9_]*IMAGE)\s*:\s*['\"]?(?P<dep>[^'\"\s#]+)",
)
_IMAGE_HELPER_RE = re.compile(r"(?:^|[/_-])(?:download|cache|pull)[-_]docker[-_]images?(?:\.sh)?$", re.IGNORECASE)
_COMMON_BARE_IMAGES = frozenset({
    "alpine", "busybox", "debian", "golang", "mongo", "mysql", "nginx",
    "node", "postgres", "python", "redis", "ubuntu",
})
_ASPIRE_PLACEHOLDER_IMAGES = frozenset({"image", "myimage"})
_DOCKERFILE_FROM_RE = re.compile(
    r"^\s*FROM\s+(?:--platform=\S+\s+)?(?P<image>\S+)(?:\s+(?:AS|as)\s+(?P<alias>[A-Za-z][\w.-]*))?",
    re.IGNORECASE,
)
_DOCKERFILE_ARG_RE = re.compile(
    r"^\s*ARG\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)(?:=(?P<value>[^\s#]+))?",
    re.IGNORECASE,
)
_YAML_MAP_KEY_RE = re.compile(r"^(?P<indent>\s*)(?:-\s*)?(?P<key>[A-Za-z_][\w.-]*)\s*:\s*(?P<value>.*)$")


class ContainerImageScanner(BaseScanner):
    name = "container-images"

    def scan_file_content(self, target: FileTarget, content: str, lines: list[str]) -> list[Finding]:
        if target.file_type == "dockerfile" and _has_docker_detector_suppression(content):
            return []
        if target.file_type in {"dockerfile", "k8s"} and _is_container_snapshot_fixture_path(target.rel_path):
            return []
        if target.file_type == "dockerfile" and _is_container_test_resource_fixture_path(target.rel_path):
            return []
        if target.file_type == "k8s" and _is_k8s_test_fixture_path(target.rel_path):
            return []
        findings = super().scan_file_content(target, content, lines)
        if target.file_type == "dockerfile":
            findings = _filter_dockerfile_stage_alias_findings(findings, lines)
            findings = _filter_repo_local_dockerfile_base_findings(target, findings)
            findings = _resolve_dockerfile_arg_from_findings(findings, lines)
        if target.file_type in _SCRIPTABLE_TYPES:
            findings.extend(_scan_docker_run_lines(target, lines))
            findings.extend(_scan_docker_pull_lines(target, lines))
            findings.extend(_scan_image_helper_lines(target, lines))
        if target.file_type in {"ci", "github_action"}:
            findings.extend(_scan_image_env_lines(target, lines))
            findings.extend(_scan_ci_yaml_container_image_lines(target, lines))
        if target.file_type == "k8s":
            findings.extend(_scan_structured_helm_image_lines(target, lines))
        if target.file_type == "source_code":
            findings.extend(_scan_aspire_source_container_lines(target, content, lines))
        findings = _resolve_container_default_expansions(findings)
        findings = [
            finding for finding in findings
            if not _is_non_control_markdown_container_command_example(target, finding, lines)
            and not _is_markdown_docker_digest_lookup_example(target, finding, lines)
            and not _is_placeholder_container_image_dependency(finding.extracted_dep)
        ]
        return findings

    def register_rules(self) -> None:
        # FROM <image>:<mutable-tag> in Dockerfiles
        self.add_rule(PatternRule(
            pattern_id="unpinned-dockerfile-from",
            regex=re.compile(
                r"^FROM\s+(?P<dep>[\w./:-]+:" + _MUTABLE_TAG + r")(?:\s+(?:AS|as)\s+\w+)?\s*$",
                re.IGNORECASE | re.MULTILINE,
            ),
            severity=Severity.HIGH,
            description_template="Dockerfile FROM uses mutable image tag: {dep}",
            category=Category.CONTAINER_IMAGE,
            file_types=["dockerfile"],
        ))

        # FROM <image> with NO tag at all (implicitly :latest)
        self.add_rule(PatternRule(
            pattern_id="dockerfile-from-no-tag",
            regex=re.compile(
                r"^FROM\s+(?P<dep>(?!scratch\b|base\b|build\b|builder\b|final\b|runtime\b|runner\b|deps\b|test\b)"
                r"[\w./][\w./-]*)(?:\s+(?:AS|as)\s+\w+)?\s*$",
                re.IGNORECASE | re.MULTILINE,
            ),
            severity=Severity.HIGH,
            description_template="Dockerfile FROM has no tag (defaults to :latest): {dep}",
            category=Category.CONTAINER_IMAGE,
            file_types=["dockerfile"],
        ))

        # image: <name>:<mutable-tag> in k8s / docker-compose YAML
        self.add_rule(PatternRule(
            pattern_id="k8s-mutable-image-tag",
            regex=re.compile(
                r"^\s*(?:-\s*)?image:\s*['\"]?(?P<dep>[\w./:-]+:" + _MUTABLE_TAG + r")['\"]?",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="Container image uses mutable tag in manifest: {dep}",
            category=Category.CONTAINER_IMAGE,
            file_types=["k8s", "dockerfile"],
        ))

        # image: <name> with NO tag at all in k8s manifests
        self.add_rule(PatternRule(
            pattern_id="k8s-image-no-tag",
            regex=re.compile(
                r"image:\s*['\"]?(?P<dep>[\w.-]+(?:/[\w.-]+)+)['\"]?\s*$",
                re.IGNORECASE | re.MULTILINE,
            ),
            severity=Severity.HIGH,
            description_template="Container image has no tag in manifest (defaults to :latest): {dep}",
            category=Category.CONTAINER_IMAGE,
            file_types=["k8s", "dockerfile"],
        ))

        # Dockerfile ADD with remote URL (downloads at build time)
        self.add_rule(PatternRule(
            pattern_id="dockerfile-add-url",
            regex=re.compile(
                r"^ADD\s+(?P<dep>https?://\S+)\s+",
                re.IGNORECASE | re.MULTILINE,
            ),
            severity=Severity.HIGH,
            description_template="Dockerfile ADD downloads remote file at build time: {dep}",
            category=Category.BINARY_DOWNLOAD,
            file_types=["dockerfile"],
        ))

        # COPY --from=<external-image> in multi-stage builds
        self.add_rule(PatternRule(
            pattern_id="dockerfile-copy-from-image",
            regex=re.compile(
                r"^COPY\s+--from=(?P<dep>(?![\w-]+\s)[\w./:-]+(?:@sha256:[a-f0-9]+)?)\s+",
                re.IGNORECASE | re.MULTILINE,
            ),
            severity=Severity.HIGH,
            description_template="Dockerfile COPY --from pulls external image as dependency: {dep}",
            category=Category.CONTAINER_IMAGE,
            file_types=["dockerfile"],
        ))

        # podman run/pull (Docker-compatible alternative)
        self.add_rule(PatternRule(
            pattern_id="podman-run-in-script",
            regex=re.compile(
                r"podman\s+(?:run|pull)\s+"
                r"(?:[^\n]*?\s)?"
                r"(?P<dep>"
                r"[\w][\w.-]*(?:/[\w][\w.-]*)+(?::[\w][\w.+-]*)?"
                r")"
                r"(?:@sha256:[a-f0-9]+)?"
                r"(?=\s|$)",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="podman run/pull in script (shadow container dependency): {dep}",
            category=Category.CONTAINER_IMAGE,
            file_types=_SCRIPTABLE_TYPES,
        ))

        # nerdctl run/pull
        self.add_rule(PatternRule(
            pattern_id="nerdctl-run-in-script",
            regex=re.compile(
                r"nerdctl\s+(?:run|pull)\s+"
                r"(?:[^\n]*?\s)?"
                r"(?P<dep>"
                r"[\w][\w.-]*(?:/[\w][\w.-]*)+(?::[\w][\w.+-]*)?"
                r")"
                r"(?:@sha256:[a-f0-9]+)?"
                r"(?=\s|$)",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="nerdctl run/pull in script (shadow container dependency): {dep}",
            category=Category.CONTAINER_IMAGE,
            file_types=_SCRIPTABLE_TYPES,
        ))

        # buildah from
        self.add_rule(PatternRule(
            pattern_id="buildah-from",
            regex=re.compile(
                r"buildah\s+(?:from|bud)\s+"
                r"(?:[^\n]*?\s)?"
                r"(?P<dep>"
                r"[\w][\w.-]*(?:/[\w][\w.-]*)+(?::[\w][\w.+-]*)?"
                r")"
                r"(?:@sha256:[a-f0-9]+)?"
                r"(?=\s|$)",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="buildah from/bud references container image: {dep}",
            category=Category.CONTAINER_IMAGE,
            file_types=_SCRIPTABLE_TYPES,
        ))

        # skopeo copy
        self.add_rule(PatternRule(
            pattern_id="skopeo-copy",
            regex=re.compile(
                r"skopeo\s+copy\s+[^\n]*?(?P<dep>docker://[\w./:-]+)",
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="skopeo copy references container image: {dep}",
            category=Category.CONTAINER_IMAGE,
            file_types=_SCRIPTABLE_TYPES,
        ))

        # crane pull
        self.add_rule(PatternRule(
            pattern_id="crane-pull",
            regex=re.compile(
                r"crane\s+pull\s+(?P<dep>[\w./:-]+(?:@sha256:[a-f0-9]+)?)",
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="crane pull references container image: {dep}",
            category=Category.CONTAINER_IMAGE,
            file_types=_SCRIPTABLE_TYPES,
        ))

        # Live generated JSON configs for MCP gateways and similar wrappers.
        # These commonly appear in CI heredocs piped into a node/bootstrap
        # command; the engine preserves those bodies while stripping plain
        # printed help heredocs.
        self.add_rule(PatternRule(
            pattern_id="json-container-image",
            regex=re.compile(
                r'"container"\s*:\s*"(?P<dep>(?![^"]*@sha256:)[\w./:-]+)"',
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="Generated config references container image: {dep}",
            category=Category.CONTAINER_IMAGE,
            file_types=_SCRIPTABLE_TYPES,
        ))

        # oras pull (OCI artifact)
        self.add_rule(PatternRule(
            pattern_id="oras-pull",
            regex=re.compile(
                r"oras\s+pull\s+(?P<dep>[\w./:-]+(?:@sha256:[a-f0-9]+)?)",
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="oras pull fetches OCI artifact: {dep}",
            category=Category.CONTAINER_IMAGE,
            file_types=_SCRIPTABLE_TYPES,
        ))

        # docker-compose / k8s image: inventory — all service images
        self.add_rule(PatternRule(
            pattern_id="compose-image-inventory",
            regex=re.compile(
                r"^\s+image:\s*['\"]?(?P<dep>[\w./${}:-]+(?:@sha256:[a-f0-9]+)?)['\"]?\s*$",
                re.IGNORECASE | re.MULTILINE,
            ),
            severity=Severity.LOW,
            description_template="Docker Compose service image dependency: {dep}",
            category=Category.CONTAINER_IMAGE,
            file_types=["dockerfile"],
        ))

        # Dockerfile FROM inventory — all base images regardless of tag pinning.
        # Excludes `scratch` and multi-stage aliases like `FROM base AS final`
        # (where `base` is a stage name defined earlier, not an image).
        # Real image refs always contain `/`, `:`, `@`, or a `${VAR}`/`$VAR`
        # substitution. Bare identifiers like `base`/`builder`/`final` are aliases.
        self.add_rule(PatternRule(
            pattern_id="dockerfile-from-inventory",
            regex=re.compile(
                r"^FROM\s+"
                r"(?P<dep>(?!scratch\b)"
                r"(?=[\w./${}:-]*[/:@$])"
                r"[\w./${}:-]+(?:@sha256:[a-f0-9]+)?)"
                r"(?:\s+(?:AS|as)\s+\w+)?\s*$",
                re.IGNORECASE | re.MULTILINE,
            ),
            severity=Severity.LOW,
            description_template="Dockerfile base image dependency: {dep}",
            category=Category.CONTAINER_IMAGE,
            file_types=["dockerfile"],
        ))

        # Non-standard / private registries
        self.add_rule(PatternRule(
            pattern_id="non-standard-registry",
            regex=self._build_registry_regex(),
            severity=Severity.MEDIUM,
            description_template="Container image from non-standard/private registry: {dep}",
            category=Category.CONTAINER_IMAGE,
            file_types=["dockerfile", "k8s", "ci"],
        ))

    def _build_registry_regex(self) -> re.Pattern:
        """Build non-standard-registry regex incorporating trusted_registries from config."""
        static_trusted = [
            r"docker\.io", r"index\.docker\.io", r"gcr\.io", r"ghcr\.io",
            r"quay\.io", r"registry\.hub\.docker\.com",
            r"mcr\.microsoft\.com", r"public\.ecr\.aws",
        ]

        for registry in self.config.get_all_trusted_registries():
            escaped = re.escape(registry).replace(r"\*", r"[\w.-]*")
            static_trusted.append(escaped)

        exclusion = "|".join(static_trusted)
        pattern = (
            r"(?:^FROM|image:)\s+['\"]?(?P<dep>"
            r"(?!" + exclusion + r")"
            r"[a-z0-9][\w.-]*\.[a-z]{2,}/[\w./${}:@-]+)['\"]?"
        )
        return re.compile(pattern, re.IGNORECASE | re.MULTILINE)


def _scan_docker_run_lines(target: FileTarget, lines: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for line_number, line, stripped in _iter_shell_command_lines(target, lines):
        if target.file_type in {"ci", "github_action"} and _is_yaml_metadata_label(stripped):
            continue
        for match in _DOCKER_RUN_RE.finditer(line):
            if _is_non_executable_docker_command_context(line, match.start()):
                continue
            dep = _extract_docker_run_image(_docker_command_args(line, match))
            if not dep:
                continue
            dep = dep[:200]
            findings.append(Finding(
                file_path=target.rel_path,
                line_number=line_number,
                category=Category.CONTAINER_IMAGE,
                severity=Severity.HIGH,
                pattern_id="docker-run-in-script",
                matched_text=stripped[:200],
                extracted_dep=dep,
                description=f"docker run in script (shadow container dependency): {dep}",
                scanner_name=ContainerImageScanner.name,
            ))
    return findings


def _scan_docker_pull_lines(target: FileTarget, lines: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for line_number, line, stripped in _iter_shell_command_lines(target, lines):
        if target.file_type in {"ci", "github_action"} and _is_yaml_metadata_label(stripped):
            continue
        for match in _DOCKER_PULL_RE.finditer(line):
            if _is_non_executable_docker_command_context(line, match.start()):
                continue
            dep = _extract_docker_pull_image(_docker_command_args(line, match))
            if not dep:
                continue
            dep = dep[:200]
            findings.append(Finding(
                file_path=target.rel_path,
                line_number=line_number,
                category=Category.CONTAINER_IMAGE,
                severity=Severity.HIGH,
                pattern_id="docker-pull-in-script",
                matched_text=stripped[:200],
                extracted_dep=dep,
                description=f"docker pull in script (shadow container dependency): {dep}",
                scanner_name=ContainerImageScanner.name,
            ))
    return findings


def _iter_shell_command_lines(
    target: FileTarget,
    lines: list[str],
) -> list[tuple[int, str, str]]:
    command_lines: list[tuple[int, str, str]] = []
    in_dockerfile_run = False
    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            if target.file_type == "dockerfile":
                in_dockerfile_run = False
            continue
        if target.file_type == "dockerfile":
            is_run_instruction = bool(_DOCKERFILE_RUN_RE.match(line))
            if not is_run_instruction and not in_dockerfile_run:
                continue
            command_lines.append((line_number, line, stripped))
            in_dockerfile_run = line.rstrip().endswith("\\")
            continue
        command_lines.append((line_number, line, stripped))
    return command_lines


def _scan_image_helper_lines(target: FileTarget, lines: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        tokens = _shell_words(line)
        for helper_index, token in enumerate(tokens):
            if not _is_image_helper_token(_clean_token(token)):
                continue
            for dep in _image_refs_after_helper(tokens[helper_index + 1:]):
                findings.append(_container_finding(
                    target,
                    line_number,
                    "ci-image-helper-argument",
                    dep,
                    stripped,
                    f"CI helper downloads tag-only container image: {dep}",
                ))
    return findings


def _scan_image_env_lines(target: FileTarget, lines: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _IMAGE_ENV_RE.match(line)
        if not match:
            continue
        dep = _clean_image_ref(match.group("dep"))
        if not _is_tag_only_image_ref(dep):
            continue
        findings.append(_container_finding(
            target,
            line_number,
            "ci-image-env-var",
            dep,
            stripped,
            f"CI image environment variable references tag-only image: {dep}",
        ))
    return findings


def _scan_ci_yaml_container_image_lines(target: FileTarget, lines: list[str]) -> list[Finding]:
    if _is_github_workflow_path(target.rel_path):
        return []
    findings: list[Finding] = []
    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _YAML_MAP_KEY_RE.match(line)
        if not match:
            continue
        key = match.group("key")
        if key not in {"container", "image"}:
            continue
        dep = _ci_yaml_image_value(match.group("value"), key)
        if not dep or not _is_ci_yaml_container_image_ref(dep):
            continue
        findings.append(_ci_container_finding(target, line_number, dep, stripped))
    return findings


def _is_github_workflow_path(rel_path: str) -> bool:
    rel = rel_path.replace("\\", "/").lower()
    return "/.github/workflows/" in f"/{rel}"


def _ci_yaml_image_value(value: str, key: str) -> str:
    value = value.split(" #", 1)[0].strip()
    if not value or value in {"|", ">"}:
        return ""
    if key == "container" and value.startswith("{"):
        match = re.search(r"\bimage\s*:\s*['\"]?(?P<dep>[^,'\"}]+)", value)
        if not match:
            return ""
        value = match.group("dep").strip()
    return _clean_image_ref(value)


def _is_ci_yaml_container_image_ref(dep: str) -> bool:
    if not dep or dep.startswith(("http://", "https://", "$")):
        return False
    if any(token in dep for token in ("&&", "||")):
        return False
    if " " in dep and "${{" not in dep:
        return False
    if "{" in dep and "${{" not in dep:
        return False
    if dep.startswith(("{", "[")):
        return False
    if re.fullmatch(r"[A-Za-z0-9_.-]+", dep):
        return dep.lower() in _COMMON_BARE_IMAGES
    return _is_image_like_candidate(dep)


def _scan_structured_helm_image_lines(target: FileTarget, lines: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for image_line_number, line in enumerate(lines, start=1):
        match = _YAML_MAP_KEY_RE.match(line)
        if not match or match.group("key").lower() != "image":
            continue
        if _yaml_unquoted_value(match.group("value")):
            continue

        image_indent = len(match.group("indent"))
        repository: tuple[int, str] | None = None
        tag: tuple[int, str] | None = None
        for child_line_number, child_line in enumerate(lines[image_line_number:], start=image_line_number + 1):
            if not child_line.strip() or child_line.lstrip().startswith("#"):
                continue
            child = _YAML_MAP_KEY_RE.match(child_line)
            if not child:
                continue
            child_indent = len(child.group("indent"))
            if child_indent <= image_indent:
                break
            key = child.group("key").lower()
            value = _yaml_unquoted_value(child.group("value"))
            if not value:
                continue
            if key == "repository":
                repository = (child_line_number, value)
            elif key == "tag":
                tag = (child_line_number, value)
            if repository and tag:
                break

        if not repository or not tag:
            continue
        _, repo = repository
        tag_line_number, tag_value = tag
        dep = _compose_structured_image_ref(repo, tag_value)
        if dep is None:
            continue
        findings.append(_container_finding(
            target,
            tag_line_number,
            "helm-structured-image-tag",
            dep,
            lines[tag_line_number - 1].strip(),
            f"Helm values compose mutable container image tag: {dep}",
        ))
    return findings


def _yaml_unquoted_value(value: str) -> str:
    value = value.split("#", 1)[0].strip()
    if not value or value in {"|", ">"}:
        return ""
    return value.strip("'\"")


def _compose_structured_image_ref(repository: str, tag: str) -> str | None:
    repository = _clean_image_ref(repository)
    tag = tag.strip("'\"")
    if not repository or not tag or "@sha256:" in repository or "@sha256:" in tag:
        return None
    if not re.fullmatch(_MUTABLE_TAG, tag, re.IGNORECASE):
        return None
    return f"{repository}:{tag}"


def _scan_aspire_source_container_lines(
    target: FileTarget,
    content: str,
    lines: list[str],
) -> list[Finding]:
    if not _is_aspire_apphost_source_path(target.rel_path) or not _looks_like_aspire_apphost_source(content):
        return []

    findings: list[Finding] = []
    has_publish_container = re.search(r"\bpublishContainer\s*:\s*true\b|\bpublish_container\s*=\s*True\b", content) is not None
    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "//", "*")):
            continue

        for dep in _extract_aspire_add_container_images(line):
            finding = _source_container_finding(
                target,
                line_number,
                "aspire-source-container-image",
                dep,
                stripped,
                "Aspire AppHost source references container image",
            )
            if finding:
                findings.append(finding)

        for dep in _extract_aspire_add_service_images(line):
            finding = _source_container_finding(
                target,
                line_number,
                "aspire-source-service-image",
                dep,
                stripped,
                "Aspire generated compose service references container image",
            )
            if finding:
                findings.append(finding)

        if has_publish_container:
            for dep in _extract_aspire_base_images(line):
                finding = _source_container_finding(
                    target,
                    line_number,
                    "aspire-source-base-image",
                    dep,
                    stripped,
                    "Aspire publish-container options reference base image",
                )
                if finding:
                    findings.append(finding)
    return findings


def _has_docker_detector_suppression(content: str) -> bool:
    return any(
        "disabledockerdetector" in line.lower()
        for line in content.splitlines()[:10]
    )


def _is_placeholder_container_image_dependency(dep: str) -> bool:
    return bool(
        re.search(r"<[^>\s]+>", dep)
        or re.search(r"(?:^|[/:])your[-_][A-Za-z0-9_.-]+(?:[/:]|$)", dep, re.IGNORECASE)
    )


def _is_markdown_docker_digest_lookup_example(
    target: FileTarget,
    finding: Finding,
    lines: list[str],
) -> bool:
    if finding.pattern_id != "docker-pull-in-script":
        return False
    if target.file_type != "agent_instruction" or target.path.suffix.lower() not in _MARKDOWN_DOC_EXTENSIONS:
        return False
    if not (0 < finding.line_number <= len(lines)):
        return False
    line = lines[finding.line_number - 1]
    return bool(
        re.search(r"\bdigest\b", line, re.IGNORECASE)
        and re.search(r"\bdocker\s+pull\b", line, re.IGNORECASE)
        and re.search(r"\bdocker\s+inspect\b", line, re.IGNORECASE)
        and finding.extracted_dep.lower() in line.lower()
    )


def _is_non_control_markdown_container_command_example(
    target: FileTarget,
    finding: Finding,
    lines: list[str],
) -> bool:
    if finding.pattern_id not in {"docker-run-in-script", "docker-pull-in-script"}:
        return False
    if target.file_type != "agent_instruction" or target.path.suffix.lower() not in _MARKDOWN_DOC_EXTENSIONS:
        return False
    name = target.path.name.lower()
    if name in {doc.lower() for doc in _AGENT_CONTROL_DOC_NAMES}:
        return False
    if any(part.lower() in _AGENT_CONTROL_DOC_DIRS for part in target.path.parts):
        return False
    if _is_reference_markdown_path(target.rel_path):
        return _is_markdown_code_example_line(lines, finding.line_number, finding.extracted_dep)
    if _is_documentation_markdown_path(target.rel_path):
        return _is_markdown_code_example_line(lines, finding.line_number, finding.extracted_dep)
    if not _is_ordinary_markdown_doc_name(name):
        return False
    return _is_markdown_code_example_line(lines, finding.line_number, finding.extracted_dep)


def _is_reference_markdown_path(rel_path: str) -> bool:
    path = "/" + rel_path.replace("\\", "/").lower()
    return "/reference/" in path or "/references/" in path


def _is_documentation_markdown_path(rel_path: str) -> bool:
    path = "/" + rel_path.replace("\\", "/").lower()
    return (
        "/docs/" in path
        or "/doc/" in path
        or "/documentation/" in path
        or "/content/docs/" in path
    )


def _is_ordinary_markdown_doc_name(name: str) -> bool:
    lower = name.lower()
    if lower in {doc.lower() for doc in _ORDINARY_MARKDOWN_DOC_NAMES}:
        return True
    if not lower.endswith((".md", ".mdx")):
        return False
    stem = re.sub(r"\.mdx?$", "", lower)
    normalized = stem.replace("-", "_")
    return (
        normalized == "setup"
        or normalized == "quick_reference"
        or normalized == "dev_setup"
        or normalized.startswith("readme_")
        or normalized.endswith("_readme")
        or normalized.endswith("_install")
        or normalized.endswith("_installation")
    )


def _is_markdown_code_example_line(lines: list[str], line_number: int, dep: str) -> bool:
    if not (0 < line_number <= len(lines)):
        return False
    line = lines[line_number - 1]
    if line.startswith(("    ", "\t")):
        return True
    if _is_markdown_inline_code_example(line, dep):
        return True

    in_fence = False
    for index, current in enumerate(lines, start=1):
        stripped = current.lstrip()
        is_fence = stripped.startswith("```") or stripped.startswith("~~~")
        if index == line_number:
            return in_fence or is_fence
        if is_fence:
            in_fence = not in_fence
    return False


def _is_markdown_inline_code_example(line: str, dep: str) -> bool:
    if "`" not in line:
        return False
    dep = dep.lower()
    start = 0
    while True:
        start = line.find("`", start)
        if start == -1:
            return False
        end = line.find("`", start + 1)
        if end == -1:
            return False
        span = line[start + 1:end].lower()
        if dep and dep in span and _CONTAINER_MARKDOWN_COMMAND_RE.search(span):
            return True
        start = end + 1


def _filter_dockerfile_stage_alias_findings(findings: list[Finding], lines: list[str]) -> list[Finding]:
    alias_refs = _dockerfile_stage_alias_refs(lines)
    if not alias_refs:
        return findings
    return [
        finding
        for finding in findings
        if not (
            finding.pattern_id == "dockerfile-from-no-tag"
            and (finding.line_number, finding.extracted_dep.lower()) in alias_refs
        )
    ]


def _dockerfile_stage_alias_refs(lines: list[str]) -> set[tuple[int, str]]:
    aliases: set[str] = set()
    refs: set[tuple[int, str]] = set()
    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _DOCKERFILE_FROM_RE.match(line)
        if not match:
            continue
        image = match.group("image").strip("\"'").lower()
        if image in aliases:
            refs.add((line_number, image))
        alias = match.group("alias")
        if alias:
            aliases.add(alias.lower())
    return refs


def _filter_repo_local_dockerfile_base_findings(
    target: FileTarget,
    findings: list[Finding],
) -> list[Finding]:
    return [
        finding
        for finding in findings
        if not (
            finding.pattern_id == "dockerfile-from-no-tag"
            and _is_repo_local_dockerfile_base_image(target, finding.extracted_dep)
        )
    ]


def _is_repo_local_dockerfile_base_image(target: FileTarget, dep: str) -> bool:
    dep = dep.strip().lower()
    if (
        not dep
        or dep in _COMMON_BARE_IMAGES
        or any(marker in dep for marker in ("/", ":", "@", "$"))
    ):
        return False

    try:
        siblings = list(target.path.parent.iterdir())
    except OSError:
        return False

    for sibling in siblings:
        if not sibling.is_file():
            continue
        name = sibling.name.lower()
        if name == target.path.name.lower():
            continue
        if not (name == "dockerfile" or name.startswith("dockerfile.")):
            continue
        suffix = name.removeprefix("dockerfile").lstrip(".-_")
        if suffix and (dep == suffix or dep.endswith(f"-{suffix}") or dep.endswith(f"_{suffix}")):
            return True
    return False


def _resolve_dockerfile_arg_from_findings(findings: list[Finding], lines: list[str]) -> list[Finding]:
    arg_defaults = _dockerfile_arg_defaults(lines)
    resolved: list[Finding] = []
    for finding in findings:
        if finding.pattern_id != "dockerfile-from-inventory":
            resolved.append(finding)
            continue
        dep = _resolve_dockerfile_arg_ref(finding.extracted_dep, arg_defaults)
        if dep is None:
            if _pure_variable_name(finding.extracted_dep):
                continue
            resolved.append(finding)
            continue
        resolved.append(_replace_finding_dep(
            finding,
            dep,
            f"Dockerfile base image dependency: {dep}",
        ))
    return resolved


def _resolve_container_default_expansions(findings: list[Finding]) -> list[Finding]:
    resolved: list[Finding] = []
    for finding in findings:
        dep = _resolve_container_default_expansion(finding.extracted_dep)
        if dep == finding.extracted_dep:
            resolved.append(finding)
            continue
        resolved.append(_replace_finding_dep(
            finding,
            dep,
            finding.description.replace(finding.extracted_dep, dep),
        ))
    return resolved


def _resolve_container_default_expansion(dep: str) -> str:
    if ":-" not in dep:
        return dep

    invalid_default = False

    def replace_default(match: re.Match[str]) -> str:
        nonlocal invalid_default
        default = match.group("default").strip("'\"")
        if not default or re.search(r"\s|[${}]", default):
            invalid_default = True
            return match.group(0)
        return default

    resolved = _PARAM_DEFAULT_EXPANSION_RE.sub(replace_default, dep)
    if invalid_default or resolved == dep or "$" in resolved:
        return dep
    if not _is_image_like_candidate(resolved):
        return dep
    return resolved


def _dockerfile_arg_defaults(lines: list[str]) -> dict[str, str]:
    defaults: dict[str, str] = {}
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _DOCKERFILE_ARG_RE.match(line)
        if not match:
            continue
        value = match.group("value")
        if value:
            defaults[match.group("name")] = value.strip("\"'")
    return defaults


def _resolve_dockerfile_arg_ref(dep: str, arg_defaults: dict[str, str]) -> str | None:
    match = re.fullmatch(r"\$(?:\{(?P<brace>[A-Za-z_][A-Za-z0-9_]*)\}|(?P<bare>[A-Za-z_][A-Za-z0-9_]*))", dep)
    if not match:
        return None
    name = match.group("brace") or match.group("bare")
    return arg_defaults.get(name)


def _replace_finding_dep(finding: Finding, dep: str, description: str) -> Finding:
    return Finding(
        file_path=finding.file_path,
        line_number=finding.line_number,
        category=finding.category,
        severity=finding.severity,
        pattern_id=finding.pattern_id,
        matched_text=finding.matched_text,
        extracted_dep=dep,
        description=description,
        scanner_name=finding.scanner_name,
        end_line=finding.end_line,
        analysis_source=finding.analysis_source,
        confidence=finding.confidence,
        enrichment=finding.enrichment,
    )


def _is_aspire_apphost_source_path(rel_path: str) -> bool:
    return rel_path.rsplit("/", 1)[-1].lower().startswith("apphost.")


def _looks_like_aspire_apphost_source(content: str) -> bool:
    return (
        "createBuilder" in content
        or "create_builder" in content
        or "aspire_app" in content
        or ".aspire/modules/aspire" in content
    )


def _extract_aspire_add_container_images(line: str) -> list[str]:
    deps: list[str] = []
    patterns = (
        r"\bbuilder\s*\.\s*addContainer\s*\(\s*['\"][^'\"]+['\"]\s*,\s*['\"](?P<dep>[^'\"]+)['\"]",
        r"\bbuilder\s*\.\s*add_container\s*\(\s*['\"][^'\"]+['\"]\s*,\s*['\"](?P<dep>[^'\"]+)['\"]",
    )
    for pattern in patterns:
        for match in re.finditer(pattern, line):
            deps.append(match.group("dep"))
    return _unique(deps)


def _extract_aspire_base_images(line: str) -> list[str]:
    deps: list[str] = []
    patterns = (
        r"\bbaseImage\s*:\s*['\"](?P<dep>[^'\"]+)['\"]",
        r"\bbase_image\s*=\s*['\"](?P<dep>[^'\"]+)['\"]",
    )
    for pattern in patterns:
        for match in re.finditer(pattern, line):
            deps.append(match.group("dep"))
    return _unique(deps)


def _extract_aspire_add_service_images(line: str) -> list[str]:
    deps: list[str] = []
    for match in re.finditer(
        r"\.addService\s*\([^)]*\{\s*image\s*:\s*['\"](?P<dep>[^'\"]+)['\"]",
        line,
    ):
        deps.append(match.group("dep"))
    return _unique(deps)


def _source_container_finding(
    target: FileTarget,
    line_number: int,
    pattern_id: str,
    dep: str,
    matched_text: str,
    description_prefix: str,
) -> Finding | None:
    dep = _clean_image_ref(dep)
    if not dep or "@sha256:" in dep:
        return None
    if dep.lower() in _ASPIRE_PLACEHOLDER_IMAGES:
        return None
    if dep.startswith(("/", ".", "http://", "https://")):
        return None

    severity = Severity.LOW
    risk = "dependency"
    tag = _image_tag(dep)
    if tag is None:
        severity = Severity.HIGH
        risk = "with no tag (defaults to latest)"
    elif re.fullmatch(_MUTABLE_TAGS, tag, re.IGNORECASE):
        severity = Severity.HIGH
        risk = f"with mutable tag: {tag}"

    return Finding(
        file_path=target.rel_path,
        line_number=line_number,
        category=Category.CONTAINER_IMAGE,
        severity=severity,
        pattern_id=pattern_id,
        matched_text=matched_text[:200],
        extracted_dep=dep[:200],
        description=f"{description_prefix} {risk}: {dep[:200]}",
        scanner_name=ContainerImageScanner.name,
    )


def _image_tag(dep: str) -> str | None:
    last = dep.rsplit("/", 1)[-1]
    if ":" not in last:
        return None
    return last.rsplit(":", 1)[-1] or None


def _container_finding(
    target: FileTarget,
    line_number: int,
    pattern_id: str,
    dep: str,
    matched_text: str,
    description: str,
) -> Finding:
    return Finding(
        file_path=target.rel_path,
        line_number=line_number,
        category=Category.CONTAINER_IMAGE,
        severity=Severity.HIGH,
        pattern_id=pattern_id,
        matched_text=matched_text[:200],
        extracted_dep=dep[:200],
        description=description,
        scanner_name=ContainerImageScanner.name,
    )


def _ci_container_finding(
    target: FileTarget,
    line_number: int,
    dep: str,
    matched_text: str,
) -> Finding:
    tag = _image_tag(dep)
    severity = Severity.LOW
    risk = "dependency"
    if tag is None:
        severity = Severity.HIGH
        risk = "with no tag (defaults to latest)"
    elif re.fullmatch(_MUTABLE_TAGS, tag, re.IGNORECASE):
        severity = Severity.HIGH
        risk = f"with mutable tag: {tag}"
    return Finding(
        file_path=target.rel_path,
        line_number=line_number,
        category=Category.CONTAINER_IMAGE,
        severity=severity,
        pattern_id="ci-yaml-container-image",
        matched_text=matched_text[:200],
        extracted_dep=dep[:200],
        description=f"CI YAML references container image {risk}: {dep[:200]}",
        scanner_name=ContainerImageScanner.name,
    )


def _is_image_helper_token(token: str) -> bool:
    return bool(_IMAGE_HELPER_RE.search(token))


def _image_refs_after_helper(tokens: list[str]) -> list[str]:
    refs: list[str] = []
    for token in tokens:
        cleaned = _clean_image_ref(token)
        if cleaned in _SHELL_SEPARATORS:
            break
        if _is_tag_only_image_ref(cleaned):
            refs.append(cleaned)
    return _unique(refs)


def _clean_image_ref(token: str) -> str:
    return _clean_token(token).rstrip(",]")


def _is_tag_only_image_ref(dep: str) -> bool:
    if not dep or dep.startswith(("http://", "https://", "$")):
        return False
    if "@sha256:" in dep:
        return False
    if not _is_image_like_candidate(dep):
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9][\w.-]*(?::\d+)?/[\w./-]+(?::[\w.+-]+)?", dep))


def _extract_docker_run_image(args: str) -> str | None:
    tokens = _shell_words(args)
    fallback_variable: str | None = None
    i = 0
    while i < len(tokens):
        token = _clean_token(tokens[i])
        if not token:
            i += 1
            continue
        if token in _SHELL_SEPARATORS:
            return None
        if token in _INVALID_IMAGE_TOKENS:
            i += 1
            continue

        next_i = _skip_docker_option(tokens, i)
        if next_i != i:
            i = next_i
            continue

        if _is_shell_parameter_option_expansion(token):
            i += 1
            continue

        if _is_variable_option_bundle(token, tokens, i):
            i += 1
            continue

        if _is_assignment(token):
            i += 1
            continue

        if token.startswith("-"):
            i += 1
            continue

        image_token = _clean_docker_run_image_candidate(token)
        if _is_local_path_token(image_token):
            return fallback_variable
        pure_variable = _pure_variable_name(image_token)
        if pure_variable and not _IMAGE_VAR_RE.search(pure_variable):
            fallback_variable = fallback_variable or image_token
            i += 1
            continue
        if _is_docker_run_image_token(image_token):
            return image_token
        i += 1
    return fallback_variable


def _extract_docker_pull_image(args: str) -> str | None:
    tokens = _shell_words(args)
    i = 0
    while i < len(tokens):
        token = _clean_token(tokens[i])
        if not token:
            i += 1
            continue
        if token in _SHELL_SEPARATORS:
            return None
        if token in _INVALID_IMAGE_TOKENS:
            i += 1
            continue

        next_i = _skip_docker_option(tokens, i)
        if next_i != i:
            i = next_i
            continue

        if _is_shell_parameter_option_expansion(token):
            i += 1
            continue

        if _is_assignment(token):
            i += 1
            continue

        if token.startswith("-"):
            i += 1
            continue

        image_token = _clean_docker_run_image_candidate(token)
        if _is_docker_run_image_token(image_token):
            return image_token
        i += 1
    return None


def _clean_docker_run_image_candidate(token: str) -> str:
    if "`:" in token:
        token = token.split("`:", 1)[0]
    return token.strip("'\"`")


def _is_docker_run_image_token(token: str) -> bool:
    if token.endswith((".", ",", ":", ";", "!", "?")):
        return False
    if _pure_variable_name(token):
        return bool(_IMAGE_VAR_RE.search(_pure_variable_name(token) or ""))
    if "$" in token:
        return True
    if _is_image_like_candidate(token):
        return True
    return bool(re.fullmatch(r"[a-z0-9][a-z0-9_.-]*", token))


def _skip_docker_option(tokens: list[str], index: int) -> int:
    token = _clean_token(tokens[index])
    if token in _SHELL_SEPARATORS:
        return index
    if token == "--":
        return index + 1
    if token in _DOCKER_BOOL_FLAGS or _is_short_bool_cluster(token):
        return index + 1

    if token.startswith("--"):
        name = token.split("=", 1)[0]
        if name in _DOCKER_VALUE_FLAGS:
            return index + 1 if "=" in token else min(index + 2, len(tokens))
        return index + 1

    if token.startswith("-") and len(token) > 1:
        if len(token) == 2 and token[1] in _SHORT_VALUE_FLAGS:
            return min(index + 2, len(tokens))
        if len(token) > 2 and token[1] in _SHORT_VALUE_FLAGS:
            return index + 1
        return index + 1

    return index


def _is_short_bool_cluster(token: str) -> bool:
    return token.startswith("-") and len(token) > 1 and set(token[1:]) <= {"d", "i", "t"}


def _is_variable_option_bundle(token: str, tokens: list[str], index: int) -> bool:
    name = _pure_variable_name(token)
    if not name or _IMAGE_VAR_RE.search(name):
        return False
    if _OPTION_VAR_RE.search(name):
        return True
    return _has_later_image_candidate(tokens, index + 1)


def _has_later_image_candidate(tokens: list[str], start: int) -> bool:
    i = start
    while i < len(tokens):
        token = _clean_token(tokens[i])
        if token in _SHELL_SEPARATORS:
            return False
        if _is_shell_parameter_option_expansion(token):
            i += 1
            continue
        next_i = _skip_docker_option(tokens, i)
        if next_i != i:
            i = next_i
            continue
        if _is_image_like_candidate(token):
            return True
        i += 1
    return False


def _is_image_like_candidate(token: str) -> bool:
    if not token or token in _SHELL_SEPARATORS or token.startswith("-"):
        return False
    if token.endswith((".", ",", ":", ";", "!", "?")):
        return False
    if _is_local_path_token(token):
        return False
    name = _pure_variable_name(token)
    if name:
        return bool(_IMAGE_VAR_RE.search(name))
    if _is_assignment(token):
        return False
    if token.startswith("/"):
        return False
    if re.fullmatch(r"\d+(?:-\d+)?:\d+(?:-\d+)?(?:/[a-z]+)?", token):
        return False
    return "/" in token or ":" in token or "@sha256:" in token


def _is_local_path_token(token: str) -> bool:
    return token.startswith(("/", "./", "../", ".\\", "..\\"))


def _is_k8s_test_fixture_path(rel_path: str) -> bool:
    rel_lower = rel_path.replace("\\", "/").lower()
    path = f"/{rel_lower}"
    return any(segment in path for segment in ("/test/", "/tests/", "/testdata/", "/fixtures/"))


def _is_container_test_resource_fixture_path(rel_path: str) -> bool:
    parts = tuple(part.lower() for part in rel_path.replace("\\", "/").split("/") if part)
    if not parts:
        return False
    has_test_path = any(part in {"test", "tests"} or part.endswith("tests") for part in parts[:-1])
    has_fixture_data = any(part in {"resource", "resources", "fixture", "fixtures", "__fixtures__"} for part in parts[:-1])
    return has_test_path and has_fixture_data


def _is_container_snapshot_fixture_path(rel_path: str) -> bool:
    parts = tuple(part.lower() for part in rel_path.replace("\\", "/").split("/") if part)
    if not parts:
        return False
    has_test_path = any(part in {"test", "tests"} or part.endswith("tests") for part in parts[:-1])
    has_snapshot_path = any(part in {"snapshot", "snapshots", "__snapshots__"} for part in parts[:-1])
    name = parts[-1]
    return has_test_path and has_snapshot_path and name.endswith((".verified.yaml", ".verified.yml"))


def _is_assignment(token: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", token))


def _is_non_executable_docker_command_context(line: str, command_start: int) -> bool:
    if _looks_like_docker_command_prose(line[command_start:]):
        return True
    prefix = line[:command_start]
    if re.search(r"\bthrow\s+['\"][^'\"]*$", prefix, re.IGNORECASE):
        return True
    if _looks_like_printed_help(line):
        if "$(" in prefix or "`" in prefix:
            return False
        return not re.search(r"(?:&&|\|\||[;|])", prefix)
    return False


def _looks_like_docker_command_prose(command_text: str) -> bool:
    return bool(re.search(
        r"\bdocker\s+pull\s*,\s*(?:inspect|run|push|build)\b"
        r"|\bdocker\s+run\s+commands?\b",
        command_text,
        re.IGNORECASE,
    ))


def _docker_command_args(line: str, match: re.Match[str]) -> str:
    code_end = _inline_code_span_end(line, match.start())
    if code_end is not None and code_end >= match.end():
        return line[match.end():code_end]
    return line[match.end():]


def _inline_code_span_end(line: str, command_start: int) -> int | None:
    code_start = line.rfind("`", 0, command_start)
    if code_start == -1:
        return None
    code_end = line.find("`", command_start)
    if code_end == -1:
        return None
    return code_end


def _looks_like_printed_help(line: str) -> bool:
    return bool(re.match(
        r"\s*(?:echo|printf|warn|fail|pass|log|info|debug|error|"
        r"Write-(?:Host|Warning|Output|Verbose|Error|Debug)|throw)\b",
        line,
        re.IGNORECASE,
    ))


def _is_yaml_metadata_label(line: str) -> bool:
    return bool(re.match(r"\s*(?:-\s*)?(?:displayName|name|description|title):\s+", line, re.IGNORECASE))


def _is_shell_parameter_option_expansion(token: str) -> bool:
    match = _PARAM_OPTION_EXPANSION_RE.fullmatch(token)
    if not match:
        return False
    name = match.group("name")
    if _IMAGE_VAR_RE.search(name):
        return False
    body = match.group("body").strip()
    if not body:
        return True
    first = body.split(None, 1)[0]
    return first.startswith("-") or _OPTION_VAR_RE.search(name) is not None


def _pure_variable_name(token: str) -> str | None:
    match = _VAR_TOKEN_RE.fullmatch(token)
    if not match:
        return None
    return match.group("brace") or match.group("paren") or match.group("bare")


def _clean_token(token: str) -> str:
    return token.strip().strip("'\"`")


def _shell_words(text: str) -> list[str]:
    tokens: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        while i < n and text[i].isspace():
            i += 1
        if i >= n:
            break
        if text.startswith("&&", i) or text.startswith("||", i):
            tokens.append(text[i:i + 2])
            i += 2
            continue
        if text[i] in {";", "|"}:
            tokens.append(text[i])
            i += 1
            continue

        buf: list[str] = []
        quote: str | None = None
        while i < n:
            ch = text[i]
            if quote:
                if ch == quote:
                    quote = None
                else:
                    buf.append(ch)
                i += 1
                continue
            if text.startswith("&&", i) or text.startswith("||", i) or ch in {";", "|"} or ch.isspace():
                break
            if ch in {"'", '"'}:
                quote = ch
                i += 1
                continue
            if ch == "$" and i + 1 < n and text[i + 1] in {"(", "{"}:
                expansion, i = _read_expansion(text, i)
                buf.append(expansion)
                continue
            buf.append(ch)
            i += 1

        token = "".join(buf).strip()
        if token:
            tokens.append(token)
    return tokens


def _unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            out.append(value)
    return out


def _read_expansion(text: str, start: int) -> tuple[str, int]:
    opener = text[start + 1]
    closer = "}" if opener == "{" else ")"
    depth = 1
    i = start + 2
    quote: str | None = None
    while i < len(text):
        ch = text[i]
        if quote:
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in {"'", '"'}:
            quote = ch
            i += 1
            continue
        if opener == "(" and ch == "(":
            depth += 1
        elif ch == closer:
            depth -= 1
            if depth == 0:
                return text[start:i + 1], i + 1
        i += 1
    return text[start:i], i
