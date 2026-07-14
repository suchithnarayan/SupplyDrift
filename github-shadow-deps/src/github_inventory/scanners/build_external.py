"""Category 8: Makefile downloads, non-standard Maven/Gradle/Helm/Terraform repos, IaC patterns."""
from __future__ import annotations

import json
import re

from github_inventory.discovery import FileTarget
from github_inventory.models import Category, Finding, Severity
from github_inventory.scanners.base import BaseScanner, PatternRule

_JSON_API_URL_RE = re.compile(
    r"https?://(?:"
    r"api\.github\.com/"
    r"|api\.appcenter\.ms/"
    r"|marketplace\.visualstudio\.com/_apis/"
    r"|dev\.azure\.com/[^/\s]+/"
    r"|[^/\s]+\.visualstudio\.com/_apis/"
    r")",
    re.IGNORECASE,
)
_LOCALHOST_URL_RE = re.compile(r"^https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[?::1\]?)(?:[/:?#]|$)", re.IGNORECASE)
_CMAKE_EXTERNAL_PATTERN_IDS = frozenset({"cmake-fetchcontent", "cmake-external-project"})
_GRADLE_REPOSITORY_PATTERN_IDS = frozenset({
    "gradle-non-standard-repo",
    "gradle-plugin-management-repo",
    "gradle-buildscript-repo",
})
_STANDARD_GRADLE_REPOSITORY_HOSTS = frozenset({
    "repo.maven.apache.org",
    "repo1.maven.org",
    "plugins.gradle.org",
    "jcenter.bintray.com",
    "dl.google.com",
    "maven.google.com",
    "repo.spring.io",
    "oss.sonatype.org",
    "s01.oss.sonatype.org",
})
_TEST_FIXTURE_PATH_SEGMENTS = (
    "/test/",
    "/tests/",
    "/testing/",
    "/testdata/",
    "/fixture/",
    "/fixtures/",
    "/__fixtures__/",
)
_PLACEHOLDER_TEST_FIXTURE_EXTERNAL_DEP_RE = re.compile(
    r"^(?:"
    r"https?://(?:[^/?#@]+\.)?example\.(?:com|org|net)(?:[/:?#]|$)"
    r"|https?://github\.com/example/"
    r"|git@github\.com:(?:example|fooco)/"
    r")",
    re.IGNORECASE,
)


class BuildExternalScanner(BaseScanner):
    name = "build-external"

    def scan_file_content(self, target: FileTarget, content: str, lines: list[str]) -> list[Finding]:
        findings = super().scan_file_content(target, content, lines)
        if target.file_type == "build_wrapper":
            _normalize_wrapper_url_findings(target, findings)
        if target.file_type == "build" and target.path.name.endswith((".gradle", ".gradle.kts")):
            findings = [
                finding for finding in findings
                if finding.pattern_id != "url-variable-assignment"
                or not _gradle_url_assignment_is_metadata(lines, finding.line_number)
            ]
        if target.file_type == "build" and target.path.name == "pom.xml":
            findings = [
                finding for finding in findings
                if not (
                    finding.pattern_id == "maven-non-standard-repo"
                    and not _maven_url_is_repository_source(content, finding.line_number)
                )
                and not _pom_xml_url_assignment_is_namespace(lines, finding)
            ]
        if target.file_type == "package_config" and target.path.name == "package.json":
            allowed_npm_git_deps = _package_json_git_dependency_values(content)
            findings = [
                finding for finding in findings
                if finding.pattern_id != "npm-git-dependency"
                or finding.extracted_dep in allowed_npm_git_deps
            ]
        if target.file_type == "package_config" and target.path.name != "Cargo.toml":
            findings = [
                finding for finding in findings
                if finding.pattern_id != "cargo-git-dependency"
            ]
        if target.file_type == "package_config" and target.path.name != "composer.json":
            findings = [
                finding for finding in findings
                if finding.pattern_id != "composer-vcs-repo"
            ]
        findings = [
            finding for finding in findings
            if not _is_non_artifact_makefile_download(finding)
            and not _is_standard_gradle_repository(finding)
            and not _is_placeholder_external_dep_in_test_fixture_path(target, finding)
            and not _is_test_fixture_wrapper_download(target, finding)
        ]
        return findings

    def register_rules(self) -> None:
        # URL variable assignments in Makefiles and Dockerfiles
        self.add_rule(PatternRule(
            pattern_id="url-variable-assignment",
            regex=re.compile(
                r"^\s*[\w]+\s*[:?]?=\s*['\"]?(?P<dep>https?://\S+?)['\"]?\s*$",
                re.MULTILINE,
            ),
            severity=Severity.MEDIUM,
            description_template="URL assigned to variable (external dependency source): {dep}",
            category=Category.BUILD_EXTERNAL,
            file_types=["build", "dockerfile"],
        ))

        # Makefile targets with curl/wget downloads
        self.add_rule(PatternRule(
            pattern_id="makefile-download",
            regex=re.compile(
                r"(?:curl|wget)\b[^\n]*?(?P<dep>https?://[^\s'\"`]+)",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="Binary download inside Makefile target: {dep}",
            category=Category.BUILD_EXTERNAL,
            file_types=["build"],
        ))

        # Maven non-standard repositories
        self.add_rule(PatternRule(
            pattern_id="maven-non-standard-repo",
            regex=re.compile(
                r"<url>\s*(?P<dep>https?://(?!"
                r"repo(?:1)?\.maven\.apache\.org"
                r"|repo\.maven\.apache\.org"
                r"|central\.maven\.org"
                r"|oss\.sonatype\.org"
                r"|s01\.oss\.sonatype\.org"
                r"|jcenter\.bintray\.com"
                r")\S+?)\s*</url>",
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="Non-standard Maven repository: {dep}",
            category=Category.BUILD_EXTERNAL,
            file_types=["build"],
        ))

        # Maven systemPath (local file dependency — often a vendored jar)
        self.add_rule(PatternRule(
            pattern_id="maven-system-path",
            regex=re.compile(
                r"<systemPath>\s*(?P<dep>[^<\n]+?)\s*</systemPath>",
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="Maven dependency using local systemPath (vendored jar): {dep}",
            category=Category.BUILD_EXTERNAL,
            file_types=["build"],
        ))

        # Gradle non-standard repositories
        self.add_rule(PatternRule(
            pattern_id="gradle-non-standard-repo",
            regex=re.compile(
                r"(?:maven|ivy)\s*\{[^}]{0,500}?"
                r"url\s*[=\s]\s*(?:uri\(\s*)?['\"](?P<dep>https?://"
                r"(?!repo\.maven\.apache\.org"
                r"|plugins\.gradle\.org"
                r"|jcenter\.bintray\.com"
                r"|dl\.google\.com"
                r"|repo\.spring\.io"
                r"|oss\.sonatype\.org"
                r"|s01\.oss\.sonatype\.org"
                r")[^'\"\s)]+)['\"]",
                re.IGNORECASE | re.DOTALL,
            ),
            severity=Severity.MEDIUM,
            description_template="Non-standard Gradle repository: {dep}",
            category=Category.BUILD_EXTERNAL,
            file_types=["build"],
            multiline=True,
        ))

        self.add_rule(PatternRule(
            pattern_id="gradle-maven-local-repo",
            regex=re.compile(r"\bmavenLocal\s*\(\s*\)", re.IGNORECASE),
            severity=Severity.LOW,
            description_template="Gradle resolves dependencies from local Maven cache: {dep}",
            category=Category.BUILD_EXTERNAL,
            file_types=["build"],
        ))

        self.add_rule(PatternRule(
            pattern_id="gradle-flatdir-repo",
            regex=re.compile(
                r"\bflatDir\s*\{\s*(?P<dep>[^}\n]+)\s*\}",
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="Gradle flatDir local repository for vendored artifacts: {dep}",
            category=Category.BUILD_EXTERNAL,
            file_types=["build"],
        ))

        self.add_rule(PatternRule(
            pattern_id="gradle-local-file-dependency",
            regex=re.compile(
                r"\b(?:api|classpath|compileOnly|implementation|runtimeOnly|testImplementation)\s+"
                r"(?P<dep>(?:files|fileTree)\([^\n)]+\))",
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="Gradle dependency references local artifact files: {dep}",
            category=Category.BUILD_EXTERNAL,
            file_types=["build"],
        ))

        # Helm chart dependencies from non-standard repositories
        self.add_rule(PatternRule(
            pattern_id="helm-external-repo",
            regex=re.compile(
                r"repository:\s*['\"]?(?P<dep>https?://(?!"
                r"charts\.helm\.sh"
                r"|kubernetes-charts\.storage\.googleapis\.com"
                r"|charts\.bitnami\.com"
                r")\S+)['\"]?",
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="Helm chart dependency from external/untrusted repository: {dep}",
            category=Category.BUILD_EXTERNAL,
            file_types=["k8s", "build"],
        ))

        # Terraform providers from non-standard registries
        self.add_rule(PatternRule(
            pattern_id="terraform-non-standard-provider",
            regex=re.compile(
                r"source\s*=\s*['\"](?P<dep>(?!registry\.terraform\.io/)(?!hashicorp/)(?!\.{1,2}/)(?!/)[\w.-]+/[\w.-]+(?:/[\w.-]+)?)['\"]",
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="Terraform provider from non-standard registry: {dep}",
            category=Category.BUILD_EXTERNAL,
            file_types=["iac"],
        ))

        # Terraform module from git or http source
        self.add_rule(PatternRule(
            pattern_id="terraform-remote-module",
            regex=re.compile(
                r"source\s*=\s*['\"](?P<dep>(?:git::|https?://|git@)\S+)['\"]",
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="Terraform module loaded from remote source: {dep}",
            category=Category.BUILD_EXTERNAL,
            file_types=["iac"],
        ))

        # package.json scripts section running curl/wget/npx inline
        self.add_rule(PatternRule(
            pattern_id="npm-script-download",
            regex=re.compile(
                r"['\"](?:postinstall|preinstall|install|prepare)['\"]:\s*['\"][^'\"]*(?:curl|wget)\s+[^\n]*?(?P<dep>https?://\S+?)['\"]",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="npm lifecycle script downloads from URL: {dep}",
            category=Category.BUILD_EXTERNAL,
            file_types=["package_config"],
        ))

        # --- CMake FetchContent / ExternalProject_Add ---

        self.add_rule(PatternRule(
            pattern_id="cmake-fetchcontent",
            regex=re.compile(
                r'FetchContent_Declare\s*\([^)]*?(?:GIT_REPOSITORY|URL)\s+[\'"]?(?P<dep>https?://[^\s)\'"]+|git@[^\s)\'"]+)',
                re.DOTALL | re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="CMake FetchContent pulls external dependency: {dep}",
            category=Category.BUILD_EXTERNAL,
            file_types=["build"],
            multiline=True,
        ))

        self.add_rule(PatternRule(
            pattern_id="cmake-external-project",
            regex=re.compile(
                r'ExternalProject_Add\s*\([^)]*?(?:GIT_REPOSITORY|URL)\s+[\'"]?(?P<dep>https?://[^\s)\'"]+|git@[^\s)\'"]+)',
                re.DOTALL | re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="CMake ExternalProject_Add pulls external dependency: {dep}",
            category=Category.BUILD_EXTERNAL,
            file_types=["build"],
            multiline=True,
        ))

        # --- Gradle/Maven wrapper distributionUrl ---

        self.add_rule(PatternRule(
            pattern_id="gradle-wrapper-url",
            regex=re.compile(
                r"distributionUrl\s*=\s*(?P<dep>\S+)",
            ),
            severity=Severity.MEDIUM,
            description_template="Gradle wrapper downloads distribution from: {dep}",
            category=Category.BUILD_EXTERNAL,
            file_types=["build_wrapper"],
        ))

        self.add_rule(PatternRule(
            pattern_id="maven-wrapper-url",
            regex=re.compile(
                r"wrapperUrl\s*=\s*(?P<dep>\S+)",
            ),
            severity=Severity.MEDIUM,
            description_template="Maven wrapper downloads distribution from: {dep}",
            category=Category.BUILD_EXTERNAL,
            file_types=["build_wrapper"],
        ))

        # --- Language manifest git dependencies ---

        # Cargo.toml [patch] or [dependencies] with git
        self.add_rule(PatternRule(
            pattern_id="cargo-git-dependency",
            regex=re.compile(
                r'git\s*=\s*"(?P<dep>https?://\S+|git@\S+)"',
            ),
            severity=Severity.MEDIUM,
            description_template="Cargo.toml dependency from git source: {dep}",
            category=Category.GIT_DEPENDENCY,
            file_types=["package_config"],
        ))

        # go.mod replace directives — single-line form: replace mod => replacement version
        self.add_rule(PatternRule(
            pattern_id="gomod-replace-directive",
            regex=re.compile(
                r"^\s*(?:replace\s+)?\S+\s+=>\s+(?P<dep>[\w][\w.-]*\.[\w.-]+/\S+)",
                re.MULTILINE,
            ),
            severity=Severity.MEDIUM,
            description_template="go.mod replace points to external module: {dep}",
            category=Category.GIT_DEPENDENCY,
            file_types=["package_config"],
        ))

        # Gemfile git sources
        self.add_rule(PatternRule(
            pattern_id="gemfile-git-source",
            regex=re.compile(
                r"gem\s+['\"][\w-]+['\"][^,\n]*,\s*git:\s*['\"](?P<dep>[^'\"]+)['\"]",
            ),
            severity=Severity.MEDIUM,
            description_template="Gemfile dependency from git source: {dep}",
            category=Category.GIT_DEPENDENCY,
            file_types=["package_config"],
        ))

        # Package.swift .package(url: ...)
        self.add_rule(PatternRule(
            pattern_id="swift-package-url",
            regex=re.compile(
                r'\.package\s*\(\s*url:\s*"(?P<dep>[^"]+)"',
            ),
            severity=Severity.MEDIUM,
            description_template="Swift Package Manager dependency from URL: {dep}",
            category=Category.GIT_DEPENDENCY,
            file_types=["package_config"],
        ))

        # composer.json repositories with type=vcs or url
        self.add_rule(PatternRule(
            pattern_id="composer-vcs-repo",
            regex=re.compile(
                r'"url"\s*:\s*"(?P<dep>(?:https?://|git@)\S+?)"[^}]*?"type"\s*:\s*"(?:vcs|git)"',
                re.DOTALL,
            ),
            severity=Severity.MEDIUM,
            description_template="Composer VCS repository: {dep}",
            category=Category.GIT_DEPENDENCY,
            file_types=["package_config"],
            multiline=True,
        ))

        # --- package.json git/URL dependencies ---

        self.add_rule(PatternRule(
            pattern_id="npm-git-dependency",
            # Require an EXPLICIT git/github protocol prefix. Plain `https://`
            # was matching every package.json's `repository.url`, `homepage`,
            # `bugs.url`, JSON `$schema`, etc. — pure metadata, not a dep.
            # The `github:` shorthand requires `user/repo` (must contain `/`)
            # — without the slash it matches things like `"github:login"`
            # which are VSCode command IDs / context keys, not npm refs.
            regex=re.compile(
                r'"[\w@/.-]+"\s*:\s*"(?P<dep>'
                r'(?:git\+https?://|git\+ssh://|git://)\S+?'
                r'|github:[\w.-]+/[\w.+/#-]+'
                r')"',
            ),
            severity=Severity.MEDIUM,
            description_template="npm dependency from git/URL source: {dep}",
            category=Category.GIT_DEPENDENCY,
            file_types=["package_config"],
        ))

        self.add_rule(PatternRule(
            pattern_id="npm-resolution-override",
            regex=re.compile(
                r'"(?:resolutions|overrides)"[^}]*?"[\w@/.-]+"\s*:\s*"(?P<dep>(?:git\+https?://|github:|https?://)\S+?)"',
                re.DOTALL,
            ),
            severity=Severity.MEDIUM,
            description_template="npm resolution/override points to URL: {dep}",
            category=Category.GIT_DEPENDENCY,
            file_types=["package_config"],
            multiline=True,
        ))

        # SwiftPM binary targets (remote XCFramework download)
        self.add_rule(PatternRule(
            pattern_id="swift-binary-target",
            regex=re.compile(
                r'\.binaryTarget\s*\([^)]*?url:\s*"(?P<dep>https?://[^"]+)"',
                re.DOTALL,
            ),
            severity=Severity.HIGH,
            description_template="SwiftPM binary target downloads remote framework: {dep}",
            category=Category.BINARY_DOWNLOAD,
            file_types=["package_config"],
            multiline=True,
        ))

        # --- Kustomize remote resources ---

        self.add_rule(PatternRule(
            pattern_id="kustomize-remote-resource",
            regex=re.compile(
                r"resources:\s*\n(?:\s+-\s+[^\n]*\n)*?\s+-\s+(?P<dep>(?:https?://|github\.com/)\S+)",
                re.MULTILINE,
            ),
            severity=Severity.MEDIUM,
            description_template="Kustomize references remote resource: {dep}",
            category=Category.BUILD_EXTERNAL,
            file_types=["k8s"],
            multiline=True,
        ))

        # --- Ansible Galaxy ---

        self.add_rule(PatternRule(
            pattern_id="ansible-galaxy-role",
            regex=re.compile(
                r"roles:\s*\n(?:\s+-[^\n]*\n)*?\s+-?\s*src:\s*(?P<dep>\S+)",
                re.MULTILINE,
            ),
            severity=Severity.MEDIUM,
            description_template="Ansible Galaxy role from external source: {dep}",
            category=Category.BUILD_EXTERNAL,
            file_types=["k8s"],
            multiline=True,
        ))

        self.add_rule(PatternRule(
            pattern_id="ansible-galaxy-collection",
            regex=re.compile(
                r"collections:\s*\n(?:\s+-[^\n]*\n)*?\s+-?\s*name:\s*(?P<dep>\S+)",
                re.MULTILINE,
            ),
            severity=Severity.MEDIUM,
            description_template="Ansible Galaxy collection: {dep}",
            category=Category.BUILD_EXTERNAL,
            file_types=["k8s"],
            multiline=True,
        ))

        # --- Meson wrap files ---

        self.add_rule(PatternRule(
            pattern_id="meson-wrap-source-url",
            regex=re.compile(
                r"source_url\s*=\s*(?P<dep>https?://\S+)",
            ),
            severity=Severity.MEDIUM,
            description_template="Meson wrap downloads source from URL: {dep}",
            category=Category.BUILD_EXTERNAL,
            file_types=["meson_wrap"],
        ))

        self.add_rule(PatternRule(
            pattern_id="meson-wrap-patch-url",
            regex=re.compile(
                r"patch_url\s*=\s*(?P<dep>https?://\S+)",
            ),
            severity=Severity.MEDIUM,
            description_template="Meson wrap downloads patch from URL: {dep}",
            category=Category.BUILD_EXTERNAL,
            file_types=["meson_wrap"],
        ))

        # --- Gradle plugin management / buildscript custom repos ---

        self.add_rule(PatternRule(
            pattern_id="gradle-plugin-management-repo",
            regex=re.compile(
                r"pluginManagement\s*\{[^}]*?maven\s*\{[^}]*?url\s*[=\s]\s*['\"](?P<dep>https?://\S+?)['\"]",
                re.DOTALL,
            ),
            severity=Severity.MEDIUM,
            description_template="Gradle pluginManagement uses non-standard repository: {dep}",
            category=Category.BUILD_EXTERNAL,
            file_types=["build"],
            multiline=True,
        ))

        self.add_rule(PatternRule(
            pattern_id="gradle-buildscript-repo",
            regex=re.compile(
                r"buildscript\s*\{[^}]*?maven\s*\{[^}]*?url\s*[=\s]\s*['\"](?P<dep>https?://\S+?)['\"]",
                re.DOTALL,
            ),
            severity=Severity.MEDIUM,
            description_template="Gradle buildscript uses non-standard repository: {dep}",
            category=Category.BUILD_EXTERNAL,
            file_types=["build"],
            multiline=True,
        ))

        self.add_rule(PatternRule(
            pattern_id="gradle-included-build",
            regex=re.compile(
                r'includeBuild\s*\(\s*["\'](?P<dep>[^"\']+)["\']',
            ),
            severity=Severity.LOW,
            description_template="Gradle composite build includes external project: {dep}",
            category=Category.BUILD_EXTERNAL,
            file_types=["build"],
        ))


def _package_json_git_dependency_values(content: str) -> set[str]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return set()
    if not isinstance(data, dict):
        return set()

    values: set[str] = set()
    for section in (
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
        "overrides",
        "resolutions",
    ):
        _collect_git_dependency_values(data.get(section), values)
    return values


def _normalize_wrapper_url_findings(target: FileTarget, findings: list[Finding]) -> None:
    for finding in findings:
        if finding.pattern_id in {"gradle-wrapper-url", "maven-wrapper-url"}:
            finding.extracted_dep = _normalize_properties_url(finding.extracted_dep)
        if finding.pattern_id != "gradle-wrapper-url":
            continue
        finding.description = f"Gradle wrapper downloads distribution from: {finding.extracted_dep}"
        if target.path.name != "maven-wrapper.properties":
            continue
        finding.pattern_id = "maven-wrapper-url"
        finding.description = f"Maven wrapper downloads distribution from: {finding.extracted_dep}"


def _normalize_properties_url(value: str) -> str:
    return value.replace(r"\:", ":")


def _maven_url_is_repository_source(content: str, line_number: int) -> bool:
    lines = content.splitlines()
    prefix = "\n".join(lines[:line_number])
    repo_start = max(
        prefix.rfind("<repositories"),
        prefix.rfind("<pluginRepositories"),
    )
    repo_end = max(
        prefix.rfind("</repositories>"),
        prefix.rfind("</pluginRepositories>"),
    )
    return repo_start > repo_end


def _pom_xml_url_assignment_is_namespace(lines: list[str], finding: Finding) -> bool:
    if finding.pattern_id != "url-variable-assignment":
        return False
    if not 0 < finding.line_number <= len(lines):
        return False
    line = lines[finding.line_number - 1].lstrip()
    return line.startswith(("xmlns=", "xmlns:", "xsi:"))


def _gradle_url_assignment_is_metadata(lines: list[str], line_number: int) -> bool:
    if not 0 < line_number <= len(lines):
        return False
    target_line = lines[line_number - 1]
    if not re.match(r"\s*url\s*[:?]?=", target_line, re.IGNORECASE):
        return False

    metadata_blocks = {"pom", "licenses", "license", "scm", "developers", "developer", "organization"}
    stack: list[str] = []
    for current_number, raw_line in enumerate(lines[:line_number], start=1):
        line = re.split(r"//", raw_line, maxsplit=1)[0]
        if current_number == line_number:
            return bool(metadata_blocks & set(stack))

        closes = line.count("}")
        if closes:
            stack = stack[: max(0, len(stack) - closes)]
        for match in re.finditer(r"\b([A-Za-z_][\w.-]*)\s*(?:\([^{}]*\))?\s*\{", line):
            stack.append(match.group(1).lower())
    return False


def _is_non_artifact_makefile_download(finding: Finding) -> bool:
    dep = finding.extracted_dep.rstrip("\"'`")
    return (
        finding.pattern_id == "makefile-download"
        and bool(_JSON_API_URL_RE.match(dep) or _LOCALHOST_URL_RE.match(dep))
    )


def _is_standard_gradle_repository(finding: Finding) -> bool:
    if finding.pattern_id not in _GRADLE_REPOSITORY_PATTERN_IDS:
        return False
    dep = finding.extracted_dep.rstrip("/\"'`")
    match = re.match(r"https?://([^/:?#]+)", dep, re.IGNORECASE)
    if not match:
        return False
    return match.group(1).lower() in _STANDARD_GRADLE_REPOSITORY_HOSTS


def _is_placeholder_external_dep_in_test_fixture_path(target: FileTarget, finding: Finding) -> bool:
    if target.file_type != "build" or finding.pattern_id not in _CMAKE_EXTERNAL_PATTERN_IDS:
        return False
    path = "/" + target.rel_path.replace("\\", "/").lower()
    if not any(segment in path for segment in _TEST_FIXTURE_PATH_SEGMENTS):
        return False
    return bool(_PLACEHOLDER_TEST_FIXTURE_EXTERNAL_DEP_RE.match(finding.extracted_dep))


def _is_test_fixture_wrapper_download(target: FileTarget, finding: Finding) -> bool:
    if target.file_type != "build_wrapper" or finding.pattern_id not in {"gradle-wrapper-url", "maven-wrapper-url"}:
        return False
    parts = {part.lower() for part in target.rel_path.replace("\\", "/").split("/") if part}
    return bool(parts & {"test-fixtures", "test-resources"})


def _collect_git_dependency_values(value, out: set[str]) -> None:
    if isinstance(value, str):
        if _is_npm_git_dependency_spec(value):
            out.add(value)
        return
    if isinstance(value, dict):
        for nested in value.values():
            _collect_git_dependency_values(nested, out)


def _is_npm_git_dependency_spec(value: str) -> bool:
    return bool(re.match(r"(?:git\+https?://|git\+ssh://|git://|github:[\w.-]+/)", value))
