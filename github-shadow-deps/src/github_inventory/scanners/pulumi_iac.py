"""
Pulumi IaC scanner — flags container images, helm charts, and external
modules referenced from Pulumi TypeScript / Python infrastructure code.

Pulumi programs build a stack via SDK calls like:
    new docker.Image("img", { context: ..., tags: ["foo:latest"] });
    new k8s.helm.v3.Chart("nginx", { chart: "nginx", repo: "https://..." });
    new aws.ecr.Repository(...);

These references are real shadow deps — the resulting infra pulls
external images at deploy time. Regex-anchored on the SDK constructor
shapes; restricted to source_code files in directories named `pulumi/`,
`infra/`, or `iac/` to keep FPs off application TS/Python code.
"""
from __future__ import annotations

import re

from github_inventory.discovery import FileTarget
from github_inventory.models import Category, Finding, Severity
from github_inventory.scanners.base import BaseScanner, PatternRule


_PULUMI_PATH_RE = re.compile(
    r"(?:^|/)(?:pulumi|infra|iac|deploy/pulumi|cdk|cdktf|aws-cdk|crossplane)(?:/|$)",
    re.IGNORECASE,
)


class PulumiIaCScanner(BaseScanner):
    name = "pulumi-iac"

    def register_rules(self) -> None:
        # docker.Image / dockerBuild.Image with mutable tag in `tags` array
        self.add_rule(PatternRule(
            pattern_id="pulumi-docker-image-mutable-tag",
            regex=re.compile(
                r'(?:docker|dockerBuild)\.Image\s*\([^)]*?'
                r'tags?\s*[:=]\s*\[?\s*[\'"`](?P<dep>[\w./-]+:'
                r'(?:latest|main|master|dev|develop|stable|edge|nightly|canary|next))[\'"`]',
                re.IGNORECASE | re.DOTALL,
            ),
            severity=Severity.HIGH,
            description_template="Pulumi docker.Image uses mutable tag: {dep}",
            category=Category.PULUMI_RESOURCE,
            file_types=["source_code"],
            multiline=True,
        ))

        # k8s.helm.v3.Chart / helm.v3.Chart with `chart:` + `repo:` (external)
        self.add_rule(PatternRule(
            pattern_id="pulumi-helm-chart-remote",
            regex=re.compile(
                r'(?:k8s\.)?helm\.v3\.Chart\s*\([^)]*?'
                r'repo\s*[:=]\s*[\'"](?P<dep>https?://[^\'"`]+)[\'"]',
                re.IGNORECASE | re.DOTALL,
            ),
            severity=Severity.MEDIUM,
            description_template="Pulumi installs Helm chart from remote repo: {dep}",
            category=Category.PULUMI_RESOURCE,
            file_types=["source_code"],
            multiline=True,
        ))

        # Hardcoded image string in Pulumi resource (e.g. `image: "mongo:7.0"`)
        self.add_rule(PatternRule(
            pattern_id="pulumi-image-literal",
            regex=re.compile(
                r"\bimage\s*[:=]\s*['\"`](?P<dep>[\w./-]+:[\w.-]+)['\"`]",
                re.IGNORECASE,
            ),
            severity=Severity.LOW,
            description_template="Pulumi resource references container image: {dep}",
            category=Category.PULUMI_RESOURCE,
            file_types=["source_code"],
        ))

        # AWS CDK: new ContainerImage.fromRegistry("nginx:latest")
        self.add_rule(PatternRule(
            pattern_id="cdk-container-image-mutable",
            regex=re.compile(
                r"ContainerImage\.fromRegistry\s*\(\s*['\"`]"
                r"(?P<dep>[\w./-]+:"
                r"(?:latest|main|master|dev|develop|stable|edge|nightly|canary|next))['\"`]",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="CDK ContainerImage.fromRegistry uses mutable tag: {dep}",
            category=Category.PULUMI_RESOURCE,
            file_types=["source_code"],
        ))
        # CDK: ecs.ContainerImage.fromAsset("./path") — local build, fine.
        # CDK: ecs.ContainerImage.fromEcrRepository(repo, "tag") — pinned by tag.
        # We only flag the mutable case above.

        # Crossplane: composition with `package: xpkg.upbound.io/...:vXYZ`.
        # Mutable tag inside `package:` field of a Crossplane resource.
        self.add_rule(PatternRule(
            pattern_id="crossplane-package-mutable",
            regex=re.compile(
                r"\bpackage\s*:\s*['\"]?(?P<dep>(?:xpkg\.[\w.-]+|registry\.[\w.-]+)/[\w./-]+:"
                r"(?:latest|main|master|stable|edge))['\"]?",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="Crossplane provider/configuration package on mutable tag: {dep}",
            category=Category.PULUMI_RESOURCE,
            file_types=["source_code", "k8s"],
        ))

    def scan_file_content(self, target: FileTarget, content: str, lines: list[str]) -> list[Finding]:
        # Restrict to known IaC directories — application source code is
        # never the intended target, and Pulumi-shaped patterns can FP
        # heavily there (e.g. unrelated `image:` properties on UI cards).
        if not _PULUMI_PATH_RE.search(target.rel_path):
            return []
        return super().scan_file_content(target, content, lines)
