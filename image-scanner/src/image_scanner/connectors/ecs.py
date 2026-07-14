"""AWS ECS service connector.

ECS is an orchestrator like Kubernetes (not a registry walk): it enumerates
running tasks and reads the container images they are actually running.

Official command chain (2026, CLI auto-paginates):

* ``aws ecs list-clusters`` — cluster ARNs per region;
* ``aws ecs list-tasks --cluster C --desired-status RUNNING`` — running task ARNs;
* ``aws ecs describe-tasks --cluster C --tasks ...`` (<=100/call) ->
  ``containers[].image`` (+ resolved ``containers[].imageDigest``).

Authentication to AWS comes from the source's
:class:`~image_scanner.auth.aws.AwsSession`; pulls fall back to the configured
registries via the :class:`~image_scanner.auth.index.RegistryAuthIndex`, with
this session as the ECR fallback (ECS images are almost always ECR).

Config::

    - name: ecs-prod
      type: ecs
      connection:
        aws_auth: { profile: prod, regions: [us-east-1] }
        clusters: ["*"]
"""
from __future__ import annotations

import fnmatch
from typing import Iterable

from ..auth.aws import AwsSession
from ..models import ImageTarget
from .base import ConnectorError, ServiceConnector

from k8s_cartographer.image_ref import parse_image_reference

_DESCRIBE_BATCH = 100


def _chunked(items: list, size: int) -> Iterable[list]:
    for i in range(0, len(items), size):
        yield items[i: i + size]


class EcsConnector(ServiceConnector):
    type = "ecs"

    def __init__(self, source, index=None, aws_session: AwsSession | None = None):
        super().__init__(source, index=index)
        self.session = aws_session or getattr(source, "aws_session", None) or AwsSession.from_config(
            self.connection.get("aws_auth")
        )
        self.aws_session = self.session
        clusters = self.connection.get("clusters")
        if isinstance(clusters, str):
            clusters = [clusters]
        self.cluster_globs = list(clusters or ["*"])

    @staticmethod
    def _cluster_name(arn: str) -> str:
        return arn.rsplit("/", 1)[-1] if "/" in arn else arn

    def _clusters(self, region: str) -> list[str]:
        data = self.session.run_json(["ecs", "list-clusters"], region=region)
        arns = data.get("clusterArns", []) if isinstance(data, dict) else []
        return [a for a in arns if any(fnmatch.fnmatch(self._cluster_name(a), g) for g in self.cluster_globs)]

    def _running_task_arns(self, cluster: str, region: str) -> list[str]:
        data = self.session.run_json(
            ["ecs", "list-tasks", "--cluster", cluster, "--desired-status", "RUNNING"], region=region
        )
        return data.get("taskArns", []) if isinstance(data, dict) else []

    def _describe_tasks(self, cluster: str, region: str, task_arns: list[str]) -> list[dict]:
        tasks: list[dict] = []
        for batch in _chunked(task_arns, _DESCRIBE_BATCH):
            data = self.session.run_json(
                ["ecs", "describe-tasks", "--cluster", cluster, "--tasks", *batch], region=region
            )
            tasks.extend(data.get("tasks", []) if isinstance(data, dict) else [])
        return tasks

    def connect(self) -> None:
        if not self.session.region_list():
            raise ConnectorError(
                f"source '{self.name}': ECS requires aws_auth.region(s) to enumerate clusters"
            )

    def discover_images(self) -> Iterable[ImageTarget]:
        regions = self.session.region_list()
        if not regions:
            raise ConnectorError(
                f"source '{self.name}': ECS requires aws_auth.region(s) to enumerate clusters"
            )
        seen: set[str] = set()
        for region in regions:
            for cluster_arn in self._clusters(region):
                cluster = self._cluster_name(cluster_arn)
                task_arns = self._running_task_arns(cluster_arn, region)
                if not task_arns:
                    continue
                for task in self._describe_tasks(cluster_arn, region, task_arns):
                    task_def = task.get("taskDefinitionArn", "")
                    for container in task.get("containers", []):
                        target = self._target(container, cluster, region, task_def)
                        if target is None or target.reference in seen:
                            continue
                        seen.add(target.reference)
                        yield target

    def _target(self, container: dict, cluster: str, region: str, task_def: str) -> ImageTarget | None:
        image = container.get("image", "") or ""
        if not image:
            return None
        ref = parse_image_reference(image)
        if ref.tag and not self.filters.tag_allowed(ref.tag):
            return None
        if not self.filters.repository_allowed(ref.repository):
            return None
        digest = ref.digest or (container.get("imageDigest", "") or "")
        reference = image if "@" in image or not digest else f"{image}@{digest}"
        return ImageTarget(
            reference=reference,
            registry=ref.registry,
            repository=ref.repository,
            tag=ref.tag,
            digest=digest,
            pushed_at="",
            source=self.name,
            discovered_via={
                "connector": "ecs",
                "cluster": cluster,
                "region": region,
                "task_definition": task_def,
                "container": container.get("name", ""),
                "registry_connection": self.index.describe(ref.registry, ref.repository),
            },
        )
