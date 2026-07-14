"""AWS ECR connector.

Enumerates repositories and images through the AWS CLI (no boto3), using the
shared :class:`~image_scanner.auth.aws.AwsSession` for credentials so IAM roles,
static keys, profiles, and the default chain all work identically:

* ``aws ecr describe-repositories`` — enumerate repos (CLI auto-paginates);
* ``aws ecr describe-images``       — list images with ``imagePushedAt``;
* pull token via ``AwsSession.ecr_auth`` (``aws ecr get-login-password``).

Config::

    - name: ecr-prod
      type: ecr
      connection:
        aws_auth: { profile: prod, regions: [us-east-1, eu-west-1] }
        account_id: "123456789012"     # optional; cross-account via --registry-id
      scan:
        repositories: ["payments/*"]
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable

from ..auth.aws import AwsSession
from ..models import ImageTarget, RegistryAuth
from .base import Connector, ConnectorError


def _normalize_timestamp(value: Any) -> str:
    if value in (None, ""):
        return ""
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc).replace(microsecond=0).isoformat()
    return str(value)


class EcrConnector(Connector):
    type = "ecr"

    def __init__(self, source, aws_session: AwsSession | None = None):
        super().__init__(source)
        self.session = aws_session or getattr(source, "aws_session", None) or AwsSession.from_config(
            self.connection.get("aws_auth")
        )
        self.account_id = str(self.connection.get("account_id", "") or "")
        self.regions = self.session.region_list() or ["us-east-1"]

    def _registry_id_args(self) -> list[str]:
        return ["--registry-id", self.account_id] if self.account_id else []

    def connect(self) -> None:
        self.session.run_json(
            ["ecr", "describe-repositories", "--max-results", "1", *self._registry_id_args()],
            region=self.regions[0],
        )

    def _repositories(self, region: str) -> list[str]:
        explicit = [r for r in self.filters.repositories if "*" not in r and "?" not in r]
        if explicit and self.filters.repositories == explicit:
            return explicit[: self.filters.max_images] if self.filters.max_images else explicit
        data = self.session.run_json(
            ["ecr", "describe-repositories", *self._registry_id_args()], region=region
        )
        repos = [r.get("repositoryName", "") for r in data.get("repositories", [])]
        selected = [r for r in repos if r and self.filters.repository_allowed(r)]
        if self.filters.max_images:
            selected = selected[: self.filters.max_images]
        return selected

    def _describe_images(self, region: str, repository: str) -> list[dict[str, Any]]:
        args = ["ecr", "describe-images", "--repository-name", repository, *self._registry_id_args()]
        if self.filters.tag_status in ("tagged", "untagged"):
            args += ["--filter", f"tagStatus={self.filters.tag_status.upper()}"]
        data = self.session.run_json(args, region=region)
        details = data.get("imageDetails", [])
        details.sort(key=lambda d: _normalize_timestamp(d.get("imagePushedAt")), reverse=True)
        return details

    def discover_images(self) -> Iterable[ImageTarget]:
        for region in self.regions:
            for repository in self._repositories(region):
                count = 0
                for detail in self._describe_images(region, repository):
                    registry_id = detail.get("registryId", "") or self.account_id
                    registry = f"{registry_id}.dkr.ecr.{region}.amazonaws.com"
                    pushed_at = _normalize_timestamp(detail.get("imagePushedAt"))
                    if not self.filters.within_push_window(pushed_at):
                        continue
                    digest = detail.get("imageDigest", "")
                    tags = detail.get("imageTags") or [""]
                    allowed_tags = [t for t in tags if not t or self.filters.tag_allowed(t)]
                    if not allowed_tags:
                        continue
                    tag = next((t for t in allowed_tags if t), "")
                    reference = (
                        f"{registry}/{repository}@{digest}" if digest else f"{registry}/{repository}:{tag}"
                    )
                    yield ImageTarget(
                        reference=reference,
                        registry=registry,
                        repository=repository,
                        tag=tag,
                        digest=digest,
                        pushed_at=pushed_at,
                        source=self.name,
                        provider="aws_ecr",
                        discovered_via={"connector": "ecr", "region": region, "all_tags": tags},
                    )
                    count += 1
                    if self.filters.max_images_per_repo and count >= self.filters.max_images_per_repo:
                        break

    def registry_auth_for(self, target: ImageTarget) -> RegistryAuth | None:
        return self.session.ecr_auth(target.registry)
