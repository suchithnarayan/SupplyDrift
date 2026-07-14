"""AWS EKS service connector.

EKS is Kubernetes, but the clusters and their access are discovered through AWS:

* ``aws eks list-clusters`` — enumerate clusters in each configured region;
* ``aws eks update-kubeconfig --name C --region R [--role-arn ARN]`` — write a
  throwaway kubeconfig whose exec plugin calls ``aws eks get-token``;
* then the shared ``k8s_cartographer`` collector walks the workloads.

Authentication comes from the source's :class:`~image_scanner.auth.aws.AwsSession`
(``aws_auth`` block); pull credentials fall back to the configured registries via
the :class:`~image_scanner.auth.index.RegistryAuthIndex`, with this session as the
ECR fallback.

Config::

    - name: eks-prod
      type: eks
      connection:
        aws_auth: { profile: prod, regions: [us-east-1], role_arn: arn:aws:iam::123:role/Scanner }
        clusters: ["*"]              # default: all clusters in the region(s)
      discovery: { namespaces: ["*"] }
"""
from __future__ import annotations

import fnmatch
import tempfile
from typing import Callable, Iterable

from ..auth.aws import AwsSession
from ..models import ImageTarget
from .base import ConnectorError
from .kubernetes import KubernetesConnector

from k8s_cartographer import collector as k8s_collector

# (cluster_name, region) -> list of raw resource dicts
EksClusterCollector = Callable[[str, str], list]


class EksConnector(KubernetesConnector):
    type = "eks"

    def __init__(self, source, index=None, resources: list | None = None,
                 aws_session: AwsSession | None = None,
                 eks_collector: EksClusterCollector | None = None):
        super().__init__(source, index=index, resources=resources)
        self.session = aws_session or getattr(source, "aws_session", None) or AwsSession.from_config(
            self.connection.get("aws_auth")
        )
        # EKS resolves ECR pulls with its own AWS session when no registry matched.
        self.aws_session = self.session
        clusters = self.connection.get("clusters")
        if isinstance(clusters, str):
            clusters = [clusters]
        self.cluster_globs = list(clusters or ["*"])
        self._eks_collector = eks_collector

    def _clusters(self, region: str) -> list[str]:
        explicit = [c for c in self.cluster_globs if "*" not in c and "?" not in c]
        if explicit and self.cluster_globs == explicit:
            return explicit
        data = self.session.run_json(["eks", "list-clusters"], region=region)
        names = data.get("clusters", []) if isinstance(data, dict) else []
        return [c for c in names if any(fnmatch.fnmatch(c, g) for g in self.cluster_globs)]

    def _collect_eks_cluster(self, cluster: str, region: str) -> list:
        if self._eks_collector is not None:
            return self._eks_collector(cluster, region)
        with tempfile.NamedTemporaryFile(prefix="eks-kubeconfig-", suffix=".yaml") as tmp:
            kubeconfig = tmp.name
            args = ["eks", "update-kubeconfig", "--name", cluster, "--kubeconfig", kubeconfig]
            if self.session.role_arn:
                args += ["--role-arn", self.session.role_arn]
            self.session.run(args, region=region)
            return k8s_collector.collect_from_cluster(kubeconfig=kubeconfig, env=self.session.env() or None)

    def connect(self) -> None:
        offline = self._offline_resources()
        if offline is not None:
            return
        regions = self.session.region_list()
        if not regions:
            raise ConnectorError(
                f"source '{self.name}': EKS requires aws_auth.region(s) to enumerate clusters"
            )

    def discover_images(self) -> Iterable[ImageTarget]:
        offline = self._offline_resources()
        if offline is not None:
            cluster = self.connection.get("cluster_name") or self.name
            yield from self._emit(offline, cluster)
            return
        regions = self.session.region_list()
        if not regions:
            raise ConnectorError(
                f"source '{self.name}': EKS requires aws_auth.region(s) to enumerate clusters"
            )
        for region in regions:
            for cluster in self._clusters(region):
                resources = self._collect_eks_cluster(cluster, region)
                yield from self._emit(resources, cluster)
