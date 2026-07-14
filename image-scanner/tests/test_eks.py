import json
from pathlib import Path

from conftest import service_cfg

from image_scanner.auth.aws import AwsSession
from image_scanner.auth.index import RegistryAuthIndex
from image_scanner.connectors import build_connector
from image_scanner.connectors.eks import EksConnector
from image_scanner.config import parse_config
from k8s_cartographer.collector import collect_from_json_file

K8S_DUMP = Path(__file__).parent / "fixtures" / "cluster-dump.json"


def test_eks_offline_mode_uses_kubernetes_discovery():
    cfg = parse_config(
        {
            "version": 2,
            "services": [
                {
                    "name": "prod-eks",
                    "type": "eks",
                    "connection": {"from_json": str(K8S_DUMP), "cluster_name": "prod-eks-1"},
                    "discovery": {"object_kinds": ["CronJob"]},
                }
            ],
        }
    )
    conn = build_connector(cfg.source("prod-eks"), index=RegistryAuthIndex())
    assert isinstance(conn, EksConnector)
    targets = list(conn.discover_images())
    assert len(targets) == 1
    assert targets[0].discovered_via["connector"] == "eks"
    assert targets[0].discovered_via["cluster"] == "prod-eks-1"


def test_eks_aws_mode_lists_clusters_then_collects():
    def runner(cmd, env=None):
        if "list-clusters" in " ".join(cmd):
            return json.dumps({"clusters": ["prod-1", "staging-1"]})
        return "{}"

    session = AwsSession.from_config({"regions": ["us-east-1"]}, runner=runner)
    resources = collect_from_json_file(K8S_DUMP)
    source = service_cfg(
        "eks-prod", "eks", {"clusters": ["prod-*"]},
        discovery={"object_kinds": ["CronJob"]}, aws_session=session,
    )
    conn = EksConnector(
        source, index=RegistryAuthIndex(), aws_session=session,
        eks_collector=lambda cluster, region: resources,
    )
    targets = list(conn.discover_images())
    # Only the prod-* cluster is scanned (staging filtered out).
    assert {t.discovered_via["cluster"] for t in targets} == {"prod-1"}
    assert targets[0].discovered_via["connector"] == "eks"
