"""Tests for the ECS connector (running tasks -> images)."""
from __future__ import annotations

import json

from conftest import service_cfg

from image_scanner.auth.aws import AwsSession
from image_scanner.auth.index import RegistryAuthIndex
from image_scanner.connectors.ecs import EcsConnector

ECR_IMAGE = "123456789012.dkr.ecr.us-east-1.amazonaws.com/payments-api:prod"
ECR_DIGEST = "sha256:" + "a" * 64


def make_session():
    def runner(cmd, env=None):
        joined = " ".join(cmd)
        if "list-clusters" in joined:
            return json.dumps({"clusterArns": ["arn:aws:ecs:us-east-1:123:cluster/prod"]})
        if "list-tasks" in joined:
            return json.dumps({"taskArns": ["arn:aws:ecs:us-east-1:123:task/prod/abc"]})
        if "describe-tasks" in joined:
            return json.dumps(
                {"tasks": [{
                    "taskDefinitionArn": "arn:aws:ecs:us-east-1:123:task-definition/app:7",
                    "containers": [
                        {"name": "app", "image": ECR_IMAGE, "imageDigest": ECR_DIGEST},
                        {"name": "sidecar", "image": "docker.io/library/envoy:1.29"},
                    ],
                }]}
            )
        if "get-login-password" in joined:
            return "ecr-token\n"
        return "{}"

    return AwsSession.from_config({"regions": ["us-east-1"]}, runner=runner)


def make_connector():
    source = service_cfg("ecs-prod", "ecs", {"clusters": ["*"]}, aws_session=make_session())
    return EcsConnector(source, index=RegistryAuthIndex())


def test_ecs_discovers_running_task_images():
    conn = make_connector()
    targets = list(conn.discover_images())
    refs = {t.reference for t in targets}
    assert f"{ECR_IMAGE}@{ECR_DIGEST}" in refs           # resolved digest appended
    assert "docker.io/library/envoy:1.29" in refs
    ecr = next(t for t in targets if "ecr" in t.registry)
    assert ecr.repository == "payments-api" and ecr.digest == ECR_DIGEST
    assert ecr.discovered_via["connector"] == "ecs"
    assert ecr.discovered_via["cluster"] == "prod"


def test_ecs_pull_auth_falls_back_to_aws_session():
    conn = make_connector()
    ecr = next(t for t in conn.discover_images() if "ecr" in t.registry)
    auth = conn.registry_auth_for(ecr)
    assert auth is not None and auth.username == "AWS" and auth.password == "ecr-token"


def test_ecs_repository_filter():
    source = service_cfg("ecs-prod", "ecs", {"clusters": ["*"]}, aws_session=make_session(),
                         repositories=["payments-api"])
    conn = EcsConnector(source, index=RegistryAuthIndex())
    repos = {t.repository for t in conn.discover_images()}
    assert repos == {"payments-api"}  # envoy (library/envoy) filtered out
