from datetime import datetime, timedelta, timezone

import pytest

from image_scanner.config import parse_config
from image_scanner.models import ImageFilter


# --- filters ---------------------------------------------------------------- #
def test_filter_tag_globs():
    f = ImageFilter(include_tags=["prod-*", "latest"], exclude_tags=["*-debug"])
    assert f.tag_allowed("prod-2026")
    assert f.tag_allowed("latest")
    assert not f.tag_allowed("dev-1")
    assert not f.tag_allowed("prod-debug")


def test_filter_repository_globs():
    f = ImageFilter(repositories=["acme/*"])
    assert f.repository_allowed("acme/api")
    assert not f.repository_allowed("other/api")


def test_within_push_window_relative():
    f = ImageFilter(pushed_within_days=30)
    recent = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
    old = (datetime.now(timezone.utc) - timedelta(days=100)).isoformat()
    assert f.within_push_window(recent)
    assert not f.within_push_window(old)
    assert f.within_push_window("")  # no timestamp -> not excluded


# --- config schema ---------------------------------------------------------- #
def test_registry_and_service_schema():
    cfg = parse_config(
        {
            "version": 2,
            "defaults": {"scan": {"tag_status": "tagged"}},
            "registries": [
                {
                    "name": "ghcr",
                    "type": "ghcr",
                    "connection": {"owner": "acme", "auth": {"provider": "env", "token_env": "GH"}},
                    "scan": {"projects": ["acme"], "repositories": ["acme/*"], "max_images": 10, "latest_versions": 2},
                },
                {"name": "hub", "type": "docker_hub", "connection": {"namespaces": ["acme"]}},
                {"name": "harbor", "type": "harbor", "connection": {"url": "https://harbor.acme.io/"}},
                {"name": "ecr", "type": "ecr", "connection": {"aws_auth": {"profile": "p", "regions": ["us-east-1"]}}},
            ],
            "services": [
                {"name": "eks", "type": "aws_eks", "connection": {"aws_auth": {"region": "us-east-1"}}},
                {"name": "k8s", "type": "k8s", "connection": {"contexts": ["*"]}},
            ],
        }
    )

    ghcr = cfg.source("ghcr")
    assert ghcr.category == "registry"
    assert ghcr.type == "ghcr"
    assert ghcr.connection["registry"] == "ghcr.io"  # implicit
    assert ghcr.filters.projects == ["acme"]
    assert ghcr.filters.repositories == ["acme/*"]
    assert ghcr.filters.max_images == 10
    assert ghcr.filters.max_images_per_repo == 2  # latest_versions alias

    hub = cfg.source("hub")
    assert hub.type == "dockerhub"
    assert hub.filters.max_images_per_repo == 1  # registry default: latest version
    assert hub.filters.tag_status == "tagged"    # inherited default

    harbor = cfg.source("harbor")
    assert harbor.connection["url"] == "https://harbor.acme.io"  # normalized (no trailing slash)
    assert harbor.connection["registry"] == "harbor.acme.io"

    ecr = cfg.source("ecr")
    assert ecr.aws_session is not None
    assert ecr.aws_session.region_list() == ["us-east-1"]

    eks = cfg.source("eks")
    assert eks.category == "service"
    assert eks.type == "eks"
    assert eks.aws_session is not None

    assert cfg.source("k8s").type == "kubernetes"


def test_unknown_registry_type_rejected():
    with pytest.raises(ValueError, match="unknown type"):
        parse_config({"registries": [{"name": "x", "type": "gcr", "connection": {}}]})


def test_unknown_service_type_rejected():
    with pytest.raises(ValueError, match="unknown type"):
        parse_config({"services": [{"name": "x", "type": "nomad", "connection": {}}]})


def test_duplicate_names_rejected():
    with pytest.raises(ValueError, match="duplicate"):
        parse_config(
            {
                "registries": [{"name": "dup", "type": "dockerhub", "connection": {"namespaces": ["a"]}}],
                "services": [{"name": "dup", "type": "kubernetes", "connection": {}}],
            }
        )


def test_harbor_requires_url():
    with pytest.raises(ValueError, match="connection.url"):
        parse_config({"registries": [{"name": "h", "type": "harbor", "connection": {}}]})
