from pathlib import Path

from conftest import registry_cfg

from image_scanner.auth.aws import AwsSession
from image_scanner.connectors.ecr import EcrConnector
from image_scanner.models import ImageTarget

FIXTURES = Path(__file__).parent / "fixtures"


def make_session():
    repos = (FIXTURES / "ecr_describe_repositories.json").read_text()
    images = (FIXTURES / "ecr_describe_images.json").read_text()

    def runner(cmd, env=None):
        joined = " ".join(cmd)
        if "describe-repositories" in joined:
            return repos
        if "describe-images" in joined:
            return images
        if "get-login-password" in joined:
            return "ecr-pull-token\n"
        return "{}"

    return AwsSession.from_config({"regions": ["us-east-1"]}, runner=runner)


def make_source(**filter_kwargs):
    return registry_cfg("prod-ecr", "ecr", {"account_id": "123456789012"}, **filter_kwargs)


def test_ecr_tag_exclude_and_max_per_repo():
    conn = EcrConnector(
        make_source(repositories=["payments-api"], include_tags=["*"], exclude_tags=["*-debug"], max_images_per_repo=2),
        aws_session=make_session(),
    )
    targets = list(conn.discover_images())
    assert len(targets) == 2
    assert targets[0].tag == "prod-2026-05-25"
    assert targets[1].tag == "prod-2026-04-01"
    assert targets[0].reference.endswith("@sha256:" + "a" * 64)
    assert targets[0].registry == "123456789012.dkr.ecr.us-east-1.amazonaws.com"
    assert targets[0].provider == "aws_ecr"


def test_ecr_repository_listing_when_glob():
    conn = EcrConnector(make_source(repositories=["*"]), aws_session=make_session())
    assert conn._repositories("us-east-1") == ["payments-api", "web"]


def test_ecr_pull_mints_token_via_session():
    conn = EcrConnector(make_source(), aws_session=make_session())
    target = ImageTarget(reference="r", registry="123456789012.dkr.ecr.us-east-1.amazonaws.com")
    auth = conn.registry_auth_for(target)
    assert auth is not None and auth.username == "AWS" and auth.password == "ecr-pull-token"
    assert auth.provider == "ecr"
