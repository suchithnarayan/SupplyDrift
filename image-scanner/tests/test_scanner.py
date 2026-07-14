from conftest import FakeExtractor

from image_scanner.core.scanner import (
    ImageScanner,
    build_platform_payload,
    provider_for,
    registry_type,
)
from image_scanner.models import ImageTarget


def test_registry_type_and_provider():
    assert registry_type("123456789012.dkr.ecr.us-east-1.amazonaws.com") == "ecr"
    assert registry_type("ghcr.io") == "ghcr"
    assert registry_type("docker.io") == "dockerhub"
    t = ImageTarget(reference="x", registry="123456789012.dkr.ecr.us-east-1.amazonaws.com")
    assert provider_for(t) == "aws_ecr"


def test_scan_and_payload_shape():
    scanner = ImageScanner(FakeExtractor())
    target = ImageTarget(
        reference="123456789012.dkr.ecr.us-east-1.amazonaws.com/payments-api@sha256:aa",
        registry="123456789012.dkr.ecr.us-east-1.amazonaws.com",
        repository="payments-api",
        tag="prod",
        digest="sha256:aa",
        pushed_at="2026-05-25T09:41:00+00:00",
        source="prod-ecr",
        source_id="connector-123",
    )
    result = scanner.scan(target)
    assert result.ok
    assert result.component_count == 1

    payload = build_platform_payload(result)
    # Compact normalized shape — extracted fields, no raw CycloneDX document.
    assert "cyclonedx" not in payload
    assert payload["connector"]["id"] == "connector-123"
    asset = payload["assets"][0]
    assert asset["asset_type"] == "container_image"
    assert asset["provider"] == "aws_ecr"
    assert asset["details"]["digest"] == "sha256:aa"
    assert asset["details"]["repository"] == "payments-api"
    assert asset["details"]["pushed_at"] == "2026-05-25T09:41:00+00:00"
    # Required fields present: ecosystem (from purl) AND package type (from syft).
    comp = payload["components"][0]
    assert comp["name"] == "openssl" and comp["version"] == "3.0.2"
    assert comp["purl"] == "pkg:deb/ubuntu/openssl@3.0.2"
    assert comp["ecosystem"] == "deb"
    assert comp["package_manager"] == "deb"
    assert payload["component_usages"][0]["evidence_path"] == "/var/lib/dpkg/status"
