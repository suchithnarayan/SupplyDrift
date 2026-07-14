from k8s_cartographer.image_ref import digest_from_image_id, parse_image_reference


def test_dockerhub_official_image_defaults():
    ref = parse_image_reference("busybox")
    assert ref.registry == "docker.io"
    assert ref.repository == "library/busybox"
    assert ref.tag == "latest"
    assert ref.digest == ""
    assert ref.mutable_tag is True
    assert ref.pinned is False


def test_dockerhub_namespaced_image():
    ref = parse_image_reference("acme/api:1.2.3")
    assert ref.registry == "docker.io"
    assert ref.repository == "acme/api"
    assert ref.tag == "1.2.3"
    assert ref.mutable_tag is False


def test_registry_with_port_is_not_a_tag():
    ref = parse_image_reference("localhost:5000/team/app:dev")
    assert ref.registry == "localhost:5000"
    assert ref.repository == "team/app"
    assert ref.tag == "dev"


def test_digest_pinned_is_immutable():
    ref = parse_image_reference("ghcr.io/acme/web:1.4.2@sha256:" + "a" * 64)
    assert ref.registry == "ghcr.io"
    assert ref.repository == "acme/web"
    assert ref.tag == "1.4.2"
    assert ref.digest == "sha256:" + "a" * 64
    assert ref.pinned is True
    assert ref.mutable_tag is False


def test_ecr_digest_only_reference():
    raw = "123456789012.dkr.ecr.us-east-1.amazonaws.com/payments-api@sha256:" + "9" * 64
    ref = parse_image_reference(raw)
    assert ref.registry == "123456789012.dkr.ecr.us-east-1.amazonaws.com"
    assert ref.repository == "payments-api"
    assert ref.pinned is True


def test_digest_from_image_id():
    assert digest_from_image_id("docker.io/library/busybox@sha256:" + "1" * 64) == "sha256:" + "1" * 64
    assert digest_from_image_id("sha256:" + "2" * 64) == "sha256:" + "2" * 64
    assert digest_from_image_id("") == ""
