import pytest

from posture.images import (
    has_mutable_tag,
    identify_image,
    mirror_target,
    normalize_image_id,
    parse_image_ref,
    rewrite_registry,
)

D = "sha256:" + "a" * 64


@pytest.mark.parametrize("ref,registry,repo,tag,digest", [
    ("alpine", "docker.io", "library/alpine", None, None),
    ("alpine:3.20", "docker.io", "library/alpine", "3.20", None),
    ("postgres:16-alpine", "docker.io", "library/postgres", "16-alpine", None),
    ("rayproject/ray:2.56.0", "docker.io", "rayproject/ray", "2.56.0", None),
    ("docker.io/library/alpine:3.20", "docker.io", "library/alpine", "3.20", None),
    ("registry-1.docker.io/bitnami/postgresql:latest", "docker.io", "bitnami/postgresql", "latest", None),
    ("localhost:32000/checkmaite-api:2.56.0-r1", "localhost:32000", "checkmaite-api", "2.56.0-r1", None),
    ("quay.io/jetstack/cert-manager-controller:v1.16.2", "quay.io", "jetstack/cert-manager-controller", "v1.16.2", None),
    (f"ghcr.io/org/app:1.0@{D}", "ghcr.io", "org/app", "1.0", D),
    (f"registry.k8s.io/pause@{D}", "registry.k8s.io", "pause", None, D),
    ("artifacts.100-89-230-107.sslip.io/ray/ray-polars:2.56.0", "artifacts.100-89-230-107.sslip.io", "ray/ray-polars",
     "2.56.0", None),
    ("registry.local:5000/a/b/c", "registry.local:5000", "a/b/c", None, None),
])
def test_parse(ref, registry, repo, tag, digest):
    r = parse_image_ref(ref)
    assert (r.registry, r.repository, r.tag, r.digest) == (registry, repo, tag, digest)


@pytest.mark.parametrize("bad", ["", "UPPER/Case:1", "alpine@sha256:xyz"])
def test_parse_invalid(bad):
    with pytest.raises(ValueError):
        parse_image_ref(bad)


@pytest.mark.parametrize("image_id,expected", [
    (f"docker.io/library/alpine@{D}", (f"docker.io/library/alpine@{D}", D)),
    (f"docker-pullable://alpine@{D}", (f"docker.io/library/alpine@{D}", D)),
    (f"localhost:32000/checkmaite-api@{D}", (f"localhost:32000/checkmaite-api@{D}", D)),
    (D, (None, D)),
    ("", (None, None)),
    (None, (None, None)),
    ("garbage", (None, None)),
])
def test_normalize_image_id(image_id, expected):
    assert normalize_image_id(image_id) == expected


def test_identify_prefers_imageid_digest_keeps_spec_tag():
    i = identify_image("postgres:16-alpine", f"docker.io/library/postgres@{D}")
    assert i.key == f"docker.io/library/postgres@{D}"
    assert i.ref.tag == "16-alpine"
    assert i.ref.display == "docker.io/library/postgres:16-alpine"


def test_identify_local_config_id_falls_back_to_tag_with_warning():
    i = identify_image("docker.io/rayproject/ray:2.56.0", D)
    assert i.key == "docker.io/rayproject/ray:2.56.0"
    assert i.ref.digest is None
    assert i.warnings and "locally loaded" in i.warnings[0]


def test_identify_without_imageid():
    i = identify_image("dependencytrack/apiserver:4.11.4", None)
    assert i.key == "docker.io/dependencytrack/apiserver:4.11.4"


def test_rewrite_and_mirror_target():
    ref = parse_image_ref(f"localhost:32000/checkmaite-api@{D}")
    rw = rewrite_registry(ref, {"localhost:32000": "registry.container-registry.svc.cluster.local:5000"})
    assert rw.registry == "registry.container-registry.svc.cluster.local:5000"
    assert rw.pullable == f"registry.container-registry.svc.cluster.local:5000/checkmaite-api@{D}"
    t = mirror_target(parse_image_ref(f"docker.io/library/alpine@{D}"), "mirror:5000")
    assert t == f"mirror:5000/posture-mirror/docker.io/library/alpine:sha256-{'a' * 64}"


@pytest.mark.parametrize("image,mutable", [
    ("alpine", True), ("alpine:latest", True), ("alpine:3.20", False), (f"alpine@{D}", False),
    (f"alpine:latest@{D}", False),
])
def test_mutable_tag(image, mutable):
    assert has_mutable_tag(image) is mutable
