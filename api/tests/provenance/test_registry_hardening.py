"""Security review H3: SSRF guards, realm allowlist, streamed body caps for HttpRegistry."""

from __future__ import annotations

import json

import httpx
import pytest

from posture.provenance import registry as regmod
from posture.provenance.registry import HttpRegistry, RegistryError

PUBLIC = {"reg.example.com": ["93.184.216.34"], "auth.example.com": ["93.184.216.35"],
          "cdn.example.net": ["93.184.216.36"], "auth.docker.io": ["3.3.3.3"],
          "registry-1.docker.io": ["3.3.3.4"], "evil.example.org": ["93.184.216.40"],
          "metadata.internal": ["169.254.169.254"], "internal.example.com": ["10.0.0.5"],
          "mirror.svc": ["10.152.183.10"], "loop.example.com": ["127.0.0.1"]}


async def resolver(host):
    if host not in PUBLIC:
        raise OSError("nxdomain")
    return PUBLIC[host]


def make(handler, **kw):
    return HttpRegistry(transport=httpx.MockTransport(handler), resolver=resolver, **kw)


MANIFEST = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "layers": []}


async def test_realm_on_foreign_host_is_refused():
    seen = []

    def handler(req):
        seen.append(str(req.url))
        if req.url.host == "reg.example.com":
            return httpx.Response(401, headers={"www-authenticate":
                                                'Bearer realm="https://evil.example.org/token",service="x"'})
        return httpx.Response(200, json={"token": "t"})

    async with make(handler) as r:
        with pytest.raises(RegistryError, match="realm"):
            await r.get_manifest("reg.example.com", "a/b", "1.0")
    assert not any("evil.example.org" in u for u in seen)


async def test_realm_on_private_address_is_refused_even_on_same_parent_domain():
    def handler(req):
        return httpx.Response(401, headers={"www-authenticate":
                                            'Bearer realm="https://internal.example.com/token"'})

    async with make(handler) as r:
        with pytest.raises(RegistryError, match="private"):
            await r.get_manifest("reg.example.com", "a/b", "1.0")


async def test_realm_same_parent_domain_and_docker_hub_allowed():
    def handler(req):
        if req.url.path.endswith("/token"):
            return httpx.Response(200, json={"token": "tok"})
        if req.headers.get("authorization") != "Bearer tok":
            return httpx.Response(401, headers={"www-authenticate":
                                                f'Bearer realm="https://{AUTH[req.url.host]}/token"'})
        return httpx.Response(200, json=MANIFEST, headers={"content-type": MANIFEST["mediaType"]})

    AUTH = {"reg.example.com": "auth.example.com", "registry-1.docker.io": "auth.docker.io"}
    async with make(handler) as r:
        assert (await r.get_manifest("reg.example.com", "a/b", "1.0")) is not None
        assert (await r.get_manifest("docker.io", "library/alpine", "3")) is not None


async def test_realm_allowlist_env(monkeypatch):
    monkeypatch.setenv("PROVENANCE_REGISTRY_AUTH_REALMS", "evil.example.org")
    assert "evil.example.org" in HttpRegistry().realm_hosts


async def test_redirect_to_link_local_is_refused():
    def handler(req):
        if req.url.host == "reg.example.com":
            return httpx.Response(307, headers={"location": "http://metadata.internal/latest/meta-data/"})
        raise AssertionError("followed a redirect to the metadata service")

    async with make(handler) as r:
        with pytest.raises(RegistryError):
            await r.get_manifest("reg.example.com", "a/b", "1.0")


@pytest.mark.parametrize("target", ["https://internal.example.com/x", "https://loop.example.com/x",
                                    "https://169.254.169.254/x", "https://[::1]/x", "file:///etc/passwd"])
async def test_redirect_to_private_ranges_refused(target):
    def handler(req):
        if req.url.host == "reg.example.com":
            return httpx.Response(302, headers={"location": target})
        raise AssertionError("redirect followed")

    async with make(handler) as r:
        with pytest.raises(RegistryError):
            await r.get_blob("reg.example.com", "a/b", "sha256:" + "a" * 64)


async def test_public_redirect_followed_without_authorization():
    seen = {}

    def handler(req):
        if req.url.host == "reg.example.com":
            return httpx.Response(307, headers={"location": "https://cdn.example.net/blob"})
        seen["auth"] = req.headers.get("authorization")
        return httpx.Response(200, content=b"blob")

    async with make(handler) as r:
        r._tokens[("reg.example.com", "repository:a/b:pull")] = "secret-token"
        assert await r.get_blob("reg.example.com", "a/b", "sha256:" + "a" * 64) == b"blob"
    assert seen["auth"] is None  # bearer not leaked to the CDN


async def test_initial_request_to_link_local_registry_refused():
    def handler(req):
        raise AssertionError("request sent")

    async with make(handler) as r:
        with pytest.raises(RegistryError, match="link-local"):
            await r.get_manifest("metadata.internal", "a", "1")


async def test_insecure_in_cluster_registry_may_be_private():
    def handler(req):
        return httpx.Response(200, json=MANIFEST)

    async with make(handler, insecure_hosts={"mirror.svc"}) as r:
        assert await r.get_manifest("mirror.svc", "a", "1") is not None


async def test_manifest_cap(monkeypatch):
    monkeypatch.setattr(regmod, "MAX_MANIFEST_BYTES", 1000)
    big = json.dumps({**MANIFEST, "pad": "x" * 5000}).encode()

    def handler(req):
        return httpx.Response(200, content=big)

    async with make(handler) as r:
        with pytest.raises(RegistryError, match="larger than"):
            await r.get_manifest("reg.example.com", "a", "1")


async def test_tag_list_cap_across_pages(monkeypatch):
    monkeypatch.setattr(regmod, "MAX_TAG_LIST_BYTES", 3000)
    pages = 0

    def handler(req):
        nonlocal pages
        pages += 1
        body = json.dumps({"tags": [f"v{pages}.{i}" for i in range(150)]}).encode()
        return httpx.Response(200, content=body, headers={"link": f'</v2/a/tags/list?last={pages}>; rel="next"'})

    async with make(handler) as r:
        with pytest.raises(RegistryError, match="larger than"):
            await r.list_tags("reg.example.com", "a")
    assert pages < 5


async def test_tag_next_page_on_other_host_refused():
    def handler(req):
        return httpx.Response(200, json={"tags": ["1"]}, headers={"link": '<https://evil.example.org/x>; rel="next"'})

    async with make(handler) as r:
        with pytest.raises(RegistryError, match="another host"):
            await r.list_tags("reg.example.com", "a")


async def test_blob_streams_and_truncates_at_cap(monkeypatch):
    monkeypatch.setattr(regmod, "MAX_ATTESTATION_BYTES", 2048)

    def handler(req):
        return httpx.Response(200, content=b"y" * 100_000)

    async with make(handler) as r:
        assert len(await r.get_blob("reg.example.com", "a", "sha256:" + "a" * 64, 10_000_000)) == 2048
        assert len(await r.get_blob("reg.example.com", "a", "sha256:" + "a" * 64, 100)) == 100


async def test_gzip_encoded_manifest_counts_decoded_bytes(monkeypatch):
    import gzip

    monkeypatch.setattr(regmod, "MAX_MANIFEST_BYTES", 10_000)
    bomb = gzip.compress(b"{" + b" " * 2_000_000 + b"}")

    def handler(req):
        return httpx.Response(200, content=bomb, headers={"content-encoding": "gzip"})

    async with make(handler) as r:
        with pytest.raises(RegistryError, match="larger than"):
            await r.get_manifest("reg.example.com", "a", "1")


async def test_token_response_not_json_is_registry_error():
    def handler(req):
        if req.url.host == "auth.example.com":
            return httpx.Response(200, text="<html>")
        return httpx.Response(401, headers={"www-authenticate": 'Bearer realm="https://auth.example.com/t"'})

    async with make(handler) as r:
        with pytest.raises(RegistryError, match="invalid JSON"):
            await r.get_manifest("reg.example.com", "a", "1")
