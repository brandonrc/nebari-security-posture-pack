"""Helm release Secret decoding / latest-revision selection / chart update check."""

import base64
import gzip
import json

import httpx
import pytest

from posture.provenance import helm
from posture.provenance.helm import (
    ChartRepos,
    HelmDecodeError,
    HelmRelease,
    check_chart_updates,
    decode_release_payload,
    decode_secret,
    latest_release_secrets,
    releases_from_secrets,
)

from .fakes import FakeRegistry


def release(name="cert-manager", ns="cert-manager", rev=1, status="deployed", chart="cert-manager",
            version="v1.16.2", app="v1.16.2"):
    return {"name": name, "namespace": ns, "version": rev,
            "info": {"status": status, "last_deployed": "2026-08-23T10:01:15Z", "description": "Install complete"},
            "chart": {"metadata": {"name": chart, "version": version, "appVersion": app, "apiVersion": "v2"}},
            "config": {}, "manifest": "---\n", "hooks": []}


def secret(rel: dict, compress: bool = True, owner: str = "helm") -> dict:
    raw = json.dumps(rel).encode()
    if compress:
        raw = gzip.compress(raw)
    helm_b64 = base64.b64encode(raw)  # helm's own encoding
    k8s_b64 = base64.b64encode(helm_b64).decode()  # what the API returns in .data
    return {"metadata": {"name": f"sh.helm.release.v1.{rel['name']}.v{rel['version']}", "namespace": rel["namespace"],
                         "labels": {"owner": owner, "name": rel["name"], "status": rel["info"]["status"],
                                    "version": str(rel["version"])}},
            "type": "helm.sh/release.v1", "data": {"release": k8s_b64}}


def test_decode_gzip_and_plain_payloads():
    rel = release()
    assert decode_secret(secret(rel))["chart"]["metadata"]["version"] == "v1.16.2"
    assert decode_secret(secret(rel, compress=False))["name"] == "cert-manager"
    raw = base64.b64encode(gzip.compress(json.dumps(rel).encode()))
    assert decode_release_payload(raw)["namespace"] == "cert-manager"


@pytest.mark.parametrize("payload", [b"!!!notbase64", base64.b64encode(b"\x1f\x8b\x08garbage"),
                                     base64.b64encode(b"[1,2]"), base64.b64encode(b"{not json")])
def test_decode_errors(payload):
    with pytest.raises(HelmDecodeError):
        decode_release_payload(payload)


def test_decode_secret_without_release_key():
    with pytest.raises(HelmDecodeError):
        decode_secret({"data": {}})


def test_latest_revision_per_release_any_status():
    secrets = [secret(release(rev=r, status="superseded" if r < 3 else "failed")) for r in (1, 2, 3)]
    secrets += [secret(release("keycloak", "keycloak", rev=r)) for r in (9, 10)]  # 10 > 9 numerically
    secrets.append(secret(release("other", "default"), owner="someone-else"))
    secrets.append(secret(release("skip", "excluded")))
    latest = latest_release_secrets(secrets, {"excluded"})
    assert [(s["metadata"]["namespace"], s["metadata"]["labels"]["version"]) for s in latest] == [
        ("cert-manager", "3"), ("keycloak", "10")]
    rels, errors = releases_from_secrets(secrets, {"excluded"})
    assert errors == []
    cm = rels[0]
    assert (cm.release_name, cm.status, cm.revision) == ("cert-manager", "failed", 3)
    assert cm.as_json() == {"releaseName": "cert-manager", "namespace": "cert-manager", "chart": "cert-manager",
                            "version": "v1.16.2", "appVersion": "v1.16.2", "status": "failed"}


def test_corrupt_release_is_reported_not_raised():
    bad = secret(release())
    bad["data"]["release"] = base64.b64encode(b"%%%").decode()
    rels, errors = releases_from_secrets([bad])
    assert rels == [] and len(errors) == 1 and "cert-manager" in errors[0]


def test_helm_record_with_update_json():
    from posture.provenance.updates import UpdateInfo

    r = HelmRelease("a", "ns", "c", "1.0.0", "2", "deployed", update=UpdateInfo("1.0.0", "1.1.0", "1.1.0", True))
    assert list(r.as_json()) == ["releaseName", "namespace", "chart", "version", "appVersion", "status", "update"]


INDEX = """
apiVersion: v1
entries:
  cert-manager:
    - version: v1.17.1
    - version: v1.16.3
    - version: v1.18.0-alpha.0
  ingress-nginx:
    - version: 4.8.0
"""


async def test_chart_updates_from_index_and_oci():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/index.yaml")
        return httpx.Response(200, text=INDEX)

    reg = FakeRegistry()
    reg.tags[("quay.io", "nebari/charts/nebari-app")] = ["0.1.0", "0.2.0", "0.3.0_build.1"]
    repos = ChartRepos(["https://charts.jetstack.io", "oci://quay.io/nebari/charts"],
                       transport=httpx.MockTransport(handler))
    rels = [HelmRelease("cert-manager", "cert-manager", "cert-manager", "v1.16.2", "v1.16.2", "deployed"),
            HelmRelease("ing", "ingress", "ingress-nginx", "4.8.0", "1.9.4", "deployed"),
            HelmRelease("app", "x", "nebari-app", "0.1.0", "", "deployed"),
            HelmRelease("unknown", "x", "not-in-any-repo", "1.0.0", "", "deployed"),
            HelmRelease("dev", "x", "cert-manager", "main", "", "deployed")]
    await check_chart_updates(rels, repos, skip_prerelease=True, update_level="patch", registry=reg)
    assert rels[0].update.as_json() == {"currentTag": "v1.16.2", "latestInMajor": "v1.17.1",
                                        "newestAvailable": "v1.17.1", "updateAvailable": True}
    assert rels[0].chart_source == "https://charts.jetstack.io"
    assert rels[1].update is None  # current
    assert rels[2].update.newest_available == "0.3.0+build.1" and rels[2].chart_source.startswith("oci://")
    assert rels[3].update is None and rels[4].update is None


async def test_discover_uses_label_selector(monkeypatch):
    seen = {}

    def fake_list():
        seen["called"] = True
        return [secret(release())]

    monkeypatch.setattr(helm, "list_helm_secrets_sync", fake_list)
    rels, errors = await helm.discover(["kube-system"])
    assert seen and len(rels) == 1 and helm.HELM_LABEL_SELECTOR == "owner=helm"


# ---------------------------------------------------------------- security review M1 (gzip bomb)
def test_gzip_bomb_release_is_refused():
    import time

    from posture.provenance.helm import MAX_RELEASE_BYTES, HelmDecodeError, decode_release_payload

    bomb = gzip.compress(b"{" + b" " * (MAX_RELEASE_BYTES + 1024) + b"}", compresslevel=9)
    assert len(bomb) < 100_000
    start = time.monotonic()
    with pytest.raises(HelmDecodeError, match="larger than"):
        decode_release_payload(base64.b64encode(bomb))
    assert time.monotonic() - start < 2


def test_gzip_cap_is_configurable_and_exact(monkeypatch):
    from posture.provenance import helm as helm_mod

    monkeypatch.setattr(helm_mod, "MAX_RELEASE_BYTES", 100)
    ok = json.dumps({"name": "x" * 50}).encode()
    assert helm_mod.decode_release_payload(base64.b64encode(gzip.compress(ok)))["name"] == "x" * 50
    with pytest.raises(helm_mod.HelmDecodeError):
        helm_mod.decode_release_payload(base64.b64encode(gzip.compress(json.dumps({"n": "x" * 200}).encode())))
    with pytest.raises(helm_mod.HelmDecodeError):  # uncompressed payloads are capped too
        helm_mod.decode_release_payload(base64.b64encode(json.dumps({"n": "x" * 200}).encode()))
    with pytest.raises(helm_mod.HelmDecodeError, match="truncated"):
        helm_mod.decode_release_payload(base64.b64encode(gzip.compress(ok)[:-8]))


async def test_chart_index_size_cap(monkeypatch):
    import httpx

    from posture.provenance import helm as helm_mod

    monkeypatch.setattr(helm_mod, "MAX_INDEX_BYTES", 1000)
    transport = httpx.MockTransport(lambda r: httpx.Response(200, content=b"entries: {}\n" + b"#" * 5000))
    repos = helm_mod.ChartRepos(["https://charts.example.com"], transport=transport)
    assert await repos.versions("x") == (None, None)
