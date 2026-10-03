"""End-to-end with Postgres: migrations (0002) -> worker scan with the provenance stage
(fake registry / cosign / helm) -> native + compat endpoints. Needs TEST_DATABASE_URL
(the schema is dropped and recreated!)."""

from __future__ import annotations

import asyncio
import os

import httpx
import pytest

from ..test_integration import D_ALPINE, D_APP, FakeMirror, FakeScanner, inventory
from .fakes import FakeCosign, FakeRegistry

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
async def env():
    url = os.environ["TEST_DATABASE_URL"]
    os.environ.update({"DATABASE_URL": url, "AUTH_MODE": "disabled", "ADMIN_GROUPS": "admin",
                       "CACHE_DIR": "/tmp/posture-test-cache", "CLUSTER_NAME": "grace-test"})
    from posture.config import get_settings

    get_settings.cache_clear()
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine

    eng = create_async_engine(get_settings().database_url)
    async with eng.begin() as conn:
        await conn.execute(text("DROP SCHEMA public CASCADE"))
        await conn.execute(text("CREATE SCHEMA public"))
    await eng.dispose()
    from alembic import command

    from posture.migrate import alembic_config

    await asyncio.to_thread(command.upgrade, alembic_config(), "head")
    from posture.auth import set_authenticator
    from posture.db.session import dispose_engine, get_sessionmaker
    from posture.main import create_app

    set_authenticator(None)
    app = create_app()
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")
    yield {"client": client, "sm": get_sessionmaker(), "settings": get_settings()}
    await client.aclose()
    await dispose_engine()
    set_authenticator(None)
    os.environ.pop("CLUSTER_NAME", None)
    get_settings.cache_clear()


def fake_registry() -> FakeRegistry:
    reg = FakeRegistry()
    # ghcr.io/org/web: BuildKit SBOM + SLSA attestations, cosign .sig
    reg.put("ghcr.io", "org/web", D_APP, {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
                                          "manifests": []}, "application/vnd.oci.image.index.v1+json")
    att = reg.put("ghcr.io", "org/web", "att", {"layers": [
        {"digest": "sha256:" + "e" * 64, "annotations": {"in-toto.io/predicate-type": "https://spdx.dev/Document"}},
        {"digest": "sha256:" + "f" * 64, "annotations": {"in-toto.io/predicate-type": "https://slsa.dev/provenance/v0.2"}}]})
    reg.manifests[("ghcr.io", "org/web", D_APP)].body["manifests"] = [
        {"digest": att, "annotations": {"vnd.docker.reference.type": "attestation-manifest"}}]
    reg.cosign_sig("ghcr.io", "org/web", D_APP)
    reg.tags[("ghcr.io", "org/web")] = ["1.0", "1.0.1", "1.1.0"]
    # alpine: unsigned, nothing attached, major behind
    reg.put("docker.io", "library/alpine", D_ALPINE, {"schemaVersion": 2, "layers": []})
    reg.tags[("docker.io", "library/alpine")] = ["3.17.0", "3.20.3", "4.0.0", "latest", "edge"]
    # busybox:latest (no digest): manifest by tag
    reg.single("docker.io", "library/busybox", "latest")
    return reg


async def fake_helm(excluded):
    from posture.provenance.helm import HelmRelease
    from posture.provenance.updates import UpdateInfo

    return [HelmRelease("web", "app", "web-chart", "1.0.0", "1.0", "deployed", revision=3,
                        update=UpdateInfo("1.0.0", "1.2.0", "1.2.0", True)),
            HelmRelease("dns", "kube-system", "coredns", "1.2.3", "1.11", "failed", revision=1)], []


def make_worker(env, reg):
    from posture.provenance.stage import ProvenanceStage
    from posture.scanners.clair import parse_clair_json
    from posture.scanners.grype import parse_grype_json
    from posture.scanners.trivy import parse_trivy_json
    from posture.worker import Worker

    async def inv(excluded):
        return inventory()

    scanners = {"trivy": FakeScanner("trivy", parse_trivy_json, "trivy.json"),
                "grype": FakeScanner("grype", parse_grype_json, "grype.json"),
                "clair": FakeScanner("clair", parse_clair_json, "clair.json")}
    w = Worker(env["settings"], env["sm"], scanners=scanners, inventory_fn=inv, mirror=FakeMirror())
    w.provenance_stage = ProvenanceStage(env["settings"], env["sm"], registry_factory=lambda: reg,
                                         cosign_factory=lambda cfg: FakeCosign({"ghcr.io/org/web@"}),
                                         helm_discover=fake_helm)
    return w


async def test_01_empty(env):
    c = env["client"]
    assert (await c.get("/api/reports")).json() == []
    assert (await c.get("/api/reports/latest")).status_code == 404
    sc = (await c.get("/api/v1/supply-chain")).json()
    assert sc["unique"] == 0 and sc["score"] is None and sc["grade"] == "?" and sc["unsigned"] == []
    assert (await c.get("/api/v1/helm-releases")).json() == []
    s = (await c.get("/api/v1/summary")).json()
    assert s["supplyChainScore"] is None and s["supplyChain"]["unique"] == 0


async def test_02_scan_with_provenance(env):
    c = env["client"]
    reg = fake_registry()
    r = await c.put("/api/v1/settings", json={"provenance": {"cosignPublicKey": "awskms:///alias/test"}})
    assert r.status_code == 200 and r.json()["provenance"]["cosignPublicKey"] == "awskms:///alias/test"
    assert (await c.post("/api/v1/scans", json={})).status_code == 202
    w = make_worker(env, reg)
    assert await w.poll_once() is True
    scan = (await c.get("/api/v1/scans/1")).json()
    assert scan["status"] == "done", scan
    assert any(line.split(" ", 1)[1].startswith("provenance: 3 image(s), 1 signed") for line in scan["log"]), scan["log"]
    assert reg.closed

    imgs = {i["ref"]: i for i in (await c.get("/api/v1/images")).json()["items"]}
    web = imgs["ghcr.io/org/web:1.0"]["provenance"]
    assert web["signature"] == {"signed": True, "verified": True}
    assert web["sbom"] == {"hasSBOM": True, "format": "spdx"}
    assert web["provenance"] == {"hasProvenance": True, "predicateType": "https://slsa.dev/provenance/v0.2"}
    assert web["update"]["latestInMajor"] == "1.1.0" and web["score"] == 85.0 and web["grade"] == "B"
    assert web["findings"] == ["update-available"] and web["controls"] == ["SI-2"]
    alpine = imgs["docker.io/library/alpine:3.17.0"]["provenance"]
    assert alpine["signature"] == {"signed": False, "verified": False}
    assert alpine["update"] == {"currentTag": "3.17.0", "latestInMajor": "3.20.3", "newestAvailable": "4.0.0",
                                "updateAvailable": True}
    assert alpine["score"] == 0.0 and "major-update-available" in alpine["findings"]  # 40+20+15+25
    busybox = imgs["docker.io/library/busybox:latest"]["provenance"]
    assert busybox["mutableTag"] is True and busybox["update"] == {"currentTag": "latest", "updateAvailable": False}

    s = (await c.get("/api/v1/summary")).json()
    # running containers: web x2 (85), alpine init + coredns (0) -> 42.5
    assert s["supplyChainScore"] == 42.5
    assert s["score"] == round(0.6 * s["vulnScore"] + 0.25 * s["postureScore"] + 0.15 * 42.5, 1)
    sc = s["supplyChain"]
    assert (sc["unique"], sc["signed"], sc["verified"], sc["withSbom"], sc["withProvenance"], sc["withUpdates"]) == (
        3, 1, 1, 1, 1, 2)
    assert (sc["helmReleases"], sc["helmWithUpdates"]) == (2, 1)

    full = (await c.get("/api/v1/supply-chain")).json()
    assert {u["ref"] for u in full["unsigned"]} == {"docker.io/library/alpine:3.17.0", "docker.io/library/busybox:latest"}
    assert {o["ref"] for o in full["outdated"]} == {"ghcr.io/org/web:1.0", "docker.io/library/alpine:3.17.0"}
    helm = (await c.get("/api/v1/helm-releases")).json()
    assert [h["releaseName"] for h in helm] == ["web", "dns"] and helm[0]["update"]["updateAvailable"] is True
    assert (await c.get("/api/v1/helm-releases", params={"namespace": "kube-system"})).json()[0]["status"] == "failed"

    lst = (await c.get("/api/reports")).json()
    assert len(lst) == 1 and lst[0]["clusterName"] == "grace-test"
    rep = await c.get(f"/api/reports/{lst[0]['filename']}")
    doc = rep.json()
    assert doc == (await c.get("/api/reports/latest")).json()
    assert list(doc) == ["metadata", "images", "helmReleases", "summary"]
    assert doc["metadata"]["namespacesScanned"] == ["app", "batch", "kube-system"]
    assert doc["summary"] == {"totalImages": 4, "uniqueImages": 3, "signedImages": 1, "verifiedImages": 1,
                              "imagesWithSBOM": 1, "imagesWithProvenance": 1, "imagesWithUpdates": 3,
                              "totalHelmReleases": 2, "helmReleasesWithUpdates": 1}
    web_rec = next(i for i in doc["images"] if i["image"] == "ghcr.io/org/web:1.0")
    assert web_rec["workload"] == {"kind": "Deployment", "name": "web"} and web_rec["digest"] == D_APP
    bb = next(i for i in doc["images"] if i["image"] == "busybox")
    assert bb["workload"] == {"kind": "CronJob", "name": "nightly"} and "update" not in bb
    csv = (await c.get("/api/export", params={"format": "csv"})).text.splitlines()
    assert len(csv) == 5 and csv[0].startswith("Image,Namespace,")


async def test_03_rescan_reuses_attestation_cache(env):
    c = env["client"]
    reg = fake_registry()
    assert (await c.post("/api/v1/scans", json={"force": False})).status_code == 202
    w = make_worker(env, reg)
    assert await w.poll_once() is True
    heads = [x for x in reg.calls if x[0] == "head"]
    # digest-pinned images are cached; only busybox (tag ref, no digest) is re-walked
    assert all("busybox" in x[2] for x in heads)
    assert any(x[0] == "tags" for x in reg.calls)  # update checks always re-run
    assert len((await c.get("/api/reports")).json()) == 2
    sc = (await c.get("/api/v1/supply-chain")).json()
    assert sc["signed"] == 1 and sc["scanId"] == 2


async def test_04_disabled_restores_old_weights(env):
    c = env["client"]
    r = await c.put("/api/v1/settings", json={"provenance": {"enabled": False}})
    assert r.status_code == 200 and r.json()["provenance"]["enabled"] is False
    assert (await c.post("/api/v1/scans", json={})).status_code == 202
    w = make_worker(env, fake_registry())
    assert await w.poll_once() is True
    scan = (await c.get("/api/v1/scans/3")).json()
    assert scan["score"] == round(0.7 * scan["vulnScore"] + 0.3 * scan["postureScore"], 1)
    assert len((await c.get("/api/reports")).json()) == 2  # scan 3 has no provenance results
    await c.put("/api/v1/settings", json={"provenance": {"enabled": True}})
