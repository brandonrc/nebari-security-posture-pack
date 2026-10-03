"""Report document = provenance-collector-pack internal/report/types.go (exact keys, omitempty)."""

import json
from datetime import UTC, datetime
from types import SimpleNamespace

from posture.provenance.report import (
    ImageEntry,
    ReportInput,
    build_report_document,
    collector_version,
    compute_summary,
    csv_escape,
    export_csv,
    export_markdown,
    filename_time,
    go_json,
    go_time,
    image_entries,
    report_filename,
)

TOP_KEYS = ["metadata", "images", "helmReleases", "summary"]
META_KEYS = ["generatedAt", "collectorVersion", "clusterName", "namespacesScanned"]
IMAGE_KEYS = ["image", "digest", "namespace", "workload", "signature", "sbom", "provenance", "update"]
SUMMARY_KEYS = ["totalImages", "uniqueImages", "signedImages", "verifiedImages", "imagesWithSBOM",
                "imagesWithProvenance", "imagesWithUpdates", "totalHelmReleases", "helmReleasesWithUpdates"]
HELM_KEYS = ["releaseName", "namespace", "chart", "version", "appVersion", "status"]
GEN = datetime(2025, 6, 15, 6, 0, 0, tzinfo=UTC)


def their_sample() -> dict:
    """internal/dashboard/server_test.go testReport, produced through our builder."""
    return build_report_document(ReportInput(
        generated_at=GEN, cluster_name="test-cluster", namespaces_scanned=["default"],
        images=[ImageEntry("nginx:1.27", "default", "Deployment", "nginx", "sha256:abc123def456",
                           signature={"signed": True, "verified": True}, sbom={"hasSBOM": True, "format": "spdx"},
                           provenance={"hasProvenance": False}, update={"currentTag": "1.27", "updateAvailable": False})],
        helm_releases=[{"releaseName": "ingress", "namespace": "default", "chart": "ingress-nginx", "version": "4.8.0",
                        "appVersion": "1.9.4", "status": "deployed"}]))


def test_full_document_key_sets_and_order():
    doc = their_sample()
    assert list(doc) == TOP_KEYS
    assert list(doc["metadata"]) == META_KEYS
    assert doc["metadata"]["generatedAt"] == "2025-06-15T06:00:00Z"
    assert doc["metadata"]["collectorVersion"] == collector_version() and collector_version().endswith("+posture")
    img = doc["images"][0]
    # omitempty: provenance/update dropped when negative (their generator only attaches positives)
    assert list(img) == ["image", "digest", "namespace", "workload", "signature", "sbom"]
    assert set(img) <= set(IMAGE_KEYS) and list(img["workload"]) == ["kind", "name"]
    assert list(doc["helmReleases"][0]) == HELM_KEYS
    assert list(doc["summary"]) == SUMMARY_KEYS
    assert doc["summary"] == {"totalImages": 1, "uniqueImages": 1, "signedImages": 1, "verifiedImages": 1,
                              "imagesWithSBOM": 1, "imagesWithProvenance": 0, "imagesWithUpdates": 0,
                              "totalHelmReleases": 1, "helmReleasesWithUpdates": 0}


def test_their_sample_round_trips_semantically():
    theirs = {
        "metadata": {"generatedAt": "2025-06-15T06:00:00Z", "collectorVersion": "test", "clusterName": "test-cluster",
                     "namespacesScanned": ["default"]},
        "images": [{"image": "nginx:1.27", "digest": "sha256:abc123def456", "namespace": "default",
                    "workload": {"kind": "Deployment", "name": "nginx"}, "signature": {"signed": True, "verified": True},
                    "sbom": {"hasSBOM": True, "format": "spdx"}}],
        "helmReleases": [{"releaseName": "ingress", "namespace": "default", "chart": "ingress-nginx",
                          "version": "4.8.0", "appVersion": "1.9.4", "status": "deployed"}],
    }
    ours = their_sample()
    ours["metadata"]["collectorVersion"] = "test"
    assert {k: ours[k] for k in theirs} == theirs


def test_minimal_document_omitempty():
    doc = build_report_document(ReportInput(generated_at=GEN, cluster_name="",
                                            images=[ImageEntry("busybox", "batch", "CronJob", "nightly")]))
    assert list(doc) == ["metadata", "images", "summary"]  # helmReleases omitempty
    assert list(doc["metadata"]) == ["generatedAt", "collectorVersion", "namespacesScanned"]  # clusterName omitempty
    assert doc["metadata"]["namespacesScanned"] is None  # Go nil slice -> null
    assert doc["images"][0] == {"image": "busybox", "namespace": "batch", "workload": {"kind": "CronJob", "name": "nightly"}}
    empty = build_report_document(ReportInput(generated_at=GEN, cluster_name="c"))
    assert empty["images"] == [] and empty["summary"]["uniqueImages"] == 0


def test_signature_present_even_when_unsigned_and_error_omitempty():
    e = ImageEntry("a:1", "ns", "Deployment", "a", signature={"signed": False, "verified": False})
    doc = build_report_document(ReportInput(generated_at=GEN, cluster_name="c", images=[e]))
    assert doc["images"][0]["signature"] == {"signed": False, "verified": False}


def test_summary_counts_like_their_generator():
    imgs = [
        {"image": "a:1", "signature": {"signed": True, "verified": False}, "update": {"updateAvailable": True}},
        {"image": "a:1", "signature": {"signed": True, "verified": True}, "provenance": {"hasProvenance": True}},
        {"image": "b:2", "signature": {"signed": False, "verified": False}, "sbom": {"hasSBOM": True}},
    ]
    s = compute_summary(imgs, [{"update": {"updateAvailable": True}}, {}])
    assert s == {"totalImages": 3, "uniqueImages": 2, "signedImages": 2, "verifiedImages": 1, "imagesWithSBOM": 1,
                 "imagesWithProvenance": 1, "imagesWithUpdates": 1, "totalHelmReleases": 2,
                 "helmReleasesWithUpdates": 1}


def test_go_serialization():
    assert go_time(datetime(2025, 6, 15, 6, 0, 0, 120000, tzinfo=UTC)) == "2025-06-15T06:00:00.12Z"
    assert go_time(datetime(2025, 6, 15, 6, 0, 0)) == "2025-06-15T06:00:00Z"
    assert go_json({"a": "<b>&"}).decode() == '{\n  "a": "\\u003cb\\u003e\\u0026"\n}'
    assert go_json([{"a": 1}], indent=False) == b'[{"a":1}]\n'
    assert go_json({"x": None, "y": []}).decode() == '{\n  "x": null,\n  "y": []\n}'
    assert json.loads(go_json(their_sample()))["summary"]["totalImages"] == 1


def test_filenames():
    assert report_filename(GEN) == "provenance-20250615-060000.json"
    assert filename_time("provenance-20250615-060000.json") == GEN
    assert filename_time("provenance-latest.json") is None and filename_time("../etc") is None


def _c(ns, kind, name, image, fk, ctype="container"):
    return SimpleNamespace(namespace=ns, workload_kind=kind, workload_name=name, image=image, image_fk=fk,
                           container_type=ctype)


def test_image_entries_dedup_and_per_tag_update():
    containers = [
        _c("app", "Deployment", "web", "ghcr.io/org/web:1.0", 1),
        _c("app", "Deployment", "web", "ghcr.io/org/web:1.0", 1),  # second replica: deduped
        _c("app", "Deployment", "web", "alpine:3.17.0", 2, "init"),  # init containers included
        _c("app", "Deployment", "web", "busybox", 3, "ephemeral"),  # ephemeral excluded
        _c("kube-system", "DaemonSet", "dns", "alpine:3.17.0", 2),
        _c("batch", "CronJob", "nightly", "busybox", None),  # unresolved image: no digest/checks
    ]
    images = {1: SimpleNamespace(digest="sha256:" + "1" * 64), 2: SimpleNamespace(digest="sha256:" + "2" * 64)}
    prov = {2: SimpleNamespace(signature={"signed": False, "verified": False}, sbom={"hasSBOM": False},
                               provenance={"hasProvenance": False},
                               updates={"3.17.0": {"currentTag": "3.17.0", "latestInMajor": "3.20.3",
                                                   "updateAvailable": True}})}
    entries = image_entries(containers, images, prov)
    assert [(e.namespace, e.image) for e in entries] == [("app", "ghcr.io/org/web:1.0"), ("app", "alpine:3.17.0"),
                                                         ("kube-system", "alpine:3.17.0"), ("batch", "busybox")]
    doc = build_report_document(ReportInput(generated_at=GEN, cluster_name="lab", images=entries,
                                            namespaces_scanned=["app", "batch", "kube-system"]))
    alpine = doc["images"][1]
    assert alpine["update"]["latestInMajor"] == "3.20.3" and "sbom" not in alpine and alpine["signature"]["signed"] is False
    assert "digest" not in doc["images"][3] and "signature" not in doc["images"][0]
    assert doc["summary"]["uniqueImages"] == 3 and doc["summary"]["imagesWithUpdates"] == 2


def test_export_csv_matches_their_format():
    csv = export_csv(their_sample())
    lines = csv.splitlines()
    assert lines[0] == ("Image,Namespace,Workload Kind,Workload Name,Digest,Signed,Verified,SLSA Provenance,SBOM,"
                        "SBOM Format,Update Available,Current Tag,Latest In Major")
    assert lines[1] == "nginx:1.27,default,Deployment,nginx,sha256:abc123def456,true,true,false,true,spdx,false,,"
    assert csv.endswith("\n")
    assert csv_escape('a,"b"') == '"a,""b"""' and csv_escape("plain") == "plain" and csv_escape("x\ny") == '"x\ny"'


def test_export_markdown_matches_their_format():
    md = export_markdown(their_sample())
    for want in ("# Provenance Report", "**Generated:** 2025-06-15 06:00:00 UTC", "**Cluster:** test-cluster",
                 "**Namespaces:** default", "## Summary", "| Signed | 1 |", "## Container Images",
                 "| `nginx:1.27` | default | Deployment/nginx | Verified | - | SPDX | - |", "## Helm Releases",
                 "| ingress | default | ingress-nginx | 4.8.0 | 1.9.4 | deployed |"):
        assert want in md, want
