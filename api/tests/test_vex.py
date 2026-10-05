"""VEX store (posture.vex): statement matching by image ref / digest / purl, application at
correlation time (score, counts) and the scanners' `--vex` plumbing."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from posture.analysis import analyze
from posture.scanners.base import Finding, ScanResult
from posture.vex import ImageIdentity, VexStore, image_matcher, parse_openvex

PACK_VEX = Path(__file__).resolve().parents[1] / "vex"
D1 = "sha256:" + "1" * 64
D2 = "sha256:" + "2" * 64
CTX = "https://openvex.dev/ns/v0.2.0"


def doc(*statements, ts="2026-10-01T00:00:00Z", **kw):
    return {"@context": CTX, "@id": kw.get("id", "https://example.org/vex/1"), "author": "isso",
            "timestamp": ts, "version": 1, "statements": list(statements)}


def st(vuln, products, status="not_affected", **kw):
    out = {"vulnerability": {"name": vuln} if isinstance(vuln, str) else vuln, "products": products,
           "status": status}
    if status == "not_affected":
        out["justification"] = kw.pop("justification", "vulnerable_code_not_in_execute_path")
        out["impact_statement"] = kw.pop("impact", "not reachable")
    out.update(kw)
    return out


def write(tmp_path: Path, name: str, d) -> Path:
    p = tmp_path / name
    p.write_text(json.dumps(d) if not isinstance(d, str) else d)
    return p


def ident(*refs, digests=(), tags=()):
    return ImageIdentity.of(refs, digests=digests, tags=tags)


# ---------------------------------------------------------------- the pack's own document
def test_pack_vex_loads_and_matches_every_name_of_the_packs_images():
    store = VexStore([str(PACK_VEX)])
    assert not store.errors and len(store.files) == 1 and len(store.statements) == 60
    # grace (local registry), GHCR (as published), any mirror: pkg:oci/<name> matches the last path segment
    for ref in ("localhost:32000/security-posture-api:0.1.0",
                f"ghcr.io/nebari-dev/nebari-security-posture-pack-api@{D1}",
                "quay.io/someone/security-posture-worker:dev"):
        vex = store.for_image(ident(ref))
        assert len(vex) > 0, ref
    assert len(store.for_image(ident("docker.io/library/python:3.13-slim"))) == 0
    assert len(store.for_image(ident("ghcr.io/org/security-posture-api-fork:1"))) == 0
    api = store.for_image(ident("localhost:32000/security-posture-api:0.1.0"))
    d = api.decide("CVE-2026-16742", "libsystemd0", "debian", "257.9-1~deb13u1")
    assert d.status == "not_affected" and d.suppressed and d.justification == "vulnerable_code_not_present"
    assert "systemd-homed" in d.detail and d.source.startswith("posture-images.vex.json")
    # the subcomponents scope the statement: same CVE on another package is not covered
    assert api.decide("CVE-2026-16742", "libc6", "debian", "2.41-12") is None
    # cve id case-insensitive; wrong ecosystem (a python package named like the deb) is not covered
    assert api.decide("cve-2026-16742", "libudev1", "deb", None).suppressed
    assert api.decide("CVE-2026-16742", "libudev1", "python-pkg", None) is None


def test_pack_vex_under_investigation_is_recorded_not_suppressed():
    store = VexStore([str(PACK_VEX)])
    w = store.for_image(ident("localhost:32000/security-posture-worker:0.1.0"))
    d = w.decide("CVE-2026-95619", "libstdc++6", "debian", None)
    assert d.status == "under_investigation" and not d.suppressed and d.justification is None
    assert "HarfBuzz" in d.detail


# ---------------------------------------------------------------- product forms
@pytest.mark.parametrize("product,refs,digests,expected", [
    ("pkg:oci/app", ["ghcr.io/org/app:1.0"], [], True),
    ("pkg:oci/app", ["ghcr.io/org/application:1.0"], [], False),
    (f"pkg:oci/app@{D1.replace(':', '%3A')}", ["ghcr.io/org/app:1.0"], [D1], True),
    (f"pkg:oci/app@{D1.replace(':', '%3A')}", ["ghcr.io/org/app:1.0"], [D2], False),
    ("pkg:oci/app?repository_url=ghcr.io/org/app", ["ghcr.io/org/app:1.0"], [], True),
    ("pkg:oci/app?repository_url=https://ghcr.io/org/app", ["ghcr.io/org/app:1.0"], [], True),
    ("pkg:oci/app?repository_url=ghcr.io/org/app", ["quay.io/org/app:1.0"], [], False),
    ("pkg:oci/app?repository_url=ghcr.io/org/app&tag=1.0", ["ghcr.io/org/app:2.0"], [], False),
    ("pkg:oci/nginx?repository_url=docker.io/library/nginx", ["nginx:1.27"], [], True),
    ("pkg:docker/library/nginx@1.27", ["docker.io/library/nginx:1.27"], [], True),
    ("pkg:docker/library/nginx@1.27", ["docker.io/library/nginx:1.28"], [], False),
    ("pkg:docker/org/app?repository_url=quay.io", ["quay.io/org/app:1"], [], True),
    ("ghcr.io/org/app", ["ghcr.io/org/app:1.0"], [], True),
    ("ghcr.io/org/app", ["quay.io/org/app:1.0"], [], False),
    ("ghcr.io/org/app:1.0", ["ghcr.io/org/app@" + D1], [], False),
    (f"ghcr.io/org/app@{D1}", ["localhost:32000/org/app:1.0"], [D1], False),  # repo differs
    (D1, ["localhost:32000/org/app:1.0"], [D1], True),  # bare digest: any name
    (D1, ["localhost:32000/org/app:1.0"], [D2], False),
])
def test_image_product_matching(product, refs, digests, expected):
    m = image_matcher(product)
    assert m is not None
    assert m.matches(ident(*refs, digests=digests)) is expected


def test_identity_skips_oci_layout_paths_and_keeps_digests_and_tags():
    i = ident("oci-dir:/cache/images/sha256-11", f"localhost:32000/security-posture-api@{D1}",
              digests=[D2, None, "nope"], tags=["0.1.0", "ghcr.io/x/y:2"])
    assert i.names == {"security-posture-api", "y"} and i.digests == {D1, D2}
    assert {"0.1.0", "2"} <= i.tags
    assert "oci-dir:/cache/images/sha256-11" not in i.refs


def test_subcomponent_and_package_product_matching(tmp_path):
    d = doc(
        st("CVE-2026-1", [{"@id": "pkg:oci/app", "subcomponents": [{"@id": "pkg:golang/golang.org/x/net@v0.17.0"}]}]),
        st("CVE-2026-2", ["pkg:deb/debian/libxml2"]),  # package product: every image
        st("CVE-2026-3", [{"@id": "pkg:oci/app", "subcomponents": ["pkg:maven/org.apache.commons/commons-text"]}]),
        st("CVE-2026-4", [{"identifiers": {"purl": "pkg:oci/app"}}]),  # no subcomponents: every package
    )
    store = VexStore([str(write(tmp_path, "a.json", d).parent)])
    app = store.for_image(ident("ghcr.io/org/app:1"))
    other = store.for_image(ident("ghcr.io/org/other:1"))
    assert app.decide("CVE-2026-1", "golang.org/x/net", "gobinary", "v0.17.0").suppressed
    assert app.decide("CVE-2026-1", "golang.org/x/net", "gobinary", "v0.23.0") is None  # version pinned
    assert app.decide("CVE-2026-1", "golang.org/x/crypto", "gobinary", "v0.17.0") is None
    assert other.decide("CVE-2026-1", "golang.org/x/net", "gobinary", "v0.17.0") is None
    assert other.decide("CVE-2026-2", "libxml2", "debian", "2.9.14").suppressed
    assert other.decide("CVE-2026-2", "libxml2", "alpine", "2.12") is None  # deb purl vs apk package
    assert app.decide("CVE-2026-3", "org.apache.commons:commons-text", "jar", "1.9").suppressed
    assert app.decide("CVE-2026-4", "anything", None, None).suppressed
    assert other.decide("CVE-2026-4", "anything", None, None) is None


def test_aliases_newest_statement_and_operator_override(tmp_path):
    pack, site = tmp_path / "pack", tmp_path / "site"
    pack.mkdir(), site.mkdir()
    write(pack, "pack.json", doc(st({"name": "GHSA-aaaa-bbbb-cccc", "aliases": ["CVE-2026-9"]}, ["pkg:oci/app"]),
                                 ts="2026-10-01T00:00:00Z"))
    # same timestamp, later directory (VEX_DIR after the built-in one): the operator wins
    write(site, "site.json", doc(st("CVE-2026-9", ["pkg:oci/app"], status="affected",
                                    action_statement="upgrade by Nov"), ts="2026-10-01T00:00:00Z"))
    store = VexStore([str(pack), str(site)])
    vex = store.for_image(ident("ghcr.io/org/app:1"))
    d = vex.decide("CVE-2026-9", "x")
    assert d.status == "affected" and not d.suppressed and d.detail == "upgrade by Nov" and d.source.startswith("site.json")
    assert vex.decide("GHSA-aaaa-bbbb-cccc", "x").suppressed  # alias only in the pack statement
    # a newer statement wins whatever the order
    write(pack, "pack.json", doc(st("CVE-2026-9", ["pkg:oci/app"], timestamp="2026-10-03T00:00:00Z")))
    assert store.reload_if_changed() is True
    assert store.for_image(ident("ghcr.io/org/app:1")).decide("CVE-2026-9", "x").suppressed
    assert store.reload_if_changed() is False


def test_invalid_documents_are_rejected_not_fatal(tmp_path):
    write(tmp_path, "good.json", doc(st("CVE-2026-1", ["pkg:oci/app"])))
    write(tmp_path, "broken.json", "{not json")
    write(tmp_path, "cdx.json", {"bomFormat": "CycloneDX", "vulnerabilities": []})
    write(tmp_path, "bad-status.json", doc(st("CVE-2026-2", ["pkg:oci/app"], status="maybe")))
    write(tmp_path, "notes.txt", "ignored")
    (tmp_path / "..data").mkdir()
    store = VexStore([str(tmp_path), str(tmp_path / "missing")])
    assert sorted(Path(f).name for f in store.errors) == ["broken.json", "cdx.json"]
    assert sorted(Path(f).name for f in store.files) == ["bad-status.json", "good.json"]
    assert len(store.statements) == 1  # the unknown status is skipped


def test_parse_openvex_requires_statements():
    with pytest.raises(ValueError):
        parse_openvex({"@context": CTX}, "x.json")
    with pytest.raises(ValueError):
        parse_openvex({"@context": "https://cyclonedx.org", "statements": []}, "x.json")


def test_from_settings_builtin_and_operator_dirs(tmp_path):
    class S:
        vex_builtin_dir = "/etc/posture/vex"  # absent here: falls back to api/vex of the checkout
        vex_dir = [str(tmp_path)]

    write(tmp_path, "site.json", doc(st("CVE-2026-1", ["pkg:oci/app"])))
    store = VexStore.from_settings(S())
    if not os.path.isdir("/etc/posture/vex"):
        assert store.dirs == [str(PACK_VEX), str(tmp_path)]
    assert len(store.statements) == 61

    class Off:
        vex_builtin_dir = ""
        vex_dir = []

    assert VexStore.from_settings(Off()).statements == []


# ---------------------------------------------------------------- correlation + score
def _f(vid, pkg, sev, scanner, fixed="1.1", pkg_type="debian"):
    return Finding(vid, sev, pkg, "1.0", fixed, pkg_type, scanner)


def _results():
    fs = [("CVE-2026-1", "libfoo1", "critical"), ("CVE-2026-2", "libbar1", "high"), ("CVE-2026-3", "libbaz1", "medium")]
    return [ScanResult(s, "ok", findings=[_f(v, p, sev, s) for v, p, sev in fs]) for s in ("trivy", "grype")]


def test_not_affected_is_kept_but_out_of_score_and_counts(tmp_path):
    write(tmp_path, "v.json", doc(
        st("CVE-2026-1", [{"@id": "pkg:oci/app", "subcomponents": ["pkg:deb/debian/libfoo1"]}]),
        st("CVE-2026-2", ["pkg:oci/app"], status="under_investigation", status_notes="checking"),
    ))
    vex = VexStore([str(tmp_path)]).for_image(ident("ghcr.io/org/app:1"))
    base = analyze(_results())
    with_vex = analyze(_results(), vex=vex)
    assert len(with_vex.consensus) == len(base.consensus) == 3  # nothing dropped
    sup = next(c for c in with_vex.consensus if c.vuln_id == "CVE-2026-1")
    assert sup.suppressed and sup.vex_status == "not_affected"
    assert sup.vex_justification == "vulnerable_code_not_in_execute_path" and sup.vex_source.startswith("v.json")
    inv = next(c for c in with_vex.consensus if c.vuln_id == "CVE-2026-2")
    assert inv.vex_status == "under_investigation" and not inv.suppressed and inv.vex_detail == "checking"
    assert with_vex.vex_suppressed == 1 and with_vex.vex_recorded == 2
    assert base.counts["critical"] == 1 and with_vex.counts["critical"] == 0
    assert with_vex.fixable["critical"] == 0 and with_vex.counts["high"] == 1  # under_investigation stays open
    assert with_vex.score.score > base.score.score
    assert with_vex.score.penalty == pytest.approx(base.score.penalty - 10.0 * 1.25)
    # an image the statements do not name is unchanged
    other = VexStore([str(tmp_path)]).for_image(ident("ghcr.io/org/other:1"))
    assert analyze(_results(), vex=other).score == base.score


# ---------------------------------------------------------------- scanner plumbing
def test_trivy_vex_flags_only_by_image_ref():
    from posture.scanners.trivy import TrivyScanner

    t = TrivyScanner("http://trivy:4954")
    assert "--vex" not in t.argv("ghcr.io/org/app:1", False, 60)
    t.vex_files = ("/etc/posture/vex/a.json", "/etc/posture/vex.d/extra/b.json")
    argv = t.argv("ghcr.io/org/app:1", False, 60)
    assert argv[argv.index("--vex") + 1] == "/etc/posture/vex/a.json" and argv.count("--vex") == 2
    assert "--show-suppressed" in argv and argv[-2:] == ["--", "ghcr.io/org/app:1"]
    local = t.argv("oci-dir:/cache/images/sha256-1", False, 60)
    assert "--vex" not in local and "--show-suppressed" not in local


def test_trivy_suppressed_findings_are_recovered():
    from posture.scanners.trivy import parse_trivy_json

    vuln = {"VulnerabilityID": "CVE-2026-1", "PkgName": "libfoo1", "InstalledVersion": "1.0", "Severity": "HIGH"}
    d = {"Results": [{"Target": "x", "Type": "debian", "Vulnerabilities": [
        {**vuln, "VulnerabilityID": "CVE-2026-2"}],
        "ExperimentalModifiedFindings": [
            {"Type": "vulnerability", "Status": "not_affected", "Source": "OpenVEX", "Finding": vuln},
            {"Type": "misconfiguration", "Status": "ignored", "Finding": {"ID": "DS001"}},
        ]}]}
    findings, _ = parse_trivy_json(d)
    assert sorted(f.vuln_id for f in findings) == ["CVE-2026-1", "CVE-2026-2"]


def test_grype_vex_flags_and_ignored_matches(tmp_path):
    from posture.scanners.grype import GrypeScanner, parse_grype_file, parse_grype_json

    g = GrypeScanner()
    assert g.argv("registry:ghcr.io/org/app:1") == ["grype", "-o", "json", "--", "registry:ghcr.io/org/app:1"]
    g.vex_files = ("/v/a.json",)
    assert g.argv("registry:ghcr.io/org/app:1")[3:5] == ["--vex", "/v/a.json"]
    assert "--vex" not in g.argv("oci-dir:/cache/images/sha256-1")

    def m(vid, rules=None):
        out = {"vulnerability": {"id": vid, "severity": "High"}, "artifact": {"name": "libfoo1", "version": "1", "type": "deb"}}
        if rules is not None:
            out["appliedIgnoreRules"] = rules
        return out

    d = {"matches": [m("CVE-2026-1")],
         "ignoredMatches": [m("CVE-2026-2", [{"vex-status": "not_affected", "vex-justification": "x"}]),
                            m("CVE-2026-3", [{"vulnerability": "CVE-2026-3", "reason": "user ignore rule"}])]}
    findings, _ = parse_grype_json(d)
    assert sorted(f.vuln_id for f in findings) == ["CVE-2026-1", "CVE-2026-2"]  # user ignores stay ignored
    p = tmp_path / "g.json"
    p.write_text(json.dumps(d))
    assert sorted(f.vuln_id for f in parse_grype_file(str(p))[0]) == ["CVE-2026-1", "CVE-2026-2"]
