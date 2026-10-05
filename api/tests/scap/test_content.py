"""posture.scap.content: sources (sha256), unpacking, index, catalogue, rule metadata."""

from __future__ import annotations

import bz2
import hashlib
import io
import json
import shutil
import zipfile

import pytest

from posture.scap import content

from .helpers import TEST_BENCHMARK, TEST_DS, TEST_PROFILE


def _zip(tmp_path, members: dict[str, bytes]):
    p = tmp_path / "content.zip"
    with zipfile.ZipFile(p, "w") as zf:
        for n, d in members.items():
            zf.writestr(n, d)
    return p, hashlib.sha256(p.read_bytes()).hexdigest()


def test_fetch_requires_and_verifies_sha256(tmp_path):
    z, sha = _zip(tmp_path, {"scap-security-guide-0.1.82/ssg-test-ds.xml": TEST_DS.read_bytes(),
                             "scap-security-guide-0.1.82/ssg-other-ds.xml": b"<x/>",
                             "scap-security-guide-0.1.82/README": b"r"})
    cdir = tmp_path / "content"
    with pytest.raises(content.ContentError, match="sha256 is required"):
        content.fetch_source(content.Source("ssg", f"file://{z}", ""), cdir)
    with pytest.raises(content.ContentError, match="mismatch"):
        content.fetch_source(content.Source("ssg", f"file://{z}", "0" * 64), cdir)
    assert not (cdir / "sources" / "ssg").exists()  # nothing unpacked unverified
    m = content.fetch_source(content.Source("ssg", f"file://{z}", sha, include=["ssg-test-ds.xml"]), cdir)
    assert m["files"] == ["ssg-test-ds.xml"] and (cdir / "sources/ssg/ssg-test-ds.xml").exists()
    # unchanged marker: no second download (the source file is gone and it still succeeds)
    z.unlink()
    assert content.fetch_source(content.Source("ssg", f"file://{z}", sha, include=["ssg-test-ds.xml"]), cdir) == m


def test_unpack_bz2_and_nested_disa_zip(tmp_path):
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as zf:
        zf.writestr("U_Test_V1R1_STIG_SCAP_1-3_Benchmark.xml", TEST_DS.read_bytes())
    outer, _ = _zip(tmp_path, {"U_Test_V1R1_STIG_SCAP_1-3_Benchmark.zip": inner.getvalue()})
    out = tmp_path / "o"
    assert content.unpack(outer, "bundle.zip", out, []) == ["U_Test_V1R1_STIG_SCAP_1-3_Benchmark.xml"]
    b = tmp_path / "ssg-x-ds.xml.bz2"
    b.write_bytes(bz2.compress(TEST_DS.read_bytes()))
    assert content.unpack(b, b.name, tmp_path / "o2", []) == ["ssg-x-ds.xml"]
    # member names never become paths
    evil, _ = _zip(tmp_path / "e" if (tmp_path / "e").mkdir() is None else tmp_path,
                   {"../../ssg-evil-ds.xml": b"<x/>"})
    files = content.unpack(evil, "evil.zip", tmp_path / "o3", [])
    assert files == ["ssg-evil-ds.xml"] and (tmp_path / "o3/ssg-evil-ds.xml").exists()


def test_index_catalogue_and_find_content(tmp_path):
    cdir = tmp_path / "content"
    (cdir / "local").mkdir(parents=True)
    shutil.copy(TEST_DS, cdir / "local" / "posture-test-ds.xml")
    (cdir / "local" / "broken-ds.xml").write_text("<not xml")
    idx = content.build_index(cdir)
    assert idx["files"]["local/broken-ds.xml"]["error"].startswith("unparseable")
    cat = content.catalogue(idx)
    assert len(cat) == 1
    e = cat[0]
    assert e["benchmarkId"] == TEST_BENCHMARK and e["title"] == "Posture Pack Test Benchmark"
    assert e["version"] == "V1R1" and e["rules"] == 3 and e["source"] == "custom"
    assert e["profiles"] == [{"id": TEST_PROFILE, "title": "Test STIG profile", "version": ""}]
    assert e["releaseInfo"].startswith("Release: 1")
    assert content.find_content(cat, ["nope*.xml", "posture-*.xml"], ["missing", TEST_PROFILE]) == (e, TEST_PROFILE)
    assert content.find_content(cat, ["posture-*.xml"], ["missing"]) == (e, TEST_PROFILE)  # first profile
    assert content.find_content(cat, ["ssg-*.xml"], [TEST_PROFILE]) is None
    # unchanged files are not re-parsed
    again = content.build_index(cdir)
    assert again["files"]["local/posture-test-ds.xml"] == idx["files"]["local/posture-test-ds.xml"]


def test_rule_metadata_ids_ccis_and_cache(tmp_path):
    rules = content.rule_metadata(tmp_path, TEST_DS, "abc", TEST_BENCHMARK)
    b = rules["xccdf_test.posture_rule_banner"]
    assert (b["vulnId"], b["svId"], b["stigId"], b["cci"], b["severity"]) == (
        "V-90001", "SV-90001r1_rule", "TEST-01-000010", ["CCI-000048"], "high")
    assert b["fixText"] == "Put the DoD banner in /etc/issue." and b["srg"] == ["SRG-OS-000023-GPOS-00006"]
    assert rules["xccdf_test.posture_rule_no_rhosts"]["nist"] == ["CM-6"]
    assert list((tmp_path / "rules").glob("abc-*.json"))
    cached = json.loads(next((tmp_path / "rules").glob("abc-*.json")).read_text())
    assert cached == rules


def test_refresh_offline_never_fetches(tmp_path):
    cdir = tmp_path / "c"
    (cdir / "local").mkdir(parents=True)
    shutil.copy(TEST_DS, cdir / "local" / "x-ds.xml")
    res = content.refresh(cdir, [content.Source("ssg", "https://invalid.example/x.zip", "1" * 64)], offline=True)
    assert res.errors == {} and res.fetched == [] and len(content.catalogue(res.index)) == 1
    res = content.refresh(cdir, [content.Source("bad", "ftp://x/y.zip", "1" * 64)])
    assert "bad" in res.errors and len(content.catalogue(res.index)) == 1


def test_parse_sources_validation():
    srcs = content.parse_sources([{"url": "https://h/ssg.zip", "sha256": "SHA256:" + "A" * 64}],
                                 ["https://h/U_RHEL_9_V2R5_STIG_SCAP_1-3_Benchmark.zip"])
    assert srcs[0].sha256 == "a" * 64 and srcs[0].kind == "ssg" and srcs[1].kind == "disa"
    assert srcs[1].name == "U_RHEL_9_V2R5_STIG_SCAP_1-3_Benchmark.zip"
    with pytest.raises(content.ContentError):
        content.parse_sources([{"name": "../x", "url": "https://h/a", "sha256": "1" * 64}])
    with pytest.raises(content.ContentError, match="duplicate"):
        content.parse_sources([{"name": "a", "url": "https://h/a"}, {"name": "a", "url": "https://h/b"}])
