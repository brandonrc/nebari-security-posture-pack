"""CCIs for SSG content (grace, 2026-10-05): SSG rules reference the DISA STIG by SV- / V- /
rule version but carry no CCIs; rule_metadata joins them to a DISA benchmark on the content volume."""

from __future__ import annotations

import json
import os
import shutil

from posture.scap import content, oscap

from .helpers import FIXTURES

SSG = FIXTURES / "ssg-cci-test-ds.xml"
DISA = FIXTURES / "U_TEST_9_V1R1_STIG_SCAP_1-3_Benchmark.xml"
SSG_BID = "xccdf_org.ssgproject.content_benchmark_TEST-9"
R = "xccdf_org.ssgproject.content_rule_"


def _volume(tmp_path, disa=True):
    cdir = tmp_path / "c"
    (cdir / "sources" / "ssg").mkdir(parents=True)
    shutil.copy(SSG, cdir / "sources" / "ssg" / SSG.name)
    if disa:
        (cdir / "sources" / "disa-test9").mkdir(parents=True)
        shutil.copy(DISA, cdir / "sources" / "disa-test9" / DISA.name)
    idx = content.build_index(cdir)
    entry = next(e for e in content.catalogue(idx) if e["benchmarkId"] == SSG_BID)
    return cdir, entry


def _meta(cdir, entry):
    return content.rule_metadata(cdir, cdir / entry["path"], entry["sha256"], entry["benchmarkId"])


def test_parse_collects_every_stig_reference():
    rules = content.parse_rules(SSG)
    r = rules[R + "sv_match"]
    assert r["stigRefs"] == {"v": ["V-100001"], "sv": ["SV-100001r2_rule"], "ver": ["TEST-09-000010"]}
    assert r["cci"] == [] and r["cciSource"] is None
    assert rules[R + "own_cci"]["cciSource"] == "content"


def test_disa_benchmark_indexed_as_disa(tmp_path):
    cdir, _ = _volume(tmp_path)
    cat = content.catalogue(content.load_index(cdir))
    assert {e["benchmarkId"]: e["source"] for e in cat} == {SSG_BID: "ssg",
                                                           "xccdf_mil.disa.stig_benchmark_TEST_9_STIG": "disa"}


def test_join_by_sv_v_and_rule_version(tmp_path):
    cdir, entry = _volume(tmp_path)
    m = _meta(cdir, entry)
    # SV- base id (SSG r2 vs DISA r5: revision ignored)
    assert m[R + "sv_match"]["cci"] == ["CCI-000366"] and m[R + "sv_match"]["cciSource"] == "disa"
    assert m[R + "sv_match"]["cciFrom"].startswith("xccdf_mil.disa.stig_benchmark_TEST_9_STIG 001.001")
    assert m[R + "v_match"]["cci"] == ["CCI-001493", "CCI-001494"]
    assert m[R + "ver_match"]["cci"] == ["CCI-000048"] and "TEST-09-000030" in m[R + "ver_match"]["cciFrom"]
    # the content's own CCI wins, no derivation
    assert m[R + "own_cci"]["cci"] == ["CCI-000999"] and m[R + "own_cci"]["cciSource"] == "content"
    # unmatched / no STIG reference: no CCI, with a note
    assert m[R + "unmatched"]["cci"] == [] and "lists this STIG id" in m[R + "unmatched"]["cciNote"]
    assert "Test Linux 9" in m[R + "unmatched"]["cciNote"]
    assert m[R + "no_stig"]["cci"] == [] and "references no DISA STIG id" in m[R + "no_stig"]["cciNote"]


def test_no_disa_on_volume_note(tmp_path):
    cdir, entry = _volume(tmp_path, disa=False)
    m = _meta(cdir, entry)
    assert all(not r["cci"] for k, r in m.items() if k != R + "own_cci")
    assert "no DISA benchmark for Guide to the Secure Configuration of Test Linux 9 is on the content volume" \
        in m[R + "sv_match"]["cciNote"]


def test_cache_keyed_by_disa_content(tmp_path):
    cdir, entry = _volume(tmp_path, disa=False)
    assert not _meta(cdir, entry)[R + "sv_match"]["cci"]
    # a DISA benchmark arrives: the derived cache key changes, the SSG file sha does not
    (cdir / "sources" / "disa-test9").mkdir(parents=True)
    shutil.copy(DISA, cdir / "sources" / "disa-test9" / DISA.name)
    content.build_index(cdir)
    assert _meta(cdir, entry)[R + "sv_match"]["cci"] == ["CCI-000366"]
    derived = list((cdir / "rules").glob(f"{entry['sha256']}-*-cci*.json"))
    assert len(derived) == 2
    # the cached copy is what is served
    newest = max(derived, key=lambda p: p.stat().st_mtime_ns)
    assert json.loads(newest.read_text())[R + "v_match"]["cci"] == ["CCI-001493", "CCI-001494"]
    # DISA benchmark updated (new sha): derived again from the new content
    p = cdir / "sources" / "disa-test9" / DISA.name
    p.write_text(p.read_text().replace("CCI-000366", "CCI-000367"))
    os.utime(p, (p.stat().st_atime, p.stat().st_mtime + 5))  # the index re-reads on size / mtime change
    content.build_index(cdir)
    assert _meta(cdir, entry)[R + "sv_match"]["cci"] == ["CCI-000367"]


def test_derived_ccis_reach_rule_results(tmp_path):
    """oscap.parse_results takes CCIs from the metadata, so scap_results.cci (and from there the
    product checklists' CCI_REF and the POA&M SP-STIG rows) carry the derived CCIs."""
    cdir, entry = _volume(tmp_path)
    m = _meta(cdir, entry)
    row = oscap._row({"idref": R + "v_match", "idents": [], "severity": "medium"}, "fail", m[R + "v_match"])
    assert row.cci == ["CCI-001493", "CCI-001494"] and row.vuln_id == "V-100002"
