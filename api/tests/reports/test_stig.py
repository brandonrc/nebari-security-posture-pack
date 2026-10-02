import json
import re
import xml.etree.ElementTree as ET

import pytest

from conftest import CHECKS, make_snapshot
from posture.reports.registry import generate
from posture.reports.stig import load_mapping, stig_rollup

K8S_RULES = 92
SRG_RULES = 13


def _ckl(snapshot, opts, **o):
    rep = generate("stig-checklist", "ckl", snapshot, {**opts, **o})
    assert rep.content.startswith(b'<?xml version="1.0" encoding="UTF-8"?>\n<!--DISA STIG Viewer :: 2.')
    return ET.fromstring(rep.content)


def _status(root):
    out = {}
    for v in root.iter("VULN"):
        attrs = {sd.findtext("VULN_ATTRIBUTE"): sd.findtext("ATTRIBUTE_DATA") for sd in v.findall("STIG_DATA")}
        out[attrs["Vuln_Num"]] = (v.findtext("STATUS"), v.findtext("FINDING_DETAILS"), attrs)
    return out


def test_mapping_integrity():
    m = load_mapping()
    rules = m["rules"]
    ids = [r["vulnId"] for r in rules]
    assert len(ids) == len(set(ids))
    assert sum(r["benchmark"] == "kubernetes" for r in rules) == K8S_RULES
    assert sum(r["benchmark"] == "container-platform-srg" for r in rules) == SRG_RULES
    known = {c[0] for c in CHECKS}
    for r in rules:
        assert re.fullmatch(r"V-\d{6}", r["vulnId"])
        assert re.fullmatch(r"SV-\d+r\d+_rule", r["ruleId"])
        assert r["severity"] in ("high", "medium", "low") and r["cat"] in ("I", "II", "III")
        assert r["verified"] is True
        assert r["ruleTitle"] and r["checkContent"] and r["fixText"]
        assert set(r["evaluation"].get("checks", [])) <= known
    for b in m["benchmarks"]:
        assert b["referenceIdentifier"] and b["releaseInfo"].startswith("Release:")
    # every posture check maps to at least one rule
    mapped = {c for r in rules for c in r["evaluation"].get("checks", [])}
    assert mapped == known


def test_ckl_structure(snapshot, opts):
    root = _ckl(snapshot, opts)
    assert root.tag == "CHECKLIST"
    assert [c.tag for c in root] == ["ASSET", "STIGS"]
    asset = root.find("ASSET")
    assert [c.tag for c in asset] == ["ROLE", "ASSET_TYPE", "MARKING", "HOST_NAME", "HOST_IP", "HOST_MAC", "HOST_FQDN",
                                      "TARGET_COMMENT", "TECH_AREA", "TARGET_KEY", "WEB_OR_DATABASE", "WEB_DB_SITE",
                                      "WEB_DB_INSTANCE"]
    assert asset.findtext("HOST_NAME") == "security.100-89-230-107.sslip.io"
    assert asset.findtext("TARGET_KEY") == "5376"
    istigs = root.findall("STIGS/iSTIG")
    assert len(istigs) == 2
    info = {si.findtext("SID_NAME"): si.findtext("SID_DATA") for si in istigs[0].findall("STIG_INFO/SI_DATA")}
    assert info["stigid"] == "Kubernetes_STIG" and info["version"] == "2"
    assert info["releaseinfo"].startswith("Release: 6")
    assert len(istigs[0].findall("VULN")) == K8S_RULES and len(istigs[1].findall("VULN")) == SRG_RULES
    v = istigs[0].find("VULN")
    names = [sd.findtext("VULN_ATTRIBUTE") for sd in v.findall("STIG_DATA")]
    assert names[:6] == ["Vuln_Num", "Severity", "Group_Title", "Rule_ID", "Rule_Ver", "Rule_Title"]
    assert names[-1] == "CCI_REF" and names.count("LEGACY_ID") == 2
    assert [c.tag for c in v if c.tag != "STIG_DATA"] == ["STATUS", "FINDING_DETAILS", "COMMENTS",
                                                          "SEVERITY_OVERRIDE", "SEVERITY_JUSTIFICATION"]
    for vv in root.iter("VULN"):
        assert vv.findtext("STATUS") in ("NotAFinding", "Open", "Not_Reviewed", "Not_Applicable")


def test_ckl_statuses(snapshot, opts):
    st = _status(_ckl(snapshot, opts))
    assert st["V-242383"][0] == "Open" and "default/Deployment/legacy-proxy" in st["V-242383"][1]
    assert st["V-242417"][0] == "Not_Reviewed" and "coredns" in st["V-242417"][1]
    assert st["V-233127"][0] == "Open" and "privileged" in st["V-233127"][1]
    assert st["V-270876"][0] == "Open"
    assert st["V-254800"][0] == "Open"
    assert st["V-233233"][0] == "Open"   # fixable vulns present
    assert st["V-233234"][0] == "Open"   # fixable vulns older than 30 days
    assert st["V-233275"][0] == "NotAFinding"
    assert st["V-242376"][0] == "Not_Reviewed"  # control-plane TLS flag: not evaluated
    assert st["V-242414"][0] == "Not_Reviewed"
    assert st["V-242414"][2]["Rule_Ver"] == "CNTR-K8-000960"
    counts = {}
    for s, *_ in st.values():
        counts[s] = counts.get(s, 0) + 1
    assert counts["Not_Reviewed"] > 80


def test_scoped_checklist_passes(opts):
    snap = make_snapshot(scope={"kind": "workload", "name": "security-posture/StatefulSet/postgres"})
    st = _status(_ckl(snap, opts))
    assert st["V-233127"][0] == "NotAFinding"
    assert st["V-270875"][0] == "NotAFinding"
    assert st["V-242383"][0] == "NotAFinding"
    assert st["V-233029"][0] == "Not_Reviewed"  # pass -> needs manual review of policy content


def test_include_srg_false(snapshot, opts):
    root = _ckl(snapshot, opts, includeSrg=False)
    assert len(root.findall("STIGS/iSTIG")) == 1


def test_cklb_structure(snapshot, opts):
    rep = generate("stig-checklist", "cklb", snapshot, opts)
    d = json.loads(rep.content)
    assert {"title", "id", "stigs", "target_data", "cklb_version"} <= set(d)
    assert d["cklb_version"] == "1.0"
    assert d["target_data"]["target_type"] == "Computing"
    assert d["target_data"]["host_name"] == "security.100-89-230-107.sslip.io"
    assert [s["stig_id"] for s in d["stigs"]] == ["Kubernetes_STIG", "Container_Platform_SRG"]
    k8s = d["stigs"][0]
    assert k8s["size"] == len(k8s["rules"]) == K8S_RULES
    required = {"uuid", "stig_uuid", "group_id", "rule_id", "rule_id_src", "rule_version", "severity", "group_title",
                "rule_title", "discussion", "check_content", "fix_text", "status", "finding_details", "comments",
                "ccis", "legacy_ids", "group_tree", "check_content_ref", "weight", "classification", "overrides"}
    statuses = set()
    uuids = set()
    for s in d["stigs"]:
        for r in s["rules"]:
            assert required <= set(r)
            assert r["stig_uuid"] == s["uuid"]
            assert not r["rule_id"].endswith("_rule") and r["rule_id_src"].endswith("_rule")
            statuses.add(r["status"])
            uuids.add(r["uuid"])
    assert statuses <= {"not_a_finding", "open", "not_reviewed", "not_applicable"}
    assert {"open", "not_reviewed", "not_a_finding"} <= statuses
    assert len(uuids) == K8S_RULES + SRG_RULES
    # deterministic
    assert generate("stig-checklist", "cklb", snapshot, opts).content == rep.content


def test_rollup_api_helper(snapshot, opts):
    roll = stig_rollup(snapshot, opts)
    assert len(roll) == K8S_RULES + SRG_RULES
    r = next(x for x in roll if x["vulnId"] == "V-242383")
    assert r["status"] == "Open" and r["offenders"] == ["default/Deployment/legacy-proxy"]
    assert {"vulnId", "ruleId", "title", "cat", "status", "offenders"} <= set(r)


@pytest.mark.parametrize("fmt", ["ckl", "cklb"])
def test_empty_snapshot(fmt, opts):
    snap = make_snapshot(images=[], findings=[], workloads=[], posture_results=[])
    rep = generate("stig-checklist", fmt, snap, opts)
    assert rep.content
