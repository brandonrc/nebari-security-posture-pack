"""VEX-suppressed findings in the reports: listed with their justification in the
vulnerability exports (csv / json / CycloneDX VEX), absent from POA&M and SAR as open items."""

from __future__ import annotations

import csv
import io
import json

from conftest import make_snapshot, snapshot_data
from posture.reports.registry import generate

SUPPRESSED = ("CVE-2024-24790", 3)  # stdlib in images 3 and 4: suppressed in image 3 only
DETAIL = "The image's Go binaries are built with go1.22.5; stdlib 1.21.5 is a stale SBOM entry."


def _snap():
    data = snapshot_data()
    for f in data["findings"]:
        if (f["vuln_id"], f["image_id"]) == SUPPRESSED:
            f.update(status="not_affected", vex_status="not_affected",
                     vex_justification="vulnerable_code_not_present", vex_source="site.vex.json (urn:x)",
                     vex_detail=DETAIL)
        if f["vuln_id"] == "CVE-2023-39325":
            f.update(vex_status="under_investigation", vex_source="site.vex.json (urn:x)", vex_detail="checking")
    return make_snapshot(**{k: v for k, v in data.items()})


def test_vuln_csv_and_json_list_suppressed_with_justification(opts):
    snap = _snap()
    rows = list(csv.DictReader(io.StringIO(generate("vuln-export", "csv", snap, opts).content.decode("utf-8-sig"))))
    sup = [r for r in rows if r["Vulnerability ID"] == SUPPRESSED[0]]
    assert len(sup) == 2
    by_status = {r["Status"]: r for r in sup}
    r = by_status["not_affected"]
    assert r["VEX Status"] == "not_affected" and r["VEX Justification"] == "vulnerable_code_not_present"
    assert r["VEX Source"].startswith("site.vex.json") and r["VEX Impact Statement"] == DETAIL
    assert r["Overdue"] == "No"
    assert by_status["open"]["VEX Status"] == ""
    inv = next(r for r in rows if r["Vulnerability ID"] == "CVE-2023-39325")
    assert inv["Status"] == "open" and inv["VEX Status"] == "under_investigation"
    doc = json.loads(generate("vuln-export", "json", snap, opts).content)
    j = next(f for f in doc["findings"] if f["vulnId"] == SUPPRESSED[0] and f["status"] == "not_affected")
    assert j["vexJustification"] == "vulnerable_code_not_present" and j["vexDetail"] == DETAIL


def test_cyclonedx_vex_merges_applied_statements(opts):
    d = json.loads(generate("vuln-export", "cyclonedx-vex", _snap(), opts).content)
    entries = [v for v in d["vulnerabilities"] if v["id"] == SUPPRESSED[0]]
    assert len(entries) == 2 and len({v["bom-ref"] for v in entries}) == 2
    na = next(v for v in entries if v["analysis"]["state"] == "not_affected")
    assert na["analysis"]["justification"] == "code_not_present"
    assert DETAIL in na["analysis"]["detail"] and "site.vex.json" in na["analysis"]["detail"]
    assert {"name": "nebari:vexJustification", "value": "vulnerable_code_not_present"} in na["properties"]
    open_ = next(v for v in entries if v["analysis"]["state"] == "in_triage")
    assert len(na["affects"]) == 1 and len(open_["affects"]) == 1 and na["affects"] != open_["affects"]
    inv = next(v for v in d["vulnerabilities"] if v["id"] == "CVE-2023-39325")
    assert inv["analysis"]["state"] == "in_triage" and "checking" in inv["analysis"]["detail"]
    assert "justification" not in inv["analysis"]


def test_poam_and_open_findings_exclude_suppressed(opts):
    opts = {**opts, "poamGranularity": "finding"}
    base = list(csv.DictReader(io.StringIO(
        generate("poam", "csv", make_snapshot(), {**opts, "poamVariant": "generic"}).content.decode("utf-8-sig"))))
    vex = list(csv.DictReader(io.StringIO(
        generate("poam", "csv", _snap(), {**opts, "poamVariant": "generic"}).content.decode("utf-8-sig"))))
    assert len(vex) == len(base) - 1

    def n_cve(rows):
        return sum(1 for r in rows for v in r.values() if isinstance(v, str) and SUPPRESSED[0] in v)

    assert n_cve(vex) < n_cve(base)
    from posture.reports._common import normalize

    v = normalize(_snap(), opts)
    assert len(v.open_findings) == len(v.findings) - 1
    assert all(f.status == "open" for f in v.open_findings)
