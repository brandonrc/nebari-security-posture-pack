import json
from pathlib import Path

import jsonschema
import pytest

from conftest import make_snapshot
from posture.reports.oscal import control_id
from posture.reports.registry import generate

SCHEMA = Path(__file__).parent / "fixtures" / "oscal_assessment-results_schema.json"


def _fix_patterns(node):
    """OSCAL token patterns use \\p{L}/\\p{N}, unsupported by Python `re`: translate them."""
    if isinstance(node, dict):
        return {k: (v.replace(r"\p{L}", r"[^\W\d_]").replace(r"\p{N}", r"\d") if k == "pattern" and isinstance(v, str)
                    else _fix_patterns(v)) for k, v in node.items()}
    if isinstance(node, list):
        return [_fix_patterns(v) for v in node]
    return node


@pytest.fixture(scope="module")
def validator():
    schema = _fix_patterns(json.loads(SCHEMA.read_text()))
    assert schema["$id"].endswith("/1.1.2/oscal-ar-schema.json")
    cls = jsonschema.validators.validator_for(schema)
    cls.check_schema(schema)
    return cls(schema, format_checker=cls.FORMAT_CHECKER)


def _errors(validator, doc):
    return [f"{'/'.join(map(str, e.absolute_path))}: {e.message[:200]}" for e in validator.iter_errors(doc)]


def test_validates_against_official_schema(snapshot, opts, validator):
    doc = json.loads(generate("oscal-ar", "json", snapshot, opts).content)
    assert _errors(validator, doc) == []


def test_content(snapshot, opts):
    ar = json.loads(generate("oscal-ar", "json", snapshot, opts).content)["assessment-results"]
    assert ar["metadata"]["oscal-version"] == "1.1.2"
    titles = [c["title"] for c in ar["results"][0]["local-definitions"]["components"]]
    assert {"Trivy", "Grype", "Clair"} <= set(titles)
    (res,) = ar["results"]
    n_findings = len([f for f in snapshot.findings])
    failing = {r.check_id for r in snapshot.posture_results if r.status == "fail"}
    assert len(res["observations"]) == n_findings + len(failing)
    assert len(res["risks"]) == len({f.vuln_id for f in snapshot.findings}) + len(failing)
    by_target = {f["target"]["target-id"]: f for f in res["findings"]}
    assert by_target["ra-5_smt"]["target"]["status"]["state"] == "not-satisfied"
    assert by_target["si-2.2_smt"]["related-risks"]
    assert "ac-6.10_smt" in by_target
    risk = next(r for r in res["risks"] if r["title"].startswith("CVE-2024-6387"))
    assert risk["deadline"].startswith("2026-09-06")  # first seen 2026-08-22 + 15 days
    obs_ids = {o["uuid"] for o in res["observations"]}
    for r in res["risks"]:
        assert {x["observation-uuid"] for x in r["related-observations"]} <= obs_ids
    inv = {i["uuid"] for i in res["local-definitions"]["inventory-items"]}
    for o in res["observations"]:
        for s in o.get("subjects", []):
            assert s["subject-uuid"] in inv


def test_scoped_and_empty_validate(opts, validator):
    for snap in (make_snapshot(scope={"kind": "namespace", "name": "dev"}),
                 make_snapshot(images=[], findings=[], workloads=[], posture_results=[], scanners=[], trend=[])):
        doc = json.loads(generate("oscal-ar", "json", snap, opts).content)
        assert _errors(validator, doc) == []


def test_control_ids():
    assert control_id("SI-2(2)") == "si-2.2"
    assert control_id("AC-6(10)") == "ac-6.10"
    assert control_id("RA-5") == "ra-5"
