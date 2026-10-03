"""OSCAL 1.1.2 SSP / component-definition validated against the official NIST JSON schemas
(fixtures/oscal_{ssp,component}_schema.json from usnistgov/OSCAL release v1.1.2)."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from pathlib import Path

import jsonschema
import pytest

from posture.controls_engine.engine import derive_statuses, run_assertions
from posture.controls_engine.ssp import build_component_definition, build_ssp
from posture.reports.registry import REPORT_TYPES, generate

from .fakes import good_world, make_ctx

FIXTURES = Path(__file__).parent / "fixtures"


def _fix_patterns(node):
    """OSCAL token patterns use \\p{L}/\\p{N}, unsupported by Python `re`: translate them."""
    if isinstance(node, dict):
        return {k: (v.replace(r"\p{L}", r"[^\W\d_]").replace(r"\p{N}", r"\d") if k == "pattern" and isinstance(v, str)
                    else _fix_patterns(v)) for k, v in node.items()}
    if isinstance(node, list):
        return [_fix_patterns(v) for v in node]
    return node


def _validator(name: str, suffix: str):
    schema = _fix_patterns(json.loads((FIXTURES / name).read_text()))
    assert schema["$id"].endswith(f"/1.1.2/{suffix}")
    cls = jsonschema.validators.validator_for(schema)
    cls.check_schema(schema)
    return cls(schema, format_checker=cls.FORMAT_CHECKER)


@pytest.fixture(scope="module")
def ssp_validator():
    return _validator("oscal_ssp_schema.json", "oscal-ssp-schema.json")


@pytest.fixture(scope="module")
def comp_validator():
    return _validator("oscal_component_schema.json", "oscal-component-definition-schema.json")


def _errors(v, doc):
    return [f"{'/'.join(map(str, e.absolute_path))}: {e.message[:200]}" for e in v.iter_errors(doc)]


async def engine_data(world=None):
    world = world or good_world()
    outs = await run_assertions(make_ctx(world))
    rows = derive_statuses(outs)
    return {"run": {"id": 3, "baseline": "moderate", "finishedAt": "2026-10-03T00:00:00Z"},
            "results": [o.as_dict() for o in outs],
            "statuses": [{"control": r.control, "id": r.id, "family": r.family, "baseline": r.baseline,
                          "inBaseline": r.in_baseline, "status": r.status, "components": r.components,
                          "assertions": r.assertions, "detail": r.detail, "score": r.score} for r in rows]}


async def test_ssp_validates_and_carries_statuses(ssp_validator):
    w = good_world()
    w["keycloak"][""]["failureFactor"] = 30  # AC-7 fails
    data = await engine_data(w)
    doc = build_ssp(data, system_name="grace", organization="Quansight", baseline="moderate",
                    generated_at=datetime(2026, 10, 3, tzinfo=UTC))
    assert _errors(ssp_validator, doc) == []
    ssp = doc["system-security-plan"]
    assert ssp["import-profile"]["href"].endswith("NIST_SP-800-53_rev5_MODERATE-baseline_profile.json")
    reqs = {r["control-id"]: r for r in ssp["control-implementation"]["implemented-requirements"]}
    assert len([r for r in reqs.values() if not any(p["name"] == "in-selected-baseline" for p in r["props"])]) == 287

    def status(cid):
        return next(p["value"] for p in reqs[cid]["props"] if p["name"] == "implementation-status")

    assert status("ac-7") == "failing" and status("ia-2.1") == "passing" and status("cm-8") == "hybrid"
    ac7 = reqs["ac-7"]
    # M2: failing is `planned` only when a POA&M item tracks it
    assert ac7["by-components"][0]["implementation-status"]["state"] == "not-implemented"
    with_poam = build_ssp(data, system_name="grace", generated_at=datetime(2026, 10, 3, tzinfo=UTC),
                          poam_controls={"AC-7"})
    ac7p = next(r for r in with_poam["system-security-plan"]["control-implementation"]["implemented-requirements"]
                if r["control-id"] == "ac-7")
    assert ac7p["by-components"][0]["implementation-status"]["state"] == "planned"
    link = ac7["links"][0]
    assert link["rel"] == "evidence" and link["text"] == "kc-brute-force-protection"
    res = {r["uuid"]: r for r in ssp["back-matter"]["resources"]}
    ev = res[link["href"][1:]]
    payload = json.loads(base64.b64decode(ev["base64"]["value"]))
    assert payload["status"] == "fail" and payload["evidence"]["failureFactor"] == 30
    # M1: nothing is inherited without a configured provider; org-level controls carry no OSCAL state
    this = next(c["uuid"] for c in ssp["system-implementation"]["components"] if c["type"] == "this-system")
    at2 = reqs["at-2"]["by-components"][0]
    assert at2["component-uuid"] == this and status("at-2") == "not-assessed"
    assert "implementation-status" not in at2
    assert not any(status(c) == "inherited" for c in reqs)
    pe3 = reqs["pe-3"]["by-components"][0]
    assert status("pe-3") == "org-provided-unverified" and "implementation-status" not in pe3
    assert "leveraged-authorizations" not in ssp["system-implementation"]
    # hybrid controls export the program's residual responsibility (CRM in OSCAL)
    ac2 = reqs["ac-2"]["by-components"][0]
    assert status("ac-2") == "partial" and ac2["implementation-status"]["state"] == "partial"
    assert "AC-2 a-l" in ac2["export"]["responsibilities"][0]["description"]
    # deterministic
    again = build_ssp(data, system_name="grace", organization="Quansight", generated_at=datetime(2026, 10, 3, tzinfo=UTC))
    assert again == doc


def test_ssp_without_engine_run_and_other_baselines(ssp_validator):
    for b in ("low", "moderate", "high"):
        doc = build_ssp(None, system_name="x", baseline=b, organization_statement="Org policy covers it.",
                        inherit_organizational=True)
        assert _errors(ssp_validator, doc) == []
        ssp = doc["system-security-plan"]
        assert "back-matter" not in ssp and "has not run" in ssp["control-implementation"]["description"]
        at1 = next(r for r in ssp["control-implementation"]["implemented-requirements"] if r["control-id"] == "at-1")
        assert at1["by-components"][0]["description"] == "Org policy covers it."
    with pytest.raises(ValueError):
        build_ssp(None, baseline="extreme")


async def test_ssp_leveraged_authorization_for_inherited_controls(ssp_validator):
    ccp = {"name": "DC-1 hosting", "controls": ["PE-3", "AT-2"], "authorizationRef": "eMASS 4242",
           "dateAuthorized": "2026-01-15", "statement": "Badge access and guards."}
    doc = build_ssp(None, system_name="x", providers=[ccp])
    assert _errors(ssp_validator, doc) == []
    ssp = doc["system-security-plan"]
    la = ssp["system-implementation"]["leveraged-authorizations"][0]
    assert la["date-authorized"] == "2026-01-15" and la["title"] == "DC-1 hosting authorization"
    assert any(p["uuid"] == la["party-uuid"] for p in ssp["metadata"]["parties"])
    reqs = {r["control-id"]: r for r in ssp["control-implementation"]["implemented-requirements"]}
    bc = reqs["pe-3"]["by-components"][0]
    assert bc["inherited"][0]["description"] == "Badge access and guards."
    assert bc["implementation-status"]["state"] == "implemented"
    ccp_comp = next(c for c in ssp["system-implementation"]["components"] if c["title"] == "DC-1 hosting")
    assert bc["component-uuid"] == ccp_comp["uuid"]


async def test_ssp_rebaselines_a_moderate_run(ssp_validator):
    doc = build_ssp(await engine_data(), baseline="high")
    assert _errors(ssp_validator, doc) == []
    reqs = doc["system-security-plan"]["control-implementation"]["implemented-requirements"]
    assert len([r for r in reqs if not any(p["name"] == "in-selected-baseline" for p in r["props"])]) == 370


def test_component_definition_validates(comp_validator):
    doc = build_component_definition(organization="Org")
    assert _errors(comp_validator, doc) == []
    comps = {c["title"]: c for c in doc["component-definition"]["components"]}
    kc = comps["Keycloak"]["control-implementations"][0]
    assert kc["source"].endswith("NIST_SP-800-53_rev5_catalog.json")
    ac7 = next(r for r in kc["implemented-requirements"] if r["control-id"] == "ac-7")
    assert {"name": "assertion", "ns": "https://nebari.dev/ns/oscal", "value": "kc-brute-force-protection"} in ac7[
        "props"]


SNAPSHOT = {"generated_at": "2026-10-03T00:00:00Z", "system": {"name": "grace", "organization": "Org"},
            "scan": {"id": 42, "finished_at": "2026-10-03T00:00:00Z"}}


async def test_report_generators(ssp_validator, comp_validator):
    types = {t["type"]: t for t in REPORT_TYPES}
    assert types["oscal-ssp"]["formats"] == ["json"] and types["oscal-component-definition"]["formats"] == ["json"]
    snap = {**SNAPSHOT, "controls_engine": {"data": await engine_data(), "baseline": "moderate",
                                            "organizationStatement": "", "notApplicable": {}}}
    rep = generate("oscal-ssp", "json", snap, {})
    assert rep.filename == "grace-oscal-ssp-scan42-20261003.json" and rep.content_type == "application/json"
    assert _errors(ssp_validator, json.loads(rep.content)) == []
    rep = generate("oscal-ssp", "json", SNAPSHOT, {"baseline": "low"})  # no engine data attached
    assert _errors(ssp_validator, json.loads(rep.content)) == []
    rep = generate("oscal-component-definition", "json", SNAPSHOT, {})
    assert rep.filename.startswith("grace-oscal-component-definition-scan42")
    assert _errors(comp_validator, json.loads(rep.content)) == []


def test_ssp_imports_the_selected_profile(ssp_validator):
    doc = build_ssp(None, system_name="x", baseline="fedramp-moderate-rev5")
    assert _errors(ssp_validator, doc) == []
    ssp = doc["system-security-plan"]
    assert ssp["import-profile"]["href"].endswith("FedRAMP_rev5_MODERATE-baseline_profile.json")
    reqs = ssp["control-implementation"]["implemented-requirements"]
    assert len([r for r in reqs if not any(p["name"] == "in-selected-baseline" for p in r["props"])]) == 323
    doc = build_ssp(None, system_name="x", baseline="cnssi-1253-mod-mod-mod")
    assert _errors(ssp_validator, doc) == []
    ssp = doc["system-security-plan"]
    ref = ssp["import-profile"]["href"]
    assert ref.startswith("#") and any(r["uuid"] == ref[1:] and "APPROXIMATION" in r["description"]
                                       for r in ssp["back-matter"]["resources"])
