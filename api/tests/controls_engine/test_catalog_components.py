from __future__ import annotations

from posture.controls_engine.assertions import all_assertions
from posture.controls_engine.catalog import CATALOG_FILE, get_catalog, to_label, to_oscal_id
from posture.controls_engine.components import load_components


def test_label_conversions():
    assert to_oscal_id("SI-2(2)") == "si-2.2" and to_oscal_id("ac-6.10") == "ac-6.10" and to_oscal_id("AC-6") == "ac-6"
    assert to_label("si-2.2") == "SI-2(2)" and to_label("AC-6(10)") == "AC-6(10)" and to_label("ra-5") == "RA-5"


def test_catalog_trimmed_and_baselines():
    assert CATALOG_FILE.stat().st_size < 1_000_000
    cat = get_catalog()
    assert cat.meta["version"].startswith("5.") and len(cat.families) == 20
    assert (len(cat.baseline("low")), len(cat.baseline("moderate")), len(cat.baseline("high"))) == (149, 287, 370)
    ac2 = cat.get("AC-2(1)")
    assert ac2.title == "Automated System Account Management" and ac2.parent == "ac-2"
    assert ac2.full_title.startswith("Account Management | ") and ac2.lowest_baseline == "moderate"
    assert cat.get("AC-7").baselines == ("low", "moderate", "high")
    assert cat.get("SC-12(1)").lowest_baseline == "high"
    assert cat.get("AC-2(10)").withdrawn and not cat.list(family="ac", include_withdrawn=False)[0].withdrawn


def test_components_consistent_with_catalog_and_assertions():
    comps = load_components()
    assert {"keycloak", "envoy-gateway", "cert-manager", "nebari-operator", "loki", "prometheus", "kubernetes",
            "container-registry", "security-posture"} <= set(comps)
    assert len({c.uuid for c in comps.values()}) == len(comps)
    cat = get_catalog()
    ids = {a.id: a for a in all_assertions()}
    for comp in comps.values():
        for req in comp.requirements:
            c = cat.get(req.control)
            assert c is not None and not c.withdrawn, req.control
            assert req.statement
            assert req.responsibility == "org" or req.assertions, f"{comp.id} {req.control}: no assertion"
            # CRM (S6): every non-provider requirement says what the consuming program must still do
            assert req.responsibility == "provider" or req.customer, f"{comp.id} {req.control}: no customer text"
            for a in req.assertions:
                assert a in ids, f"{comp.id}: unknown assertion {a}"
                assert req.control in ids[a].controls, f"{comp.id} {req.control}: {a} does not list the control"
    for a in ids.values():
        assert a.component in comps, a.id
        for c in a.controls:
            assert cat.get(c) is not None and not cat.get(c).withdrawn, (a.id, c)
        # the assertion's component declares every control the assertion proves
        declared = {r.control for r in comps[a.component].requirements if a.id in r.assertions}
        assert set(a.controls) <= declared, (a.id, set(a.controls) - declared)


def test_every_assertion_tags_valid_objectives_for_each_control():
    """M2: objective coverage needs each assertion to name the 800-53A objectives it evidences."""
    from posture.controls_engine.catalog import objective_control

    cat = get_catalog()
    for a in all_assertions():
        assert a.objectives, a.id
        ctl_ids = {cat.get(c).id for c in a.controls}
        tagged = {objective_control(o) for o in a.objectives}
        assert tagged == ctl_ids, (a.id, tagged ^ ctl_ids)
        for o in a.objectives:
            assert cat.get(objective_control(o)).expand_objectives([o]), (a.id, o)


def test_catalog_carries_objectives_statements_and_params():
    cat = get_catalog()
    si2 = cat.get("SI-2")
    assert si2.objectives[:3] == ("si-2_obj.a-1", "si-2_obj.a-2", "si-2_obj.a-3") and len(si2.objectives) == 10
    assert si2.statements == ("si-2_smt.a", "si-2_smt.b", "si-2_smt.c", "si-2_smt.d")
    assert si2.params == (("si-02_odp", "time period"),)
    assert cat.get("AC-3").objective_ids == ("ac-3_obj",)
