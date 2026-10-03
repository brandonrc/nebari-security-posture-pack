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
    assert cat.get("AC-7").baselines == ("low", "moderate", "high", "fedramp-moderate-rev5", "cnssi-1253-mod-mod-mod")
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


def test_extra_profiles_and_cited_odp_sets():
    """M7: FedRAMP Rev5 Moderate and the CNSSI 1253 M-M-M approximation, each with cited ODPs."""
    from posture.controls_engine.catalog import BASELINES, odp_profile

    cat = get_catalog()
    assert len(cat.baseline("fedramp-moderate-rev5")) == 323
    mod = {c.label for c in cat.baseline("moderate")}
    fed = {c.label for c in cat.baseline("fedramp-moderate-rev5")}
    assert mod <= fed and {"CA-8", "SC-45", "SI-4(16)", "RA-5(3)"} <= fed - mod
    cnssi = {c.label for c in cat.baseline("cnssi-1253-mod-mod-mod")}
    assert mod <= cnssi and "AC-6(8)" in cnssi and "CM-14" in cnssi
    assert not cat.profiles["cnssi-1253-mod-mod-mod"]["exact"] and "APPROXIMATION" in \
        cat.profiles["cnssi-1253-mod-mod-mod"]["provenance"]
    assert cat.get("CA-8").lowest_baseline == "high"  # NIST baselines only
    assert set(BASELINES) == {"low", "moderate", "high", "fedramp-moderate-rev5", "cnssi-1253-mod-mod-mod"}
    for b in BASELINES:
        odp = odp_profile(b)
        assert {"maxLoginFailures", "minPasswordLength", "minLogRetentionDays", "requireAdminRelease"} <= set(odp)
        assert all(v["source"] for v in odp.values()), b
    assert odp_profile("moderate")["minLogRetentionDays"]["value"] == 365  # M-21-31, not the rev4-era 90 days
    assert "M-21-31" in odp_profile("fedramp-moderate-rev5")["minLogRetentionDays"]["source"]
    assert odp_profile("cnssi-1253-mod-mod-mod")["minPasswordLength"]["value"] == 15
    assert odp_profile("cnssi-1253-mod-mod-mod")["requireAdminRelease"]["value"] is True


def test_parameters_default_to_the_profile_and_explicit_values_win():
    from posture import app_settings
    from posture.config import Settings
    from posture.controls_engine import engine

    env = Settings()
    st = app_settings.defaults(env)
    st.controls_engine.baseline = "cnssi-1253-mod-mod-mod"
    cfg = engine.engine_config(env, st)
    assert cfg.min_password_length == 15 and cfg.require_admin_release and cfg.min_log_retention_days == 365
    st.controls_engine.parameters.min_password_length = 20
    assert engine.engine_config(env, st).min_password_length == 20
    st.controls_engine.baseline = "moderate"
    st.controls_engine.parameters.min_password_length = None
    cfg = engine.engine_config(env, st)
    assert cfg.min_password_length == 15 and not cfg.require_admin_release and cfg.min_lockout_seconds == 1800
