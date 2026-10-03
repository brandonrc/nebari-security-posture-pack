"""Status derivation, family rollup, execution wrapper."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import pytest

from posture.controls_engine import engine
from posture.controls_engine.catalog import get_catalog
from posture.controls_engine.components import Component, Requirement
from posture.controls_engine.context import EngineConfig, EngineContext, KeycloakError
from posture.controls_engine.engine import Outcome, derive_statuses, family_rollup, run_assertions, run_one, summarize
from posture.controls_engine.model import Assertion, Result

from .fakes import good_world, make_ctx


def outcome(aid: str, status: str, controls=("AC-7",), component="keycloak") -> Outcome:
    return Outcome(id=aid, title=aid, controls=list(controls), component=component, severity="high", status=status,
                   detail=status, evidence={}, duration_ms=1, checked_at=datetime.now(UTC))


def assertion(aid: str, controls=("AC-7",), component="x") -> Assertion:
    async def ev(ctx):
        return Result("pass")

    return Assertion(id=aid, title=aid, controls=tuple(controls), component=component, severity="high", evaluate=ev)


COMPS = {
    "x": Component(id="x", uuid="00000000-0000-4000-8000-000000000001", title="X", type="software", description="d",
                   requirements=(Requirement("AC-7", "lockout", assertions=("a1", "a2")),
                                 Requirement("PE-3", "facility", responsibility="org", customer="ccp"),
                                 Requirement("SC-28", "declared only"))),
}


def statuses(outcomes, **kw):
    asserts = [assertion("a1"), assertion("a2"), assertion("a3", ("SC-8",))]
    rows = derive_statuses(outcomes, components=COMPS, assertions=asserts, **kw)
    return {r.control: r for r in rows}


def test_all_pass_passing():
    s = statuses([outcome("a1", "pass"), outcome("a2", "pass")])
    assert s["AC-7"].status == "passing" and s["AC-7"].score == 1.0 and s["AC-7"].components == ["x"]
    assert s["AC-7"].assertions == ["a1", "a2"] and s["AC-7"].in_baseline and s["AC-7"].family == "AC"
    assert [o["id"] for o in s["AC-7"].objectives] == ["ac-7_obj.a", "ac-7_obj.b"]
    assert {o["state"] for o in s["AC-7"].objectives} == {"satisfied"}


def test_some_pass_partial_all_fail_failing_and_not_assessed():
    assert statuses([outcome("a1", "pass"), outcome("a2", "fail")])["AC-7"].status == "failing"  # same objectives
    assert statuses([outcome("a1", "pass"), outcome("a2", "unknown")])["AC-7"].status == "not-assessed"
    assert statuses([outcome("a1", "fail"), outcome("a2", "fail")])["AC-7"].status == "failing"
    assert statuses([outcome("a1", "fail"), outcome("a2", "unknown")])["AC-7"].status == "failing"
    assert statuses([outcome("a1", "unknown"), outcome("a2", "unknown")])["AC-7"].status == "not-assessed"


def _tagged(aid, objectives, controls=("AC-7",)):
    async def ev(ctx):
        return Result("pass")

    return Assertion(id=aid, title=aid, controls=tuple(controls), component="x", severity="high", evaluate=ev,
                     objectives=tuple(objectives))


def test_objective_coverage_caps_at_partial():
    """M2: passing assertions that evidence one of two objectives give `partial (1 of 2)`, never passing."""
    asserts = [_tagged("a1", ["ac-7_obj.a"]), _tagged("a2", ["ac-7_obj.b"])]
    rows = {r.control: r for r in derive_statuses([outcome("a1", "pass")], components=COMPS, assertions=asserts)}
    ac7 = rows["AC-7"]
    assert ac7.status == "partial" and ac7.score == 0.5 and "1 of 2 objective(s)" in ac7.detail
    assert {o["id"]: o["state"] for o in ac7.objectives} == {"ac-7_obj.a": "satisfied",
                                                             "ac-7_obj.b": "no-evidence"}
    rows = {r.control: r for r in derive_statuses([outcome("a1", "pass"), outcome("a2", "fail")], components=COMPS,
                                                  assertions=asserts)}
    assert rows["AC-7"].status == "partial" and "1 failing" in rows["AC-7"].detail
    rows = {r.control: r for r in derive_statuses([outcome("a1", "pass"), outcome("a2", "pass")], components=COMPS,
                                                  assertions=asserts)}
    assert rows["AC-7"].status == "passing"
    # a parent objective reference covers its leaves (si-2_obj.c -> c-1, c-2)
    from posture.controls_engine.catalog import get_catalog

    assert get_catalog().get("SI-2").expand_objectives(["si-2_obj.c"]) == ["si-2_obj.c-1", "si-2_obj.c-2"]


def test_not_applicable_results_and_tailoring():
    s = statuses([outcome("a1", "not-applicable"), outcome("a2", "not-applicable")])
    assert s["AC-7"].status == "not-applicable"
    s = statuses([outcome("a1", "fail")], not_applicable={"ac-7": "no interactive logins"})
    assert s["AC-7"].status == "not-applicable" and "no interactive logins" in s["AC-7"].detail
    # n/a results are ignored when others are evaluated
    assert statuses([outcome("a1", "pass"), outcome("a2", "not-applicable")])["AC-7"].status == "passing"


def test_never_evaluated_is_not_assessed():
    s = statuses([])
    assert s["AC-7"].status == "not-assessed" and "not evaluated" in s["AC-7"].detail
    assert s["SC-8"].status == "not-assessed"


def test_org_provided_is_never_inherited_without_a_provider():
    """M1: `inherited` only with a named common control provider; NIST's implementation-level
    prop never makes a control inherited, and the org-provided assumption is off by default."""
    s = statuses([outcome("a1", "pass"), outcome("a2", "pass"), outcome("a3", "pass", ("SC-8",))])
    assert s["PE-3"].status == "org-provided-unverified" and "UNVERIFIED" in s["PE-3"].detail
    assert s["PE-3"].responsibility == "org"
    assert s["SC-28"].status == "not-assessed" and "manual evidence" in s["SC-28"].detail
    # organization-level controls: not inherited, not even org-provided by default
    assert s["AT-2"].status == "not-assessed" and s["AT-2"].responsibility == "org"
    assert statuses([], inherit_organizational=True)["AT-2"].status == "org-provided-unverified"
    assert not any(r.status == "inherited" for r in s.values())
    # system-level control nobody addresses
    assert s["SC-39"].status == "not-assessed" and s["SC-39"].responsibility == "customer"


def test_inherited_only_from_a_configured_common_control_provider():
    from posture.controls_engine.settings import CommonControlProvider

    ccp = CommonControlProvider(name="DC-1 hosting (eMASS 4242)", controls=["pe-3", "AT-2"],
                                authorization_ref="eMASS 4242, ATO 2026-01-15", date_authorized="2026-01-15",
                                statement="Badge access and guards.")
    s = statuses([], providers=[ccp])
    assert s["PE-3"].status == "inherited" and s["PE-3"].provider == "DC-1 hosting (eMASS 4242)"
    assert "eMASS 4242" in s["PE-3"].detail and s["AT-2"].status == "inherited"
    assert s["PE-6"].status != "inherited"  # not listed by the provider
    # dicts (as stored in report snapshots) work too
    assert statuses([], providers=[{"name": "X", "controls": ["PE-6"]}])["PE-6"].status == "inherited"


def test_shared_responsibility_passing_is_hybrid():
    comps = {"x": Component(id="x", uuid="00000000-0000-4000-8000-000000000001", title="X", type="software",
                            description="d", requirements=(
                                Requirement("AC-7", "lockout", assertions=("a1",), responsibility="shared",
                                            customer="program part", assigned=("rest",)),))}
    one = [_tagged("a1", ["ac-7_obj.a"])]
    rows = {r.control: r for r in derive_statuses([outcome("a1", "pass")], components=comps, assertions=one)}
    assert rows["AC-7"].status == "hybrid" and rows["AC-7"].responsibility == "shared"
    assert {o["id"]: o["state"] for o in rows["AC-7"].objectives}["ac-7_obj.b"] == "assigned"
    rows = {r.control: r for r in derive_statuses([outcome("a1", "fail")], components=comps, assertions=one)}
    assert rows["AC-7"].status == "failing"


def test_scope_baseline_plus_covered_controls():
    cat = get_catalog()
    low = statuses([], baseline="low")
    assert {c.label for c in cat.baseline("low")} <= set(low)
    assert "SC-8" in low and not low["SC-8"].in_baseline  # covered by an assertion, outside LOW
    high = derive_statuses([], baseline="high")
    assert len([r for r in high if r.in_baseline]) == len(cat.baseline("high"))


def test_rollup_and_summary():
    outs = [outcome("a1", "pass"), outcome("a2", "fail"), outcome("a3", "pass", ("SC-8",))]
    rows = derive_statuses(outs, components=COMPS, assertions=[assertion("a1"), assertion("a2"),
                                                                assertion("a3", ("SC-8",))])
    fam = {f["family"]: f for f in family_rollup(rows)}
    ac = fam["AC"]
    assert ac["title"] == "Access Control" and ac["failing"] >= 1
    assert ac["total"] == sum(ac[k] for k in engine.ROLLUP_KEYS.values())
    assert sum(f["total"] for f in fam.values()) == len(get_catalog().baseline("moderate"))
    sm = summarize(rows, outs, "moderate")
    assert sm["controls"] == 287 and sm["assertions"] == {"pass": 2, "fail": 1, "unknown": 0, "not-applicable": 0}
    # dict input (API rows) works too
    assert family_rollup([{"family": "AC", "status": "passing", "inBaseline": True}])[0]["passing"] == 1
    assert sm["objectives"]["baseline"] > sm["objectives"]["assessed"] >= sm["objectives"]["evidenced"] > 0


async def test_run_one_maps_errors_and_timeouts():
    ctx = EngineContext(config=EngineConfig())

    async def slow(ctx):
        await asyncio.sleep(5)

    async def boom(ctx):
        raise RuntimeError("bug")

    async def kc(ctx):
        raise KeycloakError("admin login failed (nebari: HTTP 401; master: HTTP 401)")

    for fn, text in ((slow, "timed out"), (boom, "assertion error: RuntimeError"), (kc, "admin login failed")):
        a = Assertion(id="t", title="t", controls=("AC-2",), component="c", severity="low", evaluate=fn)
        out = await run_one(a, ctx, 0.05)
        assert out.status == "unknown" and text in out.detail


async def test_run_assertions_all_pass_in_good_world():
    outs = await run_assertions(make_ctx(good_world()))
    assert len(outs) >= 25 and {o.status for o in outs} == {"pass"}
    rows = derive_statuses(outs)
    by = {r.control: r for r in rows}
    for c in ("AC-7", "AC-12", "RA-5(2)", "SC-23", "IA-2(1)", "SC-8", "SC-7(5)"):  # every objective evidenced
        assert by[c].status == "passing", c
    for c in ("AC-2", "RA-5", "CM-8", "AU-2"):  # platform part passes, the rest is assigned to the program
        assert by[c].status == "hybrid", c


def test_engine_config_from_settings():
    from posture import app_settings
    from posture.config import Settings

    env = Settings(controls_loki_url="http://loki:3100", mirror_registry="reg:5000", admin_groups=["/admins"])
    st = app_settings.defaults(env)
    st.controls_engine.parameters.max_login_failures = 5
    st.controls_engine.admin_subjects = ["alice"]
    cfg = engine.engine_config(env, st)
    assert cfg.loki_url == "http://loki:3100" and cfg.registry_url == "reg:5000" and cfg.max_login_failures == 5
    assert cfg.admin_subjects == ["alice"] and cfg.keycloak_admin_group == "admins" and cfg.baseline == "moderate"


def test_settings_validation_and_merge():
    from posture import app_settings

    cur = app_settings.defaults()
    new = app_settings.apply_patch(cur, {"controlsEngine": {"baseline": "high", "adminSubjects": [" alice ", "alice"],
                                                            "notApplicable": {"ac-17": "no remote access"}}})
    assert new.controls_engine.baseline == "high" and new.controls_engine.admin_subjects == ["alice"]
    assert new.controls_engine.not_applicable == {"AC-17": "no remote access"}
    with pytest.raises(Exception):
        app_settings.apply_patch(cur, {"controlsEngine": {"baseline": "extreme"}})
