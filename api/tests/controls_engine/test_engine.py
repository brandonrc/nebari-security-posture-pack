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
                                 Requirement("PE-3", "facility", inherited=True),
                                 Requirement("SC-28", "declared only"))),
}


def statuses(outcomes, **kw):
    asserts = [assertion("a1"), assertion("a2"), assertion("a3", ("SC-8",))]
    rows = derive_statuses(outcomes, components=COMPS, assertions=asserts, **kw)
    return {r.control: r for r in rows}


def test_all_pass_implemented():
    s = statuses([outcome("a1", "pass"), outcome("a2", "pass")])
    assert s["AC-7"].status == "implemented" and s["AC-7"].score == 1.0 and s["AC-7"].components == ["x"]
    assert s["AC-7"].assertions == ["a1", "a2"] and s["AC-7"].in_baseline and s["AC-7"].family == "AC"


def test_some_pass_partial_all_fail_not_implemented_and_unknown():
    assert statuses([outcome("a1", "pass"), outcome("a2", "fail")])["AC-7"].status == "partial"
    assert statuses([outcome("a1", "pass"), outcome("a2", "unknown")])["AC-7"].status == "partial"
    assert statuses([outcome("a1", "fail"), outcome("a2", "fail")])["AC-7"].status == "not-implemented"
    assert statuses([outcome("a1", "fail"), outcome("a2", "unknown")])["AC-7"].status == "not-implemented"
    assert statuses([outcome("a1", "unknown"), outcome("a2", "unknown")])["AC-7"].status == "unknown"


def test_not_applicable_results_and_tailoring():
    s = statuses([outcome("a1", "not-applicable"), outcome("a2", "not-applicable")])
    assert s["AC-7"].status == "not-applicable"
    s = statuses([outcome("a1", "fail")], not_applicable={"ac-7": "no interactive logins"})
    assert s["AC-7"].status == "not-applicable" and "no interactive logins" in s["AC-7"].detail
    # n/a results are ignored when others are evaluated
    assert statuses([outcome("a1", "pass"), outcome("a2", "not-applicable")])["AC-7"].status == "implemented"


def test_never_evaluated_is_unknown():
    s = statuses([])
    assert s["AC-7"].status == "unknown" and "not evaluated" in s["AC-7"].detail
    assert s["SC-8"].status == "unknown"


def test_inherited_declared_uncovered():
    s = statuses([outcome("a1", "pass"), outcome("a2", "pass"), outcome("a3", "pass", ("SC-8",))])
    assert s["PE-3"].status == "inherited" and "facility" in s["PE-3"].detail
    assert s["SC-28"].status == "unknown" and "manual evidence" in s["SC-28"].detail
    # organization-level controls without coverage are inherited (common controls) unless disabled
    assert s["AT-2"].status == "inherited"
    assert statuses([], inherit_organizational=False)["AT-2"].status == "not-implemented"
    # system-level control nobody addresses
    assert s["SC-39"].status == "not-implemented"


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
    assert ac["title"] == "Access Control" and ac["partial"] >= 1
    assert ac["total"] == sum(ac[k] for k in ("implemented", "partial", "notImplemented", "inherited",
                                              "notApplicable", "unknown"))
    assert sum(f["total"] for f in fam.values()) == len(get_catalog().baseline("moderate"))
    sm = summarize(rows, outs, "moderate")
    assert sm["controls"] == 287 and sm["assertions"] == {"pass": 2, "fail": 1, "unknown": 0, "not-applicable": 0}
    # dict input (API rows) works too
    assert family_rollup([{"family": "AC", "status": "implemented", "inBaseline": True}])[0]["implemented"] == 1


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
    for c in ("AC-7", "IA-2(1)", "SC-8", "SC-7(5)", "RA-5", "CM-8", "AU-2"):
        assert by[c].status == "implemented", c


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
