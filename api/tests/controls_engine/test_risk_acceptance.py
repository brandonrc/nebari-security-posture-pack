"""Risk acceptances in the controls engine: k8s-workload-least-privilege and status derivation."""

from __future__ import annotations

from posture.controls_engine.assertions import get_assertion
from posture.controls_engine.engine import derive_statuses, run_one, summarize
from posture.controls_engine.exceptions import RiskException

from .fakes import good_world, make_ctx
from .test_engine import COMPS, assertion, outcome

LP = "k8s-workload-least-privilege"
SCAP = {"checkId": "added-capabilities", "namespace": "security-posture", "kind": "Deployment",
        "name": "security-posture-scap-worker", "severity": "high"}


def exc(**kw):
    base = dict(kind="Deployment", namespace="security-posture", name="security-posture-scap-worker",
                checks=["added-capabilities", "run-as-root"], assertions=[LP], reason="OpenSCAP needs root",
                approvedBy="pack maintainers", reviewBy="2027-04-03")
    base.update(kw)
    return RiskException.model_validate(base)


async def _run(world, exceptions):
    ctx = make_ctx(world)
    ctx.config.exceptions = exceptions
    return await run_one(get_assertion(LP), ctx, 5)


async def test_only_accepted_workload_is_accepted_risk_never_pass():
    w = good_world()
    w["snapshot"]["postureFailures"].append(dict(SCAP))
    out = await _run(w, [exc()])
    assert out.status == "accepted-risk", out.detail
    acc = out.evidence["acceptedRisk"][0]
    assert acc["workload"] == "security-posture/Deployment/security-posture-scap-worker"
    assert acc["reason"] == "OpenSCAP needs root" and acc["reviewBy"] == "2027-04-03" and acc["expiresAt"] is None
    # the posture stage already marked it accepted (postureAccepted): same outcome
    w = good_world()
    w["snapshot"]["postureAccepted"] = [dict(SCAP)]
    assert (await _run(w, [exc()])).status == "accepted-risk"


async def test_other_failures_still_fail_and_list_the_accepted_one():
    w = good_world()
    w["snapshot"]["postureFailures"] += [dict(SCAP), {"checkId": "privileged", "namespace": "apps",
                                                      "kind": "Deployment", "name": "web", "severity": "critical"}]
    out = await _run(w, [exc()])
    assert out.status == "fail" and out.evidence["workloads"] == ["apps/Deployment/web"]
    assert "1 workload(s) with accepted risk" in out.detail


async def test_expired_or_unlisted_assertion_reverts_to_fail():
    w = good_world()
    w["snapshot"]["postureFailures"].append(dict(SCAP))
    out = await _run(w, [exc(expiresAt="2020-01-01")])
    assert out.status == "fail" and out.evidence["lapsedAcceptances"]
    out = await _run(w, [exc(assertions=[])])  # exception covers only the checks, which are still failing here
    assert out.status == "fail"


def test_accepted_assertion_never_makes_a_control_passing():
    asserts = [assertion("a1"), assertion("a2")]
    rows = {r.control: r for r in derive_statuses([outcome("a1", "pass"), outcome("a2", "accepted-risk")],
                                                  components=COMPS, assertions=asserts)}
    ac7 = rows["AC-7"]
    assert ac7.status not in ("passing", "hybrid", "failing")
    assert {o["state"] for o in ac7.objectives} == {"risk-accepted"}
    assert "accepted risk" in ac7.detail
    rows = {r.control: r for r in derive_statuses([outcome("a1", "accepted-risk"), outcome("a2", "fail")],
                                                  components=COMPS, assertions=asserts)}
    assert rows["AC-7"].status == "failing"
    sm = summarize(list(rows.values()), [outcome("a1", "accepted-risk")], "moderate")
    assert sm["assertions"]["accepted-risk"] == 1
