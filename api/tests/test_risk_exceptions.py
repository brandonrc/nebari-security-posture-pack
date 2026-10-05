"""Risk acceptances (`controlsEngine.exceptions`, posture.controls_engine.exceptions): posture
checks, settings / env wiring and the run-as-root detail (grace 2026-10-05, scap-worker)."""

from __future__ import annotations

import json
from datetime import date

import pytest

from posture.controls_engine.exceptions import ACCEPTED_RISK, RiskException, find, parse_env
from posture.inventory_model import InventorySnapshot
from posture.posture_checks import evaluate_inventory, evaluate_workload

TODAY = date(2026, 10, 5)
ROOT_CAPS = {"container": {"securityContext": {"runAsUser": 0, "runAsNonRoot": False,
                                               "capabilities": {"add": ["CHOWN", "SYS_CHROOT"], "drop": ["ALL"]}}},
             "pod": {}}


def exc(**kw):
    base = dict(kind="Deployment", namespace="app", name="web", checks=["added-capabilities", "run-as-root"],
                reason="OpenSCAP needs root in its container", approvedBy="ISSO Jane", reviewBy="2027-04-03")
    base.update(kw)
    return RiskException.model_validate(base)


def _results(container_factory, exceptions, today=TODAY):
    inv = InventorySnapshot([container_factory(security=ROOT_CAPS)])
    wp = evaluate_inventory(inv, exceptions=exceptions, today=today)[("app", "Deployment", "web")]
    return wp, {r.check_id: r for r in wp.results if r.container in ("web", "")}


def test_model_validation_and_matching():
    e = exc(name="web-*", kind="*")
    assert e.key == "app/*/web-*" and e.matches("StatefulSet", "app", "web-1") and not e.matches("Deployment", "x", "web-1")
    assert e.active(TODAY) and not e.review_overdue(TODAY) and e.review_overdue(date(2027, 4, 4))
    with pytest.raises(ValueError):
        exc(checks=[], assertions=[])
    with pytest.raises(ValueError):
        exc(reason=" ")
    with pytest.raises(ValueError):
        exc(approvedBy="")
    assert exc(expiresAt="2026-10-05").active(TODAY) and not exc(expiresAt="2026-10-04").active(TODAY)
    act, expired = find([exc(expiresAt="2026-10-01")], "Deployment", "app", "web", check="run-as-root", today=TODAY)
    assert act is None and expired is not None


def test_accepted_finding_stays_visible_without_penalty(container_factory):
    base, plain = _results(container_factory, None)
    assert plain["run-as-root"].status == "fail" and plain["added-capabilities"].status == "fail"
    wp, r = _results(container_factory, [exc()])
    for cid in ("run-as-root", "added-capabilities"):
        assert r[cid].status == ACCEPTED_RISK  # never pass
        assert r[cid].weight == 0.0
        assert "accepted risk: OpenSCAP needs root" in r[cid].detail and "approved by ISSO Jane" in r[cid].detail
        assert "review by 2027-04-03" in r[cid].detail
    assert wp.accepted == 2 and wp.failed == base.failed - 2
    assert wp.score > base.score  # excluded from the score penalty
    assert r["privilege-escalation"].status == "fail"  # not covered


def test_expired_exception_reverts_to_failing(container_factory):
    _, r = _results(container_factory, [exc(expiresAt="2026-10-04")])
    assert r["run-as-root"].status == "fail" and r["run-as-root"].weight > 0
    assert "risk acceptance expired 2026-10-04" in r["run-as-root"].detail
    _, r = _results(container_factory, [exc(expiresAt="2026-10-05")])  # inclusive last day
    assert r["run-as-root"].status == ACCEPTED_RISK


def test_other_workload_not_covered(container_factory):
    _, r = _results(container_factory, [exc(name="api")])
    assert r["run-as-root"].status == "fail"


def test_run_as_root_detail_explicit_false(container_factory):
    r = {x.check_id: x for x in evaluate_workload([container_factory(security=ROOT_CAPS)])}
    assert r["run-as-root"].detail == "runAsNonRoot is false and runAsUser is 0"
    r = {x.check_id: x for x in evaluate_workload([container_factory()])}
    assert r["run-as-root"].detail == "runAsNonRoot not set and runAsUser unset"
    pod_false = {"container": {}, "pod": {"securityContext": {"runAsNonRoot": False}}}
    r = {x.check_id: x for x in evaluate_workload([container_factory(security=pod_false)])}
    assert r["run-as-root"].detail.startswith("runAsNonRoot is false")


def test_parse_env_marks_values_source():
    raw = json.dumps([{"kind": "Deployment", "namespace": "sp", "name": "sp-scap-worker", "checks": ["run-as-root"],
                       "assertions": ["k8s-workload-least-privilege"], "reason": "r", "approvedBy": "chart",
                       "reviewBy": "2027-04-03", "expiresAt": ""}])
    out = parse_env(raw)
    assert out[0]["source"] == "values" and out[0]["expiresAt"] is None and out[0]["reviewBy"] == "2027-04-03"
    assert parse_env("") == [] and parse_env(None) == []
    with pytest.raises(ValueError):
        parse_env(json.dumps([{"kind": "Deployment", "namespace": "sp", "name": "x", "reason": "r", "approvedBy": "a"}]))


class _Row:
    def __init__(self, data):
        self.data, self.updated_by = data, None


class _Session:
    def __init__(self, row=None):
        self.row = row

    async def get(self, _model, _id):
        return self.row

    def add(self, row):
        self.row = row

    async def commit(self):
        pass


async def test_settings_merge_values_and_stored(monkeypatch):
    from posture import app_settings
    from posture.config import Settings

    chart = [{"kind": "Deployment", "namespace": "sp", "name": "sp-scap-worker", "checks": ["run-as-root"],
              "reason": "chart", "approvedBy": "pack", "reviewBy": "2027-04-03"}]
    env = Settings(controls_exceptions=json.dumps(chart))
    assert [e.source for e in app_settings.defaults(env).controls_engine.exceptions] == ["values"]
    # a stored settings row (saved before / without the chart entry) keeps its own and gains the chart's
    stored = {"controlsEngine": {"exceptions": [
        {"kind": "Deployment", "namespace": "app", "name": "web", "checks": ["privileged"], "reason": "own",
         "approvedBy": "AO", "expiresAt": "2027-01-01"},
        {**chart[0], "reason": "stale copy", "source": "values"}]}}
    st = await app_settings.load(_Session(_Row(stored)), env)
    got = [(e.source, e.reason) for e in st.controls_engine.exceptions]
    assert got == [("values", "chart"), ("settings", "own")]
    # saving never persists the chart entries
    monkeypatch.setattr(app_settings, "get_settings", lambda: env)
    sess = _Session(None)
    await app_settings.save(sess, st, "admin")
    saved = sess.row.data["controlsEngine"]["exceptions"]
    assert [e["reason"] for e in saved] == ["own"] and saved[0]["expiresAt"] == "2027-01-01"


def test_env_empty_or_json(monkeypatch):
    from posture.config import Settings

    monkeypatch.setenv("CONTROLS_EXCEPTIONS", "")
    assert Settings().controls_exceptions == []
    monkeypatch.setenv("CONTROLS_EXCEPTIONS", json.dumps([{"kind": "Deployment", "namespace": "a", "name": "b",
                                                           "checks": ["privileged"], "reason": "r", "approvedBy": "x",
                                                           "expiresAt": ""}]))
    assert Settings().controls_exceptions[0]["source"] == "values"


def test_status_columns_hold_accepted_risk():
    """Grace revision 20: posture_results.status was varchar(8), so persisting an `accepted-risk`
    result failed the scan's finalize (Postgres enforces the length; SQLite does not)."""
    from posture.controls_engine.models import ControlAssertionResult
    from posture.db.models import PostureResultRow

    assert PostureResultRow.__table__.c.status.type.length >= len(ACCEPTED_RISK)
    assert ControlAssertionResult.__table__.c.status.type.length >= len(ACCEPTED_RISK)
