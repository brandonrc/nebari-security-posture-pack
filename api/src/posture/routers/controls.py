"""Control evidence engine API (DESIGN §13): catalog, families, assertions and the extended
`GET /compliance/controls` (supersedes the §11 route in routers/compliance.py, whose
`control_coverage` still supplies `findingsOpen` / `checksFailed`)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import app_settings
from ..auth import User, require_admin
from ..controls_engine import engine
from ..controls_engine.assertions import all_assertions, get_assertion
from ..controls_engine.catalog import BASELINES, control_dict, get_catalog
from ..controls_engine.models import ControlAssertionResult, ControlAssertionRun
from ..db.session import get_session
from .compliance import control_coverage

router = APIRouter(tags=["compliance"])


def _baseline(value: str | None, default: str) -> str:
    b = (value or default).lower()
    if b not in BASELINES:
        raise HTTPException(422, f"unknown baseline {value!r} (low, moderate, high)")
    return b


async def _statuses(session: AsyncSession, baseline: str, st: Any) -> tuple[list[dict[str, Any]], dict | None]:
    """Latest run's statuses re-flagged for `baseline`; without a run, statuses from component
    declarations only (assertion-backed controls are `unknown`/`not-implemented` until the first run)."""
    data = await engine.latest_data(session)
    catalog = get_catalog()
    if data is None:
        ce = st.controls_engine
        rows = engine.derive_statuses([], baseline=baseline, not_applicable=ce.not_applicable,
                                      inherit_organizational=ce.inherit_organizational_controls)
        return [{"control": r.control, "id": r.id, "family": r.family, "baseline": r.baseline,
                 "inBaseline": r.in_baseline, "status": r.status, "components": r.components, "assertions": [],
                 "detail": r.detail, "score": None} for r in rows], None
    statuses = data["statuses"]
    present = {s["control"] for s in statuses}
    for s in statuses:
        c = catalog.get(s["control"])
        s["inBaseline"] = bool(c and c.in_baseline(baseline))
    for c in catalog.baseline(baseline):
        if c.label not in present:
            statuses.append({"control": c.label, "id": c.id, "family": c.family, "baseline": c.lowest_baseline,
                             "inBaseline": True, "status": "unknown", "components": [], "assertions": [],
                             "detail": f"not evaluated (latest run used the {data['run']['baseline']} baseline)",
                             "score": None})
    return statuses, data


@router.get("/compliance/catalog")
async def catalog(family: str | None = None, baseline: str | None = None, q: str | None = None,
                  includeWithdrawn: bool = False) -> list[dict[str, Any]]:  # noqa: N803
    if baseline:
        baseline = _baseline(baseline, "moderate")
    cat = get_catalog()
    out = [control_dict(c) for c in cat.list(family=family, baseline=baseline, include_withdrawn=includeWithdrawn)]
    if q:
        ql = q.lower()
        out = [c for c in out if ql in c["control"].lower() or ql in c["title"].lower()]
    return out


def _totals(rows: list[dict[str, Any]]) -> dict[str, int]:
    out = {"total": len(rows), **{k: 0 for k in engine.ROLLUP_KEYS.values()}}
    for r in rows:
        out[engine.ROLLUP_KEYS.get(r["status"], "unknown")] += 1
    return out


@router.get("/compliance/families")
async def families(baseline: str | None = None, session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    """Per-family rollup of the baseline plus consistent totals: `totals.baseline` counts the
    selected baseline's controls (the sum of `items`), `totals.catalog` every control
    `GET /compliance/controls` lists by default (baseline + assertion-covered + scan-evidence
    controls outside it)."""
    st = await app_settings.load(session)
    b = _baseline(baseline, st.controls_engine.baseline)
    statuses, data = await _statuses(session, b, st)
    rows = await _control_rows(session, statuses, data)
    return {"baseline": b, "items": engine.family_rollup(statuses),
            "totals": {"baseline": {"name": b, **_totals([r for r in rows if r["inBaseline"]])},
                       "catalog": _totals(rows)}}


async def _control_rows(session: AsyncSession, statuses: list[dict[str, Any]], data: dict | None,
                        include_all: bool = False) -> list[dict[str, Any]]:
    results = {r["id"]: r for r in (data or {}).get("results") or []}
    coverage = {c["control"]: c for c in await control_coverage(session)}
    catalog = get_catalog()
    by_control = {s["control"]: s for s in statuses}
    for label in coverage:  # §11 scan-evidence controls are always listed
        if label not in by_control:
            c = catalog.get(label)
            by_control[label] = {"control": label, "family": c.family if c else label.split("-")[0],
                                 "baseline": c.lowest_baseline if c else None, "inBaseline": False,
                                 "status": "unknown", "components": [], "assertions": [],
                                 "detail": "outside the selected baseline; see findingsOpen / checksFailed"}
    out = []
    for label, s in by_control.items():
        if not include_all and not s.get("inBaseline") and not s.get("assertions") and label not in coverage:
            continue
        cov = coverage.get(label) or {}
        c = catalog.get(label)
        out.append({
            "control": label, "title": (c.full_title if c else None) or cov.get("title") or label,
            "family": s["family"], "baseline": s.get("baseline"), "inBaseline": bool(s.get("inBaseline")),
            "status": s["status"], "detail": s.get("detail"), "score": s.get("score"),
            "implementationLevel": c.implementation_level if c else None,
            "components": s.get("components") or [],
            "assertions": [{"id": a, "title": results[a]["title"], "status": results[a]["status"],
                            "detail": results[a]["detail"], "evidence": results[a]["evidence"],
                            "checkedAt": results[a]["checkedAt"]} for a in s.get("assertions") or [] if a in results],
            "findingsOpen": cov.get("findingsOpen", 0), "checksFailed": cov.get("checksFailed", 0),
            "findingStatus": cov.get("status"),  # §11 value: not_assessed | open | satisfied
        })
    out.sort(key=lambda r: catalog.sort_key(r["control"]))
    return out


@router.get("/compliance/controls")
async def controls(family: str | None = None, status: str | None = None, baseline: str | None = None,
                   includeAll: bool = False,  # noqa: N803  (also controls outside the baseline)
                   session: AsyncSession = Depends(get_session)) -> list[dict[str, Any]]:
    st = await app_settings.load(session)
    b = _baseline(baseline, st.controls_engine.baseline)
    statuses, data = await _statuses(session, b, st)
    out = await _control_rows(session, statuses, data, include_all=includeAll)
    if family:
        out = [r for r in out if r["family"].upper() == family.upper()]
    if status:
        out = [r for r in out if r["status"] == status]
    return out


@router.get("/compliance/assertions")
async def assertions(component: str | None = None, status: str | None = None,
                     session: AsyncSession = Depends(get_session)) -> list[dict[str, Any]]:
    data = await engine.latest_data(session)
    results = {r["id"]: r for r in (data or {}).get("results") or []}
    out = []
    for a in all_assertions():
        if component and a.component != component:
            continue
        r = results.get(a.id) or {}
        row = {**a.meta(), "status": r.get("status", "unknown" if data else None), "detail": r.get("detail"),
               "evidence": r.get("evidence"), "checkedAt": r.get("checkedAt"), "durationMs": r.get("durationMs"),
               "runId": r.get("runId")}
        if status and row["status"] != status:
            continue
        out.append(row)
    return out


@router.post("/compliance/assertions/run", status_code=202)
async def run_assertions(user: User = Depends(require_admin),
                         session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    st = await app_settings.load(session)
    if not st.controls_engine.enabled:
        raise HTTPException(409, "control evidence engine is disabled (controlsEngine.enabled)")
    row = await engine.enqueue_run(session, trigger="manual", requested_by=user.username,
                                   baseline=st.controls_engine.baseline)
    await session.commit()
    return engine.run_dict(row)


@router.get("/compliance/assertions/{assertion_id}")
async def assertion_detail(assertion_id: str, limit: int = Query(50, ge=1, le=500),
                           session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    a = get_assertion(assertion_id)
    if a is None:
        raise HTTPException(404, "unknown assertion")
    rows = (await session.execute(select(ControlAssertionResult).where(
        ControlAssertionResult.assertion_id == assertion_id).order_by(ControlAssertionResult.id.desc()).limit(limit))
    ).scalars().all()
    history = [engine.result_dict(r) for r in rows]
    latest = history[0] if history else None
    return {**a.meta(), "status": latest["status"] if latest else None, "detail": latest["detail"] if latest else None,
            "evidence": latest["evidence"] if latest else None, "checkedAt": latest["checkedAt"] if latest else None,
            "history": [{k: h[k] for k in ("runId", "status", "detail", "checkedAt", "durationMs")} for h in history]}


@router.get("/compliance/runs")
async def runs(limit: int = Query(20, ge=1, le=200), session: AsyncSession = Depends(get_session)) -> list[dict]:
    rows = (await session.execute(select(ControlAssertionRun).order_by(ControlAssertionRun.id.desc()).limit(limit))
            ).scalars().all()
    return [engine.run_dict(r) for r in rows]


@router.get("/compliance/runs/{run_id}")
async def run_detail(run_id: int, session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    row = await session.get(ControlAssertionRun, run_id)
    if row is None:
        raise HTTPException(404, "unknown run")
    return engine.run_dict(row)

