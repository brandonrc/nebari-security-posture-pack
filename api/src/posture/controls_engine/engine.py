"""Run assertions, derive per-control status, roll up per family, persist (DESIGN §13).

Status vocabulary (evidence status, never an assessment result; compliance review M2/M8):

  passing                  every SP 800-53A objective of the control is evidenced by passing
                           assertions (responsibility `provider`)
  hybrid                   the platform's objectives pass and every other objective is explicitly
                           assigned to the program / organization (shared responsibility)
  partial                  some objectives have passing evidence ("n of m objectives"), others
                           fail, are unknown or have no evidence
  failing                  evidence exists and none of it passes
  not-assessed             no usable evidence (not run, unknown, not-applicable results, or nothing
                           in the platform addresses the control)
  org-provided-unverified  organization-level control assumed to be provided by the organization
                           (`inheritOrganizationalControls`, default off) or declared as provided
                           outside the platform (hosting facility); never counted as implemented
  inherited                a named, authorized common control provider lists the control
                           (`controlsEngine.commonControlProviders`)
  not-applicable           tailored out by the AO-approved `controlsEngine.notApplicable` only

Derivation order: tailoring, common control provider, objective evidence, org-provided, not-assessed.
Assertions map to controls through their own `controls` (objective tags in `objectives`) and through
component `implemented-requirements[].assertions`.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ..logs import get_logger
from .assertions import all_assertions
from .catalog import Catalog, get_catalog, objective_control, to_label, to_oscal_id
from .components import Component, load_components, requirements_by_control
from .context import EngineConfig, EngineContext, EngineError, K8sForbidden, NotConfigured
from .model import FAIL, NA, PASS, UNKNOWN, Assertion

log = get_logger(__name__)

PASSING, PARTIAL, FAILING, NOT_ASSESSED = "passing", "partial", "failing", "not-assessed"
INHERITED, NOT_APPLICABLE = "inherited", "not-applicable"
HYBRID, ORG_PROVIDED = "hybrid", "org-provided-unverified"
CONTROL_STATUSES = (PASSING, PARTIAL, FAILING, NOT_ASSESSED, ORG_PROVIDED, INHERITED, HYBRID, NOT_APPLICABLE)
ROLLUP_KEYS = {PASSING: "passing", PARTIAL: "partial", FAILING: "failing", HYBRID: "hybrid",
               INHERITED: "inherited", ORG_PROVIDED: "orgProvided", NOT_APPLICABLE: "notApplicable",
               NOT_ASSESSED: "notAssessed"}
# objective evidence states
OBJ_SATISFIED, OBJ_NOT_SATISFIED, OBJ_UNKNOWN, OBJ_ASSIGNED, OBJ_NONE = (
    "satisfied", "not-satisfied", "unknown", "assigned", "no-evidence")
KEEP_RUNS = 100
DEFAULT_ORG_STATEMENT = ("Expected to be provided by the organization (policy, procedures, personnel, training or "
                         "physical safeguards). UNVERIFIED: no common control provider or authorization is "
                         "recorded for this control; document the provider before relying on it.")
CUSTOMER_DEFAULT = "Not provided by the platform: the program implements and documents this control."
ORG_DEFAULT = ("Organization-level control: provided by the organization or a common control provider, not by "
               "the platform.")


@dataclass
class Outcome:
    id: str
    title: str
    controls: list[str]
    component: str
    severity: str
    status: str
    detail: str
    evidence: dict[str, Any]
    duration_ms: int
    checked_at: datetime

    def as_dict(self) -> dict[str, Any]:
        return {"id": self.id, "title": self.title, "controls": self.controls, "component": self.component,
                "severity": self.severity, "status": self.status, "detail": self.detail, "evidence": self.evidence,
                "durationMs": self.duration_ms, "checkedAt": _iso(self.checked_at)}


@dataclass
class ControlResult:
    control: str
    id: str
    title: str
    family: str
    baseline: str | None
    in_baseline: bool
    status: str
    components: list[str] = field(default_factory=list)
    assertions: list[str] = field(default_factory=list)
    detail: str = ""
    score: float | None = None
    responsibility: str = "customer"  # provider | shared | customer | org (CRM, S6)
    provider: str | None = None  # common control provider name when inherited
    objectives: list[dict[str, Any]] = field(default_factory=list)  # [{id, state, assertions[]}]
    inputs: dict[str, Any] = field(default_factory=dict)  # scan evidence used (M3)

    @property
    def objectives_evidenced(self) -> int:
        return sum(o["state"] in (OBJ_SATISFIED,) for o in self.objectives)


def _iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).isoformat().replace("+00:00", "Z")


# ------------------------------------------------------------------------- running
async def run_one(a: Assertion, ctx: EngineContext, timeout: float) -> Outcome:
    start = time.monotonic()
    checked = datetime.now(UTC)
    try:
        res = await asyncio.wait_for(a.evaluate(ctx), timeout)
        status, detail, evidence = res.status, res.detail, res.evidence
    except (TimeoutError, asyncio.TimeoutError):
        status, detail, evidence = UNKNOWN, f"timed out after {timeout:g}s", {}
    except K8sForbidden as e:
        status, detail, evidence = UNKNOWN, f"not permitted to read {e.path} (chart RBAC: controlsEngine.enabled)", {
            "error": str(e)}
    except NotConfigured as e:
        status, detail, evidence = UNKNOWN, str(e), {}
    except EngineError as e:
        status, detail, evidence = UNKNOWN, f"evidence unavailable: {e}", {"error": str(e)}
    except Exception as e:  # noqa: BLE001  (a buggy assertion must never break the run)
        log.exception("controls.assertion_error", assertion=a.id)
        status, detail, evidence = UNKNOWN, f"assertion error: {type(e).__name__}: {e}"[:500], {"error": repr(e)[:500]}
    return Outcome(id=a.id, title=a.title, controls=list(a.controls), component=a.component, severity=a.severity,
                   status=status, detail=detail, evidence=evidence,
                   duration_ms=int((time.monotonic() - start) * 1000), checked_at=checked)


async def run_assertions(ctx: EngineContext, assertions: Iterable[Assertion] | None = None,
                         timeout: float | None = None, concurrency: int = 8) -> list[Outcome]:
    items = list(assertions if assertions is not None else all_assertions())
    sem = asyncio.Semaphore(max(1, concurrency))
    t = timeout or ctx.config.timeout_seconds

    async def guarded(a: Assertion) -> Outcome:
        async with sem:
            return await run_one(a, ctx, t)

    return list(await asyncio.gather(*(guarded(a) for a in items)))


# ------------------------------------------------------------------------- derivation
def assertion_map(components: dict[str, Component], assertions: Iterable[Assertion]) -> dict[str, list[str]]:
    """control label -> assertion ids (union of assertion.controls and component requirements)."""
    out: dict[str, list[str]] = {}
    for a in assertions:
        for c in a.controls:
            out.setdefault(to_label(c), [])
            if a.id not in out[to_label(c)]:
                out[to_label(c)].append(a.id)
    for comp in components.values():
        for req in comp.requirements:
            lst = out.setdefault(req.control, [])
            for aid in req.assertions:
                if aid not in lst:
                    lst.append(aid)
    return out


def providers_by_control(providers: Iterable[Any] | None) -> dict[str, Any]:
    """control label -> configured common control provider (settings `commonControlProviders`)."""
    out: dict[str, Any] = {}
    for p in providers or []:
        controls = p.get("controls") if isinstance(p, dict) else getattr(p, "controls", [])
        for c in controls or []:
            out.setdefault(to_label(c), p)
    return out


def _pget(p: Any, key: str, attr: str) -> Any:
    return p.get(key) if isinstance(p, dict) else getattr(p, attr, None)


def responsibility_of(label: str, reqs: list[tuple[Component, Any]], cat: Any) -> str:
    """CRM responsibility of a control: the components' declarations; a mix (or any `shared`)
    is `shared`; undeclared controls are `org` (organization-level) or `customer`."""
    resp = {req.responsibility for _, req in reqs}
    if not resp:
        return "org" if cat is not None and cat.implementation_level == "organization" else "customer"
    return resp.pop() if len(resp) == 1 else "shared"


def assertion_objectives(a: Assertion, catalog: Catalog) -> dict[str, list[str]]:
    """control label -> leaf objectives the assertion evidences (all of a control's objectives when
    the assertion carries no tag for it, i.e. custom assertions keep their whole-control meaning)."""
    out: dict[str, list[str]] = {}
    for c in a.controls:
        cat = catalog.get(c)
        if cat is None:
            continue
        refs = [o for o in a.objectives if objective_control(o) == cat.id]
        out[cat.label] = cat.expand_objectives(refs) if refs else list(cat.objective_ids)
    return out


def _objective_states(label: str, cat: Any, results: list[Outcome], amap_obj: dict[str, dict[str, list[str]]],
                      declared: list[tuple[Component, Any]]) -> list[dict[str, Any]]:
    leaves = list(cat.objective_ids) if cat is not None else [f"{to_oscal_id(label)}_obj"]
    ev: dict[str, list[Outcome]] = {o: [] for o in leaves}
    for r in results:
        for leaf in amap_obj.get(r.id, {}).get(label, []):
            if leaf in ev:
                ev[leaf].append(r)
    assigned: set[str] = set()
    for _, req in declared:
        if "rest" in req.assigned:
            assigned |= {o for o in leaves if not ev[o]}
        elif req.assigned and cat is not None:
            assigned |= set(cat.expand_objectives(req.assigned))
    out = []
    for leaf in leaves:
        rs = ev[leaf]
        sts = {r.status for r in rs}
        if FAIL in sts:
            state = OBJ_NOT_SATISFIED
        elif sts == {PASS}:
            state = OBJ_SATISFIED
        elif sts:  # unknown (possibly next to a pass): not fully evidenced
            state = OBJ_UNKNOWN
        elif leaf in assigned:
            state = OBJ_ASSIGNED
        else:
            state = OBJ_NONE
        out.append({"id": leaf, "state": state, "assertions": sorted({r.id for r in rs})})
    return out


def scan_evidence(snapshot: dict[str, Any] | None, system_namespaces: Iterable[str] = ()) -> dict[str, Any]:
    """Scan results as failing evidence per control (compliance review M3): posture-check failures
    of non-system workloads, open fixable findings and SLA-overdue findings, mapped through
    reports/data/controls.yaml (`checks`, `vulnerabilities`, `scanObjectives`).

    Returns {control label: {"items": [{id, status, objectives, detail}], "inputs": {...}}}."""
    from ..controls import check_controls, finding_objective_controls, scan_objectives, vuln_controls

    out: dict[str, Any] = {}
    if not snapshot or not snapshot.get("lastDoneScan"):
        return out
    scan_id = snapshot["lastDoneScan"].get("id")
    sysns = set(system_namespaces)

    def add(control: str, item: dict[str, Any], key: str, n: int) -> None:
        e = out.setdefault(control, {"items": [], "inputs": {"scanId": scan_id}})
        e["items"].append(item)
        e["inputs"][key] = e["inputs"].get(key, 0) + n

    by_check: dict[str, set[str]] = {}
    for f in snapshot.get("postureFailures") or []:
        if f.get("namespace") in sysns:
            continue
        by_check.setdefault(f.get("checkId") or "", set()).add(f"{f.get('namespace')}/{f.get('kind')}/{f.get('name')}")
    for check, workloads in sorted(by_check.items()):
        for c in check_controls(check):
            add(to_label(c), {"id": f"scan:posture:{check}", "status": FAIL,
                              "objectives": scan_objectives("posture", to_label(c)),
                              "detail": f"posture check {check} fails on {len(workloads)} workload(s)"},
                "postureFailures", len(workloads))
    fixable = int((snapshot.get("findingsByFixable") or {}).get("fixable") or 0)
    if fixable:
        open_controls = set(vuln_controls(True)) & set(finding_objective_controls("open"))
        for c in sorted(open_controls):
            add(to_label(c), {"id": "scan:findings-open", "status": FAIL, "objectives": scan_objectives("open", c),
                              "detail": f"{fixable} open finding(s) with a fix available"}, "findingsOpenFixable", fixable)
    overdue = sum(int(v) for v in (snapshot.get("slaOverdue") or {}).values())
    if overdue:
        for c in finding_objective_controls("overdue"):
            add(to_label(c), {"id": "scan:findings-overdue", "status": FAIL,
                              "objectives": scan_objectives("overdue", c),
                              "detail": f"{overdue} finding(s) past their remediation SLA"}, "findingsOverdue", overdue)
    return out


def derive_statuses(outcomes: list[Outcome], *, baseline: str = "moderate",
                    components: dict[str, Component] | None = None, catalog: Catalog | None = None,
                    assertions: Iterable[Assertion] | None = None,
                    not_applicable: dict[str, str] | None = None,
                    inherit_organizational: bool = False,
                    providers: Iterable[Any] | None = None,
                    scan: dict[str, Any] | None = None) -> list[ControlResult]:
    """`scan` = `scan_evidence(snapshot)`: failing scan evidence that downgrades mapped controls (M3)."""
    catalog = catalog or get_catalog()
    components = load_components() if components is None else components
    assertions = list(all_assertions() if assertions is None else assertions)
    by_id = {o.id: o for o in outcomes}
    amap = assertion_map(components, assertions)
    amap_obj = {a.id: assertion_objectives(a, catalog) for a in assertions}
    reqs = requirements_by_control(components)
    tailored = {to_label(k): v for k, v in (not_applicable or {}).items()}
    ccp = providers_by_control(providers)
    comp_of = {a.id: a.component for a in assertions}

    scope: dict[str, None] = {}
    for c in catalog.baseline(baseline):
        scope[c.label] = None
    scan = scan or {}
    for label in [*amap, *reqs, *scan]:
        cat = catalog.get(label)
        if cat is None or not cat.withdrawn:
            scope[to_label(label)] = None

    out: list[ControlResult] = []
    for label in scope:
        cat = catalog.get(label)
        ids = [i for i in amap.get(label, []) if i in by_id]
        scan_items = (scan.get(label) or {}).get("items") or []
        declared = reqs.get(label, [])
        comps = list(dict.fromkeys([*(comp.id for comp, _ in declared),
                                    *(comp_of[i] for i in ids if i in comp_of)]))
        res = ControlResult(control=label, id=to_oscal_id(label), title=cat.full_title if cat else label,
                            family=cat.family if cat else label.split("-")[0].upper(),
                            baseline=cat.lowest_baseline if cat else None,
                            in_baseline=bool(cat and cat.in_baseline(baseline)), status=NOT_ASSESSED,
                            components=comps, assertions=ids, responsibility=responsibility_of(label, declared, cat))
        results = [by_id[i] for i in ids]
        evaluated = [r for r in results if r.status in (PASS, FAIL, UNKNOWN)]
        if scan_items:  # M3: scan results are evidence too (failing posture checks, open/overdue findings)
            res.inputs = dict((scan.get(label) or {}).get("inputs") or {})
            for it in scan_items:
                o = Outcome(id=it["id"], title=it["id"], controls=[label], component="scan", severity="high",
                            status=it["status"], detail=it.get("detail", ""), evidence={}, duration_ms=0,
                            checked_at=datetime.now(UTC))
                evaluated.append(o)
                leaves = (cat.expand_objectives(it["objectives"]) if it.get("objectives") else list(cat.objective_ids)) \
                    if cat is not None else []
                amap_obj = {**amap_obj, o.id: {**amap_obj.get(o.id, {}), label: leaves}}
        org_declared = [(comp, req) for comp, req in declared if req.responsibility == "org"]
        if evaluated or results:
            res.objectives = _objective_states(label, cat, evaluated, amap_obj, declared)
        if label in tailored:
            res.status, res.detail = NOT_APPLICABLE, f"tailored out: {tailored[label] or 'not applicable'}"
        elif label in ccp:
            prov = ccp[label]
            name, ref = _pget(prov, "name", "name"), _pget(prov, "authorizationRef", "authorization_ref")
            res.status, res.responsibility, res.provider = INHERITED, "org", name
            res.detail = f"inherited from common control provider {name}" + (f" ({ref})" if ref else "")
            if any(r.status == FAIL for r in results):
                res.detail += f"; note: {sum(r.status == FAIL for r in results)} platform assertion(s) fail"
        elif evaluated:
            _status_from_objectives(res, evaluated)
            capped = [req for _, req in declared if req.ceiling == PARTIAL]
            if capped and res.status in (PASSING, HYBRID):
                res.status = PARTIAL
                res.detail = "capped at partial: " + "; ".join(r.ceiling_reason or "evidence is incomplete"
                                                                for r in capped) + ". " + res.detail
        elif amap.get(label) and not results:
            res.status = NOT_ASSESSED
            res.detail = "assertion(s) not evaluated yet: " + ", ".join(amap[label])
        elif results:  # M5: an assertion never tailors a control out; only the AO's tailoring does
            res.status = NOT_ASSESSED
            res.detail = ("assertion(s) found nothing to evaluate (not-applicable result; tailor the control out "
                          "with controlsEngine.notApplicable if it really does not apply): " + "; ".join(
                              r.detail for r in results if r.detail))[:500]
        elif org_declared:
            res.status = ORG_PROVIDED
            res.detail = "UNVERIFIED (no common control provider configured): " + " ".join(
                f"{comp.title}: {req.statement}" for comp, req in org_declared)
        elif cat and cat.implementation_level == "organization" and inherit_organizational:
            res.status, res.detail = ORG_PROVIDED, "organization-level control, assumed organization-provided (unverified)"
        elif declared:
            res.status = NOT_ASSESSED
            res.detail = "declared by " + ", ".join(c.title for c, _ in declared) + "; no automated assertion " \
                         "(manual evidence required)"
        else:
            res.status = NOT_ASSESSED
            res.detail = "no platform evidence; system-specific implementation and assessment required"
        out.append(res)
    out.sort(key=lambda r: catalog.sort_key(r.control))
    return out


def _status_from_objectives(res: ControlResult, evaluated: list[Outcome]) -> None:
    objs = res.objectives
    m = len(objs)
    sat = sum(o["state"] == OBJ_SATISFIED for o in objs)
    bad = sum(o["state"] == OBJ_NOT_SATISFIED for o in objs)
    unk = sum(o["state"] == OBJ_UNKNOWN for o in objs)
    asg = sum(o["state"] == OBJ_ASSIGNED for o in objs)
    real = [r for r in evaluated if not r.id.startswith("scan:")]
    p = sum(r.status == PASS for r in real)
    f = sum(r.status == FAIL for r in real)
    u = sum(r.status == UNKNOWN for r in real)
    scan_fail = [r for r in evaluated if r.id.startswith("scan:")]
    res.score = round(sat / m, 3) if m else None
    cov = f"{sat} of {m} objective(s) with passing evidence"
    if asg:
        cov += f", {asg} assigned to the program/organization"
    tail = f" ({p} assertion(s) pass, {f} fail, {u} unknown" + (
        "; scan: " + "; ".join(r.detail for r in scan_fail) if scan_fail else "") + ")"
    if bad and not sat:
        res.status, res.detail = FAILING, f"{cov}; {bad} objective(s) with failing evidence" + tail
    elif not sat:
        res.status = NOT_ASSESSED
        res.detail = f"no passing evidence: {unk} objective(s) could not be evaluated" + tail
    elif bad or unk or sat + asg < m:
        res.status = PARTIAL
        res.detail = f"partial: {cov}" + (f"; {bad} failing" if bad else "") + (f"; {unk} unknown" if unk else "") \
            + tail
    elif asg:
        res.status, res.detail = HYBRID, f"platform part passing: {cov}" + tail
    else:
        res.status, res.detail = PASSING, f"evidence passing for all {m} objective(s)" + tail


def family_rollup(statuses: Iterable[ControlResult | dict[str, Any]], catalog: Catalog | None = None,
                  baseline_only: bool = True) -> list[dict[str, Any]]:
    catalog = catalog or get_catalog()
    rows: dict[str, dict[str, Any]] = {}
    for s in statuses:
        d = s if isinstance(s, dict) else {"family": s.family, "status": s.status, "inBaseline": s.in_baseline}
        if baseline_only and not d.get("inBaseline", True):
            continue
        fam = d["family"]
        row = rows.setdefault(fam, {"family": fam, "title": catalog.families.get(fam, fam), "total": 0,
                                    **{k: 0 for k in ROLLUP_KEYS.values()}})
        row[ROLLUP_KEYS.get(d["status"], "notAssessed")] += 1
        row["total"] += 1
    return sorted(rows.values(), key=lambda r: r["family"])


def summarize(statuses: list[ControlResult], outcomes: list[Outcome], baseline: str) -> dict[str, Any]:
    in_b = [s for s in statuses if s.in_baseline]
    counts = {k: sum(s.status == st for s in in_b) for st, k in ROLLUP_KEYS.items()}
    objs = [o for s in in_b for o in s.objectives]
    return {"baseline": baseline, "controls": len(in_b), **counts,
            "objectives": {"evidenced": sum(o["state"] == OBJ_SATISFIED for o in objs),
                           "assessed": len(objs),
                           "baseline": sum(len(get_catalog().get(s.control).objective_ids) for s in in_b
                                           if get_catalog().get(s.control))},
            "assertions": {st: sum(o.status == st for o in outcomes) for st in (PASS, FAIL, UNKNOWN, NA)}}


# ------------------------------------------------------------------------- config / snapshot
def engine_config(env: Any, st: Any) -> EngineConfig:
    """EngineConfig from env `Settings` and editable `AppSettings` (controls_engine section)."""
    ce = getattr(st, "controls_engine", None)
    params = getattr(ce, "parameters", None)
    cfg = EngineConfig(
        baseline=getattr(ce, "baseline", None) or env.controls_baseline,
        system_namespaces=list(env.controls_system_namespaces),
        admin_subjects=list(getattr(ce, "admin_subjects", None) or env.controls_admin_subjects),
        keycloak_url=env.controls_keycloak_url, keycloak_realm=env.controls_keycloak_realm,
        keycloak_admin_realm=env.controls_keycloak_admin_realm, keycloak_client_id=env.controls_keycloak_client_id,
        keycloak_admin_secret_name=env.controls_keycloak_admin_secret_name,
        keycloak_admin_secret_namespace=env.controls_keycloak_admin_secret_namespace,
        keycloak_admin_group=env.controls_keycloak_admin_group or (sorted(env.admin_group_set) or ["admin"])[0],
        keycloak_verify_tls=env.controls_keycloak_verify_tls,
        loki_url=env.controls_loki_url, prometheus_url=env.controls_prometheus_url,
        alertmanager_url=env.controls_alertmanager_url,
        registry_url=env.controls_registry_url or env.mirror_registry,
        discover_cluster_ip=env.controls_discover_cluster_ip,
        scan_interval_hours=getattr(st, "scan_interval_hours", 6),
        timeout_seconds=env.controls_timeout_seconds, tls_probe=env.controls_tls_probe,
    )
    if params is not None:  # M7: explicit settings, else the baseline's cited ODP set
        eff = params.effective(cfg.baseline)
        cfg.max_login_failures = int(eff["maxLoginFailures"])
        cfg.min_password_length = int(eff["minPasswordLength"])
        cfg.max_session_idle_seconds = int(eff["maxSessionIdleSeconds"])
        cfg.max_session_lifespan_seconds = int(eff["maxSessionLifespanSeconds"])
        cfg.min_log_retention_days = int(eff["minLogRetentionDays"])
        cfg.cert_renewal_window_days = int(eff["certRenewalWindowDays"])
        cfg.log_window_minutes = int(eff["logWindowMinutes"])
        cfg.lockout_window_seconds = int(eff["lockoutWindowSeconds"])
        cfg.min_lockout_seconds = int(eff["minLockoutSeconds"])
        cfg.require_admin_release = bool(eff["requireAdminRelease"])
    cfg.approved_issuers = list(getattr(ce, "approved_issuers", None) or [])
    return cfg


async def load_snapshot(session: AsyncSession, st: Any | None = None) -> dict[str, Any]:
    """Pack evidence for `pack-*` / workload assertions, from the DB (read-only)."""
    from .. import app_settings
    from ..db.models import (ConsensusFindingRow, ContainerRow, Image, PostureResultRow, Report, Scan,
                             ScannerStatus)
    from ..routers.summary import compute_sla_overdue
    from ..views import latest_done_scan

    st = st or await app_settings.load(session)
    snap: dict[str, Any] = {"scanIntervalHours": st.scan_interval_hours,
                            "slaDays": st.remediation_sla_days.model_dump()}
    enabled = st.scanners.model_dump()
    snap["scanners"] = [{"name": r.name, "enabled": bool(enabled.get(r.name, True)), "dbUpdatedAt": r.db_updated_at,
                         "healthy": r.healthy, "lastError": r.last_error}
                        for r in (await session.execute(select(ScannerStatus))).scalars()]
    last = await latest_done_scan(session)
    if last is None:
        return snap
    snap["lastDoneScan"] = {"id": last.id, "finishedAt": last.finished_at, "inventoryComplete": last.inventory_complete,
                            "imagesTotal": last.images_total, "score": last.score, "grade": last.grade}
    # Targeted scans (pod-watcher event scans, image rescans) refresh the inventory and posture
    # checks but scan only a few images and generate no reports: RA-5 recency and the POA&M
    # check are judged against the latest full scan (the scheduler's definition).
    full = (await session.execute(select(Scan).where(
        Scan.status == "done", Scan.target_image_ids.is_(None), Scan.target_namespaces.is_(None))
        .order_by(Scan.id.desc()).limit(1))).scalar_one_or_none()
    snap["lastFullScan"] = None if full is None else {
        "id": full.id, "finishedAt": full.finished_at, "imagesTotal": full.images_total, "score": full.score,
        "grade": full.grade}
    snap["openFindings"] = int(await session.scalar(
        select(func.count()).select_from(ConsensusFindingRow).join(Image, Image.id == ConsensusFindingRow.image_id)
        .where(Image.running.is_(True), ConsensusFindingRow.open_filter())) or 0)
    snap["findingsByFixable"] = {("fixable" if fx else "unfixable"): int(n) for fx, n in (await session.execute(
        select(ConsensusFindingRow.fixable, func.count()).join(Image, Image.id == ConsensusFindingRow.image_id)
        .where(Image.running.is_(True), ConsensusFindingRow.open_filter())
        .group_by(ConsensusFindingRow.fixable))).all()}
    snap["slaOverdue"] = await compute_sla_overdue(session, st.remediation_sla_days.model_dump())
    snap["postureFailures"] = [
        {"checkId": r.check_id, "namespace": r.namespace, "kind": r.kind, "name": r.name, "severity": r.severity}
        for r in (await session.execute(select(PostureResultRow).where(
            PostureResultRow.scan_id == last.id, PostureResultRow.status == "fail"))).scalars()]
    snap["inventory"] = {
        "containers": int(await session.scalar(select(func.count()).select_from(ContainerRow)
                                               .where(ContainerRow.scan_id == last.id)) or 0),
        "images": int(await session.scalar(select(func.count()).select_from(Image).where(Image.running.is_(True)))
                      or 0)}
    poam = (await session.execute(select(Report).where(Report.type == "poam", Report.status == "done")
                                  .order_by(Report.created_at.desc()).limit(1))).scalar_one_or_none()
    if poam is not None:
        snap["latestPoam"] = {"id": str(poam.id), "scanId": poam.scan_id, "createdAt": _iso(poam.created_at),
                              "format": poam.format}
    return snap


# ------------------------------------------------------------------------- persistence
async def enqueue_run(session: AsyncSession, *, trigger: str = "manual", requested_by: str | None = None,
                      scan_id: int | None = None, baseline: str = "moderate") -> Any:
    """Queue an on-demand run (returns the existing queued/running row instead of a duplicate)."""
    from .models import ControlAssertionRun

    existing = (await session.execute(select(ControlAssertionRun).where(
        ControlAssertionRun.status.in_(("queued", "running"))).order_by(ControlAssertionRun.id.desc()).limit(1))
    ).scalar_one_or_none()
    if existing is not None:
        return existing
    row = ControlAssertionRun(status="queued", trigger=trigger, requested_by=requested_by, scan_id=scan_id,
                              baseline=baseline, summary={})
    session.add(row)
    await session.flush()
    return row


async def claim_queued(sm: async_sessionmaker[AsyncSession]) -> int | None:
    from .models import ControlAssertionRun

    async with sm() as s, s.begin():
        row = (await s.execute(select(ControlAssertionRun).where(ControlAssertionRun.status == "queued")
                               .order_by(ControlAssertionRun.id).limit(1).with_for_update(skip_locked=True))
               ).scalar_one_or_none()
        if row is None:
            return None
        row.status, row.started_at = "running", datetime.now(UTC)
        return row.id


async def fail_stale(sm: async_sessionmaker[AsyncSession], older_than: timedelta = timedelta(minutes=30)) -> None:
    from sqlalchemy import update

    from .models import ControlAssertionRun

    cutoff = datetime.now(UTC) - older_than
    async with sm() as s, s.begin():
        await s.execute(update(ControlAssertionRun).where(ControlAssertionRun.status == "running",
                                                          ControlAssertionRun.started_at < cutoff)
                        .values(status="failed", finished_at=datetime.now(UTC), error="interrupted"))


ContextFactory = Callable[[EngineConfig, dict[str, Any]], Any]


async def execute(sm: async_sessionmaker[AsyncSession], env: Any, *, run_id: int | None = None,
                  trigger: str = "scan", scan_id: int | None = None, requested_by: str | None = None,
                  context_factory: ContextFactory | None = None) -> int:
    """Run the engine once and persist it. `run_id` = a claimed (running) queued row; otherwise a
    new row is created. Never raises for assertion problems; returns the run id."""
    from .. import app_settings
    from .context import build_context
    from .models import ControlAssertionResult, ControlAssertionRun, ControlStatusRow

    async with sm() as s:
        st = await app_settings.load(s, env)
    try:
        async with sm() as s:
            snapshot: dict[str, Any] | None = await load_snapshot(s, st)
    except Exception:  # noqa: BLE001  (pack assertions become `unknown`)
        log.exception("controls.snapshot_failed")
        snapshot = None
    cfg = engine_config(env, st)
    ce = getattr(st, "controls_engine", None)
    async with sm() as s, s.begin():
        if run_id is None:
            row = ControlAssertionRun(status="running", trigger=trigger, scan_id=scan_id, requested_by=requested_by,
                                      baseline=cfg.baseline, started_at=datetime.now(UTC), summary={})
            s.add(row)
            await s.flush()
            run_id = row.id
        else:
            row = await s.get(ControlAssertionRun, run_id)
            row.baseline = cfg.baseline
        if row.scan_id is None and snapshot and snapshot.get("lastDoneScan"):
            row.scan_id = snapshot["lastDoneScan"].get("id")  # M3: the scan whose evidence this run used
    ctx = None
    try:
        ctx = await (context_factory(cfg, snapshot) if context_factory else build_context(cfg, snapshot))
        outcomes = await run_assertions(ctx)
        statuses = derive_statuses(outcomes, baseline=cfg.baseline,
                                   not_applicable=dict(getattr(ce, "not_applicable", None) or {}),
                                   inherit_organizational=bool(getattr(ce, "inherit_organizational_controls", False)),
                                   providers=list(getattr(ce, "common_control_providers", None) or []),
                                   scan=scan_evidence(snapshot, cfg.system_namespaces))
        summary = summarize(statuses, outcomes, cfg.baseline)
        if ctx.keycloak_error:
            summary["keycloak"] = ctx.keycloak_error
    except Exception as e:  # noqa: BLE001
        log.exception("controls.run_failed", run_id=run_id)
        async with sm() as s, s.begin():
            row = await s.get(ControlAssertionRun, run_id)
            row.status, row.finished_at, row.error = "failed", datetime.now(UTC), str(e)[:2000]
        return run_id
    finally:
        http = getattr(ctx, "http", None)
        if http is not None and context_factory is None:
            await http.aclose()
    async with sm() as s, s.begin():
        for o in outcomes:
            s.add(ControlAssertionResult(run_id=run_id, assertion_id=o.id, title=o.title, component=o.component,
                                         controls=o.controls, severity=o.severity, status=o.status, detail=o.detail,
                                         evidence=_jsonable(o.evidence), duration_ms=o.duration_ms,
                                         checked_at=o.checked_at))
        for c in statuses:
            s.add(ControlStatusRow(run_id=run_id, control=c.control, oscal_id=c.id, family=c.family,
                                   baseline=c.baseline, in_baseline=c.in_baseline, status=c.status,
                                   components=c.components, assertions=c.assertions, detail=c.detail[:4000],
                                   score=c.score, responsibility=c.responsibility, provider=c.provider,
                                   objectives=c.objectives, inputs=c.inputs))
        row = await s.get(ControlAssertionRun, run_id)
        row.status, row.finished_at, row.summary = "done", datetime.now(UTC), summary
    await prune(sm)
    log.info("controls.run_done", run_id=run_id, trigger=trigger, baseline=cfg.baseline,
             passing=summary["passing"], partial=summary["partial"],
             failing=summary["failing"], not_assessed=summary["notAssessed"],
             assertions_failed=summary["assertions"][FAIL])
    return run_id


def _jsonable(v: Any) -> Any:
    if isinstance(v, dict):
        return {str(k): _jsonable(x) for k, x in v.items()}
    if isinstance(v, (list, tuple, set)):
        return [_jsonable(x) for x in v]
    if isinstance(v, datetime):
        return _iso(v)
    if v is None or isinstance(v, (str, int, float, bool)):
        return v
    return str(v)


async def prune(sm: async_sessionmaker[AsyncSession], keep: int = KEEP_RUNS) -> None:
    from .models import ControlAssertionRun

    async with sm() as s, s.begin():
        ids = [r for (r,) in (await s.execute(select(ControlAssertionRun.id).where(
            ControlAssertionRun.status.in_(("done", "failed"))).order_by(ControlAssertionRun.id.desc())
            .offset(keep))).all()]
        if ids:
            await s.execute(delete(ControlAssertionRun).where(ControlAssertionRun.id.in_(ids)))


# ------------------------------------------------------------------------- reads (API / reports)
async def latest_run(session: AsyncSession, scan_id: int | None = None) -> Any:
    """Latest finished run; with `scan_id`, the latest run made from that scan when one exists (M3:
    reports of one scan all use the same control evidence run)."""
    from .models import ControlAssertionRun

    q = select(ControlAssertionRun).where(ControlAssertionRun.status == "done")
    if scan_id is not None:
        row = (await session.execute(q.where(ControlAssertionRun.scan_id == scan_id)
                                     .order_by(ControlAssertionRun.id.desc()).limit(1))).scalar_one_or_none()
        if row is not None:
            return row
    return (await session.execute(q.order_by(ControlAssertionRun.id.desc()).limit(1))).scalar_one_or_none()


def run_dict(r: Any) -> dict[str, Any]:
    return {"id": r.id, "status": r.status, "trigger": r.trigger, "scanId": r.scan_id, "requestedBy": r.requested_by,
            "baseline": r.baseline, "createdAt": _iso(r.created_at), "startedAt": _iso(r.started_at),
            "finishedAt": _iso(r.finished_at), "summary": r.summary or {}, "error": r.error}


def result_dict(r: Any) -> dict[str, Any]:
    return {"id": r.assertion_id, "title": r.title, "component": r.component, "controls": r.controls or [],
            "severity": r.severity, "status": r.status, "detail": r.detail, "evidence": r.evidence or {},
            "durationMs": r.duration_ms, "checkedAt": _iso(r.checked_at), "runId": r.run_id}


async def latest_data(session: AsyncSession, scan_id: int | None = None) -> dict[str, Any] | None:
    """{run, results[], statuses[]} of the latest finished run (for routers and the reports; with
    `scan_id`, preferably the run made from that scan)."""
    from .models import ControlAssertionResult, ControlStatusRow

    run = await latest_run(session, scan_id)
    if run is None:
        return None
    results = [result_dict(r) for r in (await session.execute(
        select(ControlAssertionResult).where(ControlAssertionResult.run_id == run.id)
        .order_by(ControlAssertionResult.assertion_id))).scalars()]
    statuses = [{"control": c.control, "id": c.oscal_id, "family": c.family, "baseline": c.baseline,
                 "inBaseline": c.in_baseline, "status": c.status, "components": c.components or [],
                 "assertions": c.assertions or [], "detail": c.detail, "score": c.score,
                 "responsibility": c.responsibility, "provider": c.provider, "objectives": c.objectives or [],
                 "inputs": c.inputs or {}}
                for c in (await session.execute(select(ControlStatusRow).where(ControlStatusRow.run_id == run.id)))
                .scalars()]
    return {"run": run_dict(run), "results": results, "statuses": statuses}
