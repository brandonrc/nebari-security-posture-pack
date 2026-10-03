"""OSCAL 1.1.2 `system-security-plan` and `component-definition` documents (DESIGN §13).

* component-definition: one component per `data/components/*.yaml`, each with a
  control-implementation against the NIST SP 800-53 rev5 catalog; implemented-requirements carry
  the statement plus props naming the live assertions that prove them.
* system-security-plan: imports the official LOW/MODERATE/HIGH baseline profile; one
  implemented-requirement per control in the baseline (plus any control a component addresses)
  with the derived status (prop `implementation-status`), by-components with OSCAL
  implementation-status, and links to back-matter evidence resources (one per assertion
  result, evidence JSON embedded as base64).

UUIDs are deterministic (v5) per system name / control / component.
"""

from __future__ import annotations

import base64
import json
import uuid
from datetime import UTC, datetime
from typing import Any

from .assertions import all_assertions
from .catalog import BASELINES, get_catalog, to_oscal_id
from .components import Component, load_components, requirements_by_control
from .engine import (
    DEFAULT_ORG_STATEMENT,
    FAILING,
    HYBRID,
    INHERITED,
    NOT_APPLICABLE,
    NOT_ASSESSED,
    ORG_PROVIDED,
    PARTIAL,
    PASSING,
    derive_statuses,
    providers_by_control,
)

OSCAL_VERSION = "1.1.2"
NS = "https://nebari.dev/ns/oscal"
UUID_NS = uuid.UUID("8c6f0f0e-5d0b-4e7e-9b8a-3f1f6a0c2d41")
PROFILE_URL = ("https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/"
               "NIST_SP-800-53_rev5_{level}-baseline_profile.json")
CATALOG_URL = ("https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/"
               "NIST_SP-800-53_rev5_catalog.json")
# Evidence status -> OSCAL implementation-status (compliance review M2). org-provided-unverified and
# not-assessed carry no OSCAL state: nothing is asserted for them. `failing` is `planned` only when a
# POA&M item tracks it, otherwise `not-implemented`.
OSCAL_STATE = {PASSING: "implemented", PARTIAL: "partial", HYBRID: "partial", INHERITED: "implemented",
               NOT_APPLICABLE: "not-applicable"}


def oscal_state(status: str, label: str, poam_controls: set[str] | None) -> str | None:
    if status == FAILING:
        return "planned" if poam_controls and label in poam_controls else "not-implemented"
    return OSCAL_STATE.get(status)
TOOL = "Nebari Security Posture Pack"


def _uid(*parts: Any) -> str:
    return str(uuid.uuid5(UUID_NS, "|".join(str(p) for p in parts)))


def _prop(name: str, value: Any, ns: bool = True) -> dict[str, str]:
    p = {"name": name, "value": str(value)}
    if ns:
        p["ns"] = NS
    return p


def _iso(dt: datetime | None) -> str:
    dt = dt or datetime.now(UTC)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _text(s: str | None) -> str:
    return (s or "").strip() or "-"


def _metadata(title: str, organization: str, generated_at: datetime, version: str, seed: str) -> dict[str, Any]:
    md: dict[str, Any] = {"title": title, "last-modified": _iso(generated_at), "version": version,
                          "oscal-version": OSCAL_VERSION,
                          "props": [_prop("generator", TOOL)]}
    party = _uid(seed, "party", organization or "organization")
    md["roles"] = [{"id": "system-owner", "title": "System Owner"},
                   {"id": "prepared-by", "title": "Prepared By"}]
    md["parties"] = [{"uuid": party, "type": "organization", "name": organization or "Organization"}]
    md["responsible-parties"] = [{"role-id": "system-owner", "party-uuids": [party]}]
    return md


# ------------------------------------------------------------------ component-definition
def build_component_definition(components: dict[str, Component] | None = None, *, organization: str = "",
                               generated_at: datetime | None = None) -> dict[str, Any]:
    components = load_components() if components is None else components
    catalog = get_catalog()
    by_id = {a.id: a for a in all_assertions()}
    out_components = []
    for comp in components.values():
        reqs = []
        for req in comp.requirements:
            props = [_prop("assertion", a) for a in req.assertions]
            props.append(_prop("responsibility", req.responsibility))
            r: dict[str, Any] = {"uuid": _uid("compdef", comp.id, req.control), "control-id": to_oscal_id(req.control),
                                 "description": _text(req.statement)}
            if props:
                r["props"] = props
            titles = [by_id[a].title for a in req.assertions if a in by_id]
            if titles:
                r["remarks"] = "Evidence collected by: " + "; ".join(titles) + "."
            if req.customer:  # CRM: the residual responsibility of a consuming system
                r["remarks"] = (r.get("remarks", "") + " Customer responsibility: " + req.customer).strip()
            reqs.append(r)
        c: dict[str, Any] = {"uuid": comp.uuid, "type": comp.type, "title": comp.title,
                             "description": _text(comp.description)}
        if comp.purpose:
            c["purpose"] = comp.purpose
        if reqs:
            c["control-implementations"] = [{
                "uuid": _uid("compdef", comp.id, "control-implementation"), "source": CATALOG_URL,
                "description": f"{comp.title} implementation of NIST SP 800-53 rev5 controls in a Nebari platform "
                               f"({catalog.meta.get('title', 'NIST SP 800-53 rev5')}).",
                "implemented-requirements": reqs}]
        out_components.append(c)
    return {"component-definition": {
        "uuid": _uid("component-definition", organization),
        "metadata": _metadata("Nebari platform component definitions (NIST SP 800-53 rev5)", organization,
                              generated_at or datetime.now(UTC), "1.0", "component-definition"),
        "components": out_components,
    }}


# ------------------------------------------------------------------ system-security-plan
def build_ssp(engine_data: dict[str, Any] | None, *, system_name: str = "Nebari", organization: str = "",
              baseline: str = "moderate", generated_at: datetime | None = None, description: str = "",
              organization_statement: str = "", not_applicable: dict[str, str] | None = None,
              inherit_organizational: bool = False, providers: list[Any] | None = None,
              components: dict[str, Component] | None = None,
              poam_controls: set[str] | None = None, scan_id: Any = None) -> dict[str, Any]:
    """`engine_data` = `engine.latest_data()` ({run, results[], statuses[]}) or None (engine never ran)."""
    if baseline not in BASELINES:
        raise ValueError(f"unknown baseline {baseline!r}")
    generated_at = generated_at or datetime.now(UTC)
    catalog = get_catalog()
    components = load_components() if components is None else components
    reqs = requirements_by_control(components)
    seed = f"ssp|{system_name}"
    org_statement = organization_statement.strip() or DEFAULT_ORG_STATEMENT
    run = (engine_data or {}).get("run") or {}
    results = {r["id"]: r for r in (engine_data or {}).get("results") or []}
    if engine_data and engine_data.get("statuses"):
        statuses = [dict(s) for s in engine_data["statuses"]]
        run_baseline = run.get("baseline")
        if run_baseline != baseline:  # re-derive the baseline flag for the requested baseline
            for s in statuses:
                c = catalog.get(s["control"])
                s["inBaseline"] = bool(c and c.in_baseline(baseline))
        present = {s["control"] for s in statuses}
        for c in catalog.baseline(baseline):
            if c.label not in present:
                statuses.append({"control": c.label, "status": NOT_ASSESSED, "components": [], "assertions": [],
                                 "detail": "not evaluated by the latest engine run", "inBaseline": True})
    else:
        statuses = [{"control": r.control, "status": r.status, "components": r.components,
                     "assertions": r.assertions, "detail": r.detail, "inBaseline": r.in_baseline,
                     "responsibility": r.responsibility, "provider": r.provider}
                    for r in derive_statuses([], baseline=baseline, components=components, not_applicable=not_applicable,
                                             inherit_organizational=inherit_organizational, providers=providers)]
    statuses.sort(key=lambda s: catalog.sort_key(s["control"]))

    this_system = _uid(seed, "this-system")
    comp_uuid = {c.id: c.uuid for c in components.values()}
    sys_components = [{
        "uuid": this_system, "type": "this-system", "title": system_name,
        "description": _text(description or f"{system_name}: Nebari data-science platform on Kubernetes."),
        "status": {"state": "operational"}}]
    for comp in components.values():
        c = {"uuid": comp.uuid, "type": comp.type, "title": comp.title, "description": _text(comp.description),
             "status": {"state": "operational"}}
        if comp.purpose:
            c["purpose"] = comp.purpose
        sys_components.append(c)

    # M1: inheritance only from named, authorized common control providers (leveraged authorizations)
    ccp_list = [p if isinstance(p, dict) else p.model_dump(by_alias=True) for p in providers or []]
    leveraged, ccp_comp, ccp_parties = [], {}, []
    for p in ccp_list:
        name = p.get("name") or "Common control provider"
        party = _uid(seed, "ccp-party", name)
        ccp_parties.append({"uuid": party, "type": "organization", "name": name})
        la_uuid = _uid(seed, "leveraged-authorization", name)
        la: dict[str, Any] = {"uuid": la_uuid, "title": f"{name} authorization", "party-uuid": party,
                              "date-authorized": p.get("dateAuthorized") or "1970-01-01"}
        if p.get("authorizationRef"):
            la["props"] = [_prop("authorization-reference", p["authorizationRef"])]
        if not p.get("dateAuthorized"):
            la["remarks"] = "DRAFT: date-authorized not configured (controlsEngine.commonControlProviders[].dateAuthorized)."
        leveraged.append(la)
        ccp_comp[name] = _uid(seed, "ccp-component", name)
        sys_components.append({
            "uuid": ccp_comp[name], "type": "system", "title": name,
            "description": _text(p.get("statement") or f"Common control provider {name}."),
            "props": [{"name": "leveraged-authorization-uuid", "value": la_uuid},
                      {"name": "implementation-point", "value": "external"}],
            "status": {"state": "operational"}})

    resources: list[dict[str, Any]] = []
    res_uuid: dict[str, str] = {}
    for rid, r in sorted(results.items()):
        res_uuid[rid] = _uid(seed, "evidence", rid, run.get("id"))
        payload = json.dumps({k: r.get(k) for k in ("id", "title", "status", "detail", "controls", "component",
                                                     "checkedAt", "evidence")}, sort_keys=True, default=str)
        resources.append({
            "uuid": res_uuid[rid], "title": f"Assertion {rid}: {r.get('title', '')}",
            "description": f"{r.get('status', 'unknown').upper()}: {_text(r.get('detail'))}",
            "props": [_prop("assertion-id", rid), _prop("assertion-status", r.get("status", "unknown")),
                      _prop("checked-at", r.get("checkedAt") or _iso(generated_at))],
            "rlinks": [{"href": f"/api/v1/compliance/assertions/{rid}", "media-type": "application/json"}],
            "base64": {"filename": f"{rid}.json", "media-type": "application/json",
                       "value": base64.b64encode(payload.encode()).decode()},
        })

    impl = []
    for s in statuses:
        label = s["control"]
        cat = catalog.get(label)
        status = s["status"]
        state = oscal_state(status, label, poam_controls)
        by_components = []
        declared = reqs.get(label, [])
        claimed = {comp.id for comp, _ in declared}
        provider = s.get("provider")
        if status == INHERITED and provider in ccp_comp:
            p = next(x for x in ccp_list if x.get("name") == provider)
            by_components.append({
                "component-uuid": ccp_comp[provider], "uuid": _uid(seed, label, "ccp", provider),
                "description": _text(p.get("statement") or f"Inherited from {provider}."),
                "implementation-status": {"state": "implemented"},
                "inherited": [{"uuid": _uid(seed, label, "inherited", provider),
                               "description": _text(p.get("statement") or f"Provided by {provider}.")}]})
        for comp, req in declared:
            bc: dict[str, Any] = {"component-uuid": comp.uuid, "uuid": _uid(seed, label, comp.id),
                                  "description": _text(req.statement),
                                  "props": [_prop("responsibility", req.responsibility)]}
            if state and status != INHERITED:
                bc["implementation-status"] = {"state": state}
            if req.customer:  # CRM: what a consuming system must still do
                bc["export"] = {"responsibilities": [{"uuid": _uid(seed, label, comp.id, "responsibility"),
                                                      "description": req.customer}]}
            by_components.append(bc)
        for cid in s.get("components") or []:
            if cid not in claimed and cid in comp_uuid:
                titles = [results[a]["title"] for a in s.get("assertions") or [] if a in results
                          and results[a].get("component") == cid]
                bc = {"component-uuid": comp_uuid[cid], "uuid": _uid(seed, label, cid),
                      "description": "Verified by: " + ("; ".join(titles) or "live assertions") + "."}
                if state:
                    bc["implementation-status"] = {"state": state}
                by_components.append(bc)
        if not by_components:
            desc = org_statement if status == ORG_PROVIDED else _text(s.get("detail"))
            bc = {"component-uuid": this_system, "uuid": _uid(seed, label, "this-system"), "description": desc}
            if state:
                bc["implementation-status"] = {"state": state}
            by_components.append(bc)
        props = [_prop("implementation-status", status)]
        if s.get("responsibility"):
            props.append(_prop("responsibility", s["responsibility"]))
        if cat and cat.lowest_baseline:
            props.append(_prop("baseline", cat.lowest_baseline))
        if not s.get("inBaseline", True):
            props.append(_prop("in-selected-baseline", "false"))
        ir: dict[str, Any] = {"uuid": _uid(seed, "implemented-requirement", label), "control-id": to_oscal_id(label),
                              "props": props, "by-components": by_components}
        links = [{"href": f"#{res_uuid[a]}", "rel": "evidence", "text": a} for a in s.get("assertions") or []
                 if a in res_uuid]
        if links:
            ir["links"] = links
        if s.get("detail"):
            ir["remarks"] = s["detail"]
        impl.append(ir)

    level = f"fips-199-{baseline}"
    in_b = [s for s in statuses if s.get("inBaseline", True)]
    counts = {k: sum(s["status"] == k for s in in_b) for k in
              (PASSING, PARTIAL, FAILING, HYBRID, INHERITED, ORG_PROVIDED, NOT_APPLICABLE, NOT_ASSESSED)}
    doc = {
        "uuid": _uid(seed, "ssp"),
        "metadata": _metadata(f"System Security Plan: {system_name}", organization, generated_at,
                              str(run.get("id") or "draft"), seed),
        "import-profile": {"href": PROFILE_URL.format(level=baseline.upper()),
                           "remarks": f"NIST SP 800-53 rev5 {baseline.upper()} baseline (official profile)."},
        "system-characteristics": {
            "system-ids": [{"identifier-type": "https://ietf.org/rfc/rfc4122", "id": _uid(seed, "system-id")}],
            "system-name": system_name,
            "description": _text(description or f"{system_name}: Nebari platform (Kubernetes, Keycloak, Envoy "
                                                "Gateway, cert-manager, observability stack and data-science packs)."),
            "props": [_prop("control-evidence-run", run.get("id") or "none"),
                      *([_prop("scan-id", scan_id)] if scan_id not in (None, "") else []),
                      *([_prop("control-evidence-scan-id", run["scanId"])] if run.get("scanId") else []),
                      _prop("control-evidence-checked-at", run.get("finishedAt") or "never"),
                      *[_prop(f"controls-{k}", v) for k, v in counts.items()]],
            "security-sensitivity-level": level,
            "system-information": {"information-types": [{
                "uuid": _uid(seed, "information-type"), "title": "Platform and research data",
                "description": "Information processed by users of the platform's applications; set the NIST SP "
                               "800-60 information types for this system before submission.",
                "categorizations": [{"system": "http://doi.org/10.6028/NIST.SP.800-60v2r1",
                                     "information-type-ids": ["C.3.5.8"]}],
                "confidentiality-impact": {"base": level}, "integrity-impact": {"base": level},
                "availability-impact": {"base": level}}]},
            "security-impact-level": {"security-objective-confidentiality": level,
                                      "security-objective-integrity": level,
                                      "security-objective-availability": level},
            "status": {"state": "operational"},
            "authorization-boundary": {"description": "The Kubernetes cluster running the Nebari platform: its "
                                                      "nodes, control plane, platform services and every "
                                                      "namespace and workload inventoried by the posture pack."},
        },
        "system-implementation": {
            "users": [{"uuid": _uid(seed, "user", "admin"), "title": "Platform administrator",
                       "role-ids": ["system-owner"],
                       "description": "Members of the Keycloak administrator group."},
                      {"uuid": _uid(seed, "user", "user"), "title": "Platform user",
                       "description": "Authenticated Keycloak users of Nebari applications."}],
            "components": sys_components,
            **({"leveraged-authorizations": leveraged} if leveraged else {}),
        },
        "control-implementation": {
            "description": f"Implementation of the NIST SP 800-53 rev5 {baseline.upper()} baseline. Statuses are "
                           "derived from live assertions run by the control evidence engine"
                           + (f" (run {run['id']} at {run.get('finishedAt')})" if run.get("id") else
                              " (the engine has not run yet: statuses reflect component declarations only)") + ".",
            "implemented-requirements": impl,
        },
    }
    if ccp_parties:
        doc["metadata"]["parties"].extend(ccp_parties)
    if resources:
        doc["back-matter"] = {"resources": resources}
    return {"system-security-plan": doc}
