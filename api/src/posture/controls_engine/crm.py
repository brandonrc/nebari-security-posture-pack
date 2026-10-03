"""Customer Responsibility Matrix (compliance review M1 / S6 / §8).

One row per control in scope: who implements it (`provider` = the Nebari platform, `shared` =
platform mechanism + program decisions, `customer` = the program, `org` = the organization or an
external common control provider), what the platform provides (component statements), what the
program must still do (customer responsibility), and the platform's current evidence status.
This is a *draft* CRM: inheritance becomes real only once the platform is assessed and authorized.
"""

from __future__ import annotations

from typing import Any

from .catalog import get_catalog, to_label
from .components import Component, load_components, requirements_by_control
from .engine import CUSTOMER_DEFAULT, ORG_DEFAULT

RESPONSIBILITY_LABEL = {"provider": "Provided (platform)", "shared": "Shared / hybrid", "customer": "Customer (program)",
                        "org": "Organization / common control provider"}


def crm_rows(statuses: list[dict[str, Any]], *, components: dict[str, Component] | None = None,
             baseline_only: bool = True) -> list[dict[str, Any]]:
    """`statuses` = engine status dicts (`latest_data()["statuses"]` or `ControlResult`-shaped dicts)."""
    catalog = get_catalog()
    components = load_components() if components is None else components
    reqs = requirements_by_control(components)
    out = []
    for s in statuses:
        if baseline_only and not s.get("inBaseline", True):
            continue
        label = to_label(s["control"])
        cat = catalog.get(label)
        declared = reqs.get(label, [])
        resp = s.get("responsibility") or ("org" if cat is not None and cat.implementation_level == "organization"
                                           else "customer")
        provided = [f"{comp.title}: {req.statement}" for comp, req in declared if req.responsibility != "org"]
        external = [f"{comp.title}: {req.statement}" for comp, req in declared if req.responsibility == "org"]
        customer = [req.customer for _, req in declared if req.customer]
        if not customer:
            customer = [ORG_DEFAULT if resp == "org" else CUSTOMER_DEFAULT] if resp != "provider" else []
        out.append({
            "control": label, "title": cat.full_title if cat else label, "family": s.get("family") or label[:2],
            "baseline": s.get("baseline"), "inBaseline": bool(s.get("inBaseline", True)),
            "responsibility": resp, "responsibilityLabel": RESPONSIBILITY_LABEL.get(resp, resp),
            "status": s.get("status"), "commonControlProvider": s.get("provider"),
            "platformProvides": " ".join(provided), "externallyProvided": " ".join(external),
            "customerResponsibility": " ".join(dict.fromkeys(customer)),
            "components": list(s.get("components") or []), "assertions": list(s.get("assertions") or []),
            "objectives": s.get("objectives") or [], "detail": s.get("detail") or "",
        })
    out.sort(key=lambda r: catalog.sort_key(r["control"]))
    return out


def crm_summary(rows: list[dict[str, Any]]) -> dict[str, int]:
    out = {k: 0 for k in RESPONSIBILITY_LABEL}
    for r in rows:
        out[r["responsibility"]] = out.get(r["responsibility"], 0) + 1
    return out
