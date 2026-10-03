"""OSCAL 1.1.2 plan-of-action-and-milestones (report type `oscal-poam`, compliance review S3).

The same items as the `poam` workbook (same granularity, baseline filtering and External UIDs),
as the machine-readable OSCAL POA&M model: one risk per item (deadline, characterizations,
remediation with its milestone) and one poam-item pointing at it. UUIDs are deterministic (v5) per
system and External UID, so a regenerated document updates rather than duplicates items.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

from ._common import TOOL_NAME, filename, iso, normalize
from .oscal import NS, OSCAL_VERSION, _prop
from .registry import GeneratedReport

UUID_NS = uuid.UUID("0f9c9b52-8d2e-4e47-9a7e-5c1d2b3a4f61")


def build(v: Any) -> dict[str, Any]:
    from .poam import build_items, poam_baseline

    def uid(*parts: Any) -> str:
        return str(uuid.uuid5(UUID_NS, f"{v.system.name}|" + "|".join(str(p) for p in parts)))

    items = build_items(v)
    tool = uid("component", "pack")
    risks, poam_items = [], []
    for i in items:
        r_uuid = uid("risk", i.poam_id)
        facets = [{"name": "severity", "system": NS, "value": i.severity},
                  {"name": "known-exploited", "system": NS, "value": str(bool(i.kev)).lower()},
                  {"name": "likelihood", "system": NS, "value": "not-assessed"},
                  {"name": "impact", "system": NS, "value": "not-assessed"}]
        risk: dict[str, Any] = {
            "uuid": r_uuid, "title": i.name[:500], "description": (i.description or "-")[:30000],
            "statement": f"{i.title}. Controls: {', '.join(i.controls)}.",
            "props": [_prop("external-uid", i.poam_id), _prop("overdue", str(bool(i.overdue)).lower())],
            "status": "open",
            "characterizations": [{"origin": {"actors": [{"type": "tool", "actor-uuid": tool}]}, "facets": facets}],
            "remediations": [{"uuid": uid("remediation", i.poam_id), "lifecycle": "planned",
                              "title": "Remediation", "description": (i.plan or "-")[:30000],
                              **({"tasks": [{"uuid": uid("milestone", i.poam_id), "type": "milestone",
                                             "title": "Scheduled completion",
                                             "timing": {"on-date": {"date": iso(i.due)}}}]} if i.due else {})}],
        }
        if i.due:
            risk["deadline"] = iso(i.due)
        risks.append(risk)
        props = [_prop("external-uid", i.poam_id), _prop("kind", i.kind), _prop("raw-severity", i.severity),
                 *[_prop("control", c) for c in i.controls], *[_prop("cci", c) for c in i.ccis]]
        if i.kev:
            props.append(_prop("kev-due-date", iso(i.kev_due)[:10] if i.kev_due else "unknown"))
        poam_items.append({
            "uuid": uid("poam-item", i.poam_id), "title": i.name[:500], "description": (i.description or "-")[:30000],
            "props": props, "related-risks": [{"risk-uuid": r_uuid}],
            "remarks": (i.comments or "-")[:30000],
        })
    doc: dict[str, Any] = {
        "uuid": uid("poam"),
        "metadata": {"title": f"{v.system.name} - Plan of Action and Milestones ({v.run_stamp})",
                     "last-modified": iso(v.generated_at), "version": str(v.scan.id), "oscal-version": OSCAL_VERSION,
                     "props": [_prop("generator", TOOL_NAME), _prop("scan-id", v.scan.id),
                               _prop("control-evidence-run", v.engine_run.get("id") or "none"),
                               _prop("control-set", poam_baseline(v)), _prop("document-status", "draft")],
                     "remarks": "Machine-generated starting point for ISSO review: risk analysis (likelihood, "
                                "impact, residual risk), mitigations and approvals are not determined by the tool."},
        "import-ssp": {"href": filename(v, "oscal-ssp", "json")},
        "system-id": {"identifier-type": "https://ietf.org/rfc/rfc4122", "id": uid("system")},
        "local-definitions": {"components": [{"uuid": tool, "type": "software", "title": TOOL_NAME,
                                              "description": "Automated scanning, posture checks and control "
                                                             "assertions.", "status": {"state": "operational"}}]},
        "poam-items": poam_items or [{"uuid": uid("poam-item", "none"), "title": "No open items",
                                      "description": "The scan and control evidence run produced no open items."}],
    }
    if risks:
        doc["risks"] = risks
    return {"plan-of-action-and-milestones": doc}


def generate(fmt: str, snapshot: Any, options: dict[str, Any]) -> GeneratedReport:
    v = normalize(snapshot, options)
    data = json.dumps(build(v), indent=2, ensure_ascii=False).encode("utf-8")
    return GeneratedReport(data, filename(v, "oscal-poam", "json"), "application/json")
