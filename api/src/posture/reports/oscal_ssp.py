"""OSCAL 1.1.2 system-security-plan report (DESIGN §13). The control evidence engine's latest
run is attached to the snapshot as `controls_engine` by report_jobs (controls_engine.reporting)."""

from __future__ import annotations

import json
from typing import Any

from ._common import filename, get, normalize
from .registry import GeneratedReport


def generate(fmt: str, snapshot: Any, options: dict[str, Any]) -> GeneratedReport:
    from ..controls_engine.ssp import build_ssp

    v = normalize(snapshot, options)
    ce = get(snapshot, "controls_engine") or {}
    doc = build_ssp(ce.get("data"), system_name=v.system.name, organization=v.system.organization,
                    baseline=(options.get("baseline") or ce.get("baseline") or "moderate").lower(),
                    generated_at=v.generated_at, description=v.system.description,
                    organization_statement=ce.get("organizationStatement") or "",
                    not_applicable=ce.get("notApplicable") or {},
                    inherit_organizational=bool(ce.get("inheritOrganizationalControls", False)),
                    providers=ce.get("commonControlProviders") or [])
    data = json.dumps(doc, indent=2, ensure_ascii=False).encode("utf-8")
    return GeneratedReport(data, filename(v, "oscal-ssp", "json"), "application/json")
