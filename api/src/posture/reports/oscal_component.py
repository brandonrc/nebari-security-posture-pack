"""OSCAL 1.1.2 component-definition report for the Nebari platform components (DESIGN §13)."""

from __future__ import annotations

import json
from typing import Any

from ._common import filename, normalize
from .registry import GeneratedReport


def generate(fmt: str, snapshot: Any, options: dict[str, Any]) -> GeneratedReport:
    from ..controls_engine.ssp import build_component_definition

    v = normalize(snapshot, options)
    doc = build_component_definition(organization=v.system.organization, generated_at=v.generated_at)
    data = json.dumps(doc, indent=2, ensure_ascii=False).encode("utf-8")
    return GeneratedReport(data, filename(v, "oscal-component-definition", "json"), "application/json")
