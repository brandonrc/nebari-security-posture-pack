"""NIST 800-53 control mapping loaded from reports/data/controls.yaml."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

CONTROLS_FILE = Path(__file__).parent / "reports" / "data" / "controls.yaml"


@lru_cache
def load_controls() -> dict[str, Any]:
    with CONTROLS_FILE.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def vuln_controls(fixable: bool) -> list[str]:
    v = load_controls().get("vulnerabilities") or {}
    return list(v.get("fixable" if fixable else "default") or [])


def check_controls(check_id: str) -> list[str]:
    return list((load_controls().get("checks") or {}).get(check_id) or [])


def control_title(control: str) -> str | None:
    return (load_controls().get("titles") or {}).get(control)


def all_controls() -> list[str]:
    data = load_controls()
    seen: list[str] = []
    for group in [*(data.get("vulnerabilities") or {}).values(), *(data.get("checks") or {}).values()]:
        for c in group or []:
            if c not in seen:
                seen.append(c)
    return seen


def scan_objectives(kind: str, control: str) -> list[str] | None:
    """800-53A objectives that failing scan evidence counts against (M3). `kind`: `open`, `overdue`
    (findings) or `posture`. None = every objective of the control."""
    so = load_controls().get("scanObjectives") or {}
    table = (so.get("findings") or {}).get(kind) if kind in ("open", "overdue") else so.get("posture")
    v = (table or {}).get(control)
    return list(v) if v else None


def finding_objective_controls(kind: str) -> list[str]:
    """Controls whose status open (`open`) or SLA-overdue (`overdue`) findings downgrade."""
    so = load_controls().get("scanObjectives") or {}
    return list(((so.get("findings") or {}).get(kind) or {}).keys())
