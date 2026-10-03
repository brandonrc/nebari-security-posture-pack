"""OSCAL-style component definitions (`data/components/*.yaml`)."""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

import yaml

from .catalog import to_label

COMPONENTS_DIR = Path(__file__).parent / "data" / "components"
# Customer Responsibility Matrix vocabulary (S6): who implements a control (part).
#   provider - the Nebari platform implements it completely (inheritable once the platform is authorized)
#   shared   - the platform supplies the mechanism; the program completes it (hybrid)
#   customer - the program (tenant system) implements it
#   org      - the organization / an external common control provider (facility, CSP, policy owner)
RESPONSIBILITIES = ("provider", "shared", "customer", "org")
COMPONENT_TYPES = ("software", "service", "hardware", "policy", "interconnection", "process", "plan", "guidance",
                   "standard", "validation", "this-system")


@dataclass(frozen=True)
class Requirement:
    control: str  # label form, AC-6(10)
    statement: str
    inherited: bool = False  # legacy flag: provided outside this platform (implies responsibility `org`)
    assertions: tuple[str, ...] = ()
    responsibility: str = "provider"
    customer: str = ""  # residual responsibility of the program (CRM text); required unless `provider`
    # 800-53A objectives explicitly assigned to the program / organization (described by `customer`);
    # `rest` = every objective of the control this platform does not evidence (M2)
    assigned: tuple[str, ...] = ()
    # evidence ceiling (compliance review M4 "partial" rows): the platform's evidence can never show
    # this control as more than `partial`, with the reason (e.g. ciphers recorded but not graded)
    ceiling: str | None = None
    ceiling_reason: str = ""


@dataclass(frozen=True)
class Component:
    id: str
    uuid: str
    title: str
    type: str
    description: str
    purpose: str = ""
    requirements: tuple[Requirement, ...] = field(default_factory=tuple)


def _assigned(v: object) -> tuple[str, ...]:
    if not v:
        return ()
    if isinstance(v, str):
        return (v.strip().lower(),)
    return tuple(str(x).strip().lower() for x in v)  # type: ignore[union-attr]


def parse_component(data: dict) -> Component:
    reqs = []
    for r in data.get("implemented-requirements") or []:
        inherited = bool(r.get("inherited", False))
        resp = str(r.get("responsibility") or ("org" if inherited else "provider"))
        if resp not in RESPONSIBILITIES:
            raise ValueError(f"component {data.get('id')} {r.get('control')}: unknown responsibility {resp!r}")
        reqs.append(Requirement(control=to_label(str(r["control"])), statement=str(r.get("statement") or "").strip(),
                                inherited=inherited, assertions=tuple(r.get("assertions") or ()),
                                responsibility=resp, customer=str(r.get("customer") or "").strip(),
                                assigned=_assigned(r.get("assigned")), ceiling=r.get("ceiling") or None,
                                ceiling_reason=str(r.get("ceilingReason") or "").strip()))
    ctype = data.get("type", "software")
    if ctype not in COMPONENT_TYPES:
        raise ValueError(f"component {data.get('id')}: unknown type {ctype!r}")
    return Component(id=data["id"], uuid=str(data["uuid"]), title=data["title"], type=ctype,
                     description=str(data.get("description") or "").strip(), purpose=str(data.get("purpose") or ""),
                     requirements=tuple(reqs))


@lru_cache
def load_components(directory: Path = COMPONENTS_DIR) -> dict[str, Component]:
    out: dict[str, Component] = {}
    for path in sorted(directory.glob("*.yaml")):
        comp = parse_component(yaml.safe_load(path.read_text(encoding="utf-8")))
        if comp.id in out:
            raise ValueError(f"duplicate component id {comp.id!r} ({path.name})")
        out[comp.id] = comp
    return out


def requirements_by_control(components: dict[str, Component]) -> dict[str, list[tuple[Component, Requirement]]]:
    out: dict[str, list[tuple[Component, Requirement]]] = {}
    for comp in components.values():
        for req in comp.requirements:
            out.setdefault(req.control, []).append((comp, req))
    return out
