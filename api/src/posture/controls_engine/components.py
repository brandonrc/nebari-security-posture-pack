"""OSCAL-style component definitions (`data/components/*.yaml`)."""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

import yaml

from .catalog import to_label

COMPONENTS_DIR = Path(__file__).parent / "data" / "components"
COMPONENT_TYPES = ("software", "service", "hardware", "policy", "interconnection", "process", "plan", "guidance",
                   "standard", "validation", "this-system")


@dataclass(frozen=True)
class Requirement:
    control: str  # label form, AC-6(10)
    statement: str
    inherited: bool = False
    assertions: tuple[str, ...] = ()


@dataclass(frozen=True)
class Component:
    id: str
    uuid: str
    title: str
    type: str
    description: str
    purpose: str = ""
    requirements: tuple[Requirement, ...] = field(default_factory=tuple)


def parse_component(data: dict) -> Component:
    reqs = []
    for r in data.get("implemented-requirements") or []:
        reqs.append(Requirement(control=to_label(str(r["control"])), statement=str(r.get("statement") or "").strip(),
                                inherited=bool(r.get("inherited", False)),
                                assertions=tuple(r.get("assertions") or ())))
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
