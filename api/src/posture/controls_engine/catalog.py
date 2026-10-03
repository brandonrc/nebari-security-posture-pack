"""Trimmed NIST SP 800-53 rev5 catalog + LOW/MODERATE/HIGH baselines (vendored from the
official usnistgov/oscal-content files; rebuild with `data/build_catalog.py`)."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from collections.abc import Iterable
from typing import Any

DATA = Path(__file__).parent / "data"
CATALOG_FILE = DATA / "nist_800_53_rev5.json"
BASELINES = ("low", "moderate", "high")
_LABEL_RE = re.compile(r"^\s*([A-Za-z]{2})-(\d+)(?:\s*\((\d+)\))?\s*$")
_ID_RE = re.compile(r"^\s*([a-z]{2})-(\d+)(?:\.(\d+))?\s*$")


def to_oscal_id(control: str) -> str:
    """`SI-2(2)` / `si-2.2` -> `si-2.2` (OSCAL catalog id)."""
    m = _LABEL_RE.match(control)
    if m:
        base = f"{m.group(1).lower()}-{int(m.group(2))}"
        return f"{base}.{int(m.group(3))}" if m.group(3) else base
    return control.strip().lower()


def objective_control(objective: str) -> str:
    """`si-2_obj.c-1` -> `si-2`; `ia-5.1_obj.a` -> `ia-5.1`."""
    return objective.strip().lower().split("_obj", 1)[0]


def to_label(control: str) -> str:
    """`si-2.2` / `SI-2(2)` -> `SI-2(2)`."""
    m = _ID_RE.match(control.strip().lower())
    if m:
        base = f"{m.group(1).upper()}-{int(m.group(2))}"
        return f"{base}({int(m.group(3))})" if m.group(3) else base
    m = _LABEL_RE.match(control)
    if m:
        return to_label(to_oscal_id(control))
    return control.strip().upper()


@dataclass(frozen=True)
class Control:
    id: str  # oscal id, e.g. ac-6.10
    label: str  # AC-6(10)
    title: str
    family: str  # AC
    cls: str | None
    parent: str | None
    implementation_level: str | None  # organization | system | None
    withdrawn: bool
    sort_id: str
    baselines: tuple[str, ...]
    objectives: tuple[str, ...] = ()  # SP 800-53A leaf assessment-objective ids (ac-7_obj.a)
    statements: tuple[str, ...] = ()  # statement part ids (ac-7_smt.a)
    params: tuple[tuple[str, str], ...] = ()  # (odp id, label)

    @property
    def objective_ids(self) -> tuple[str, ...]:
        """Leaf objectives; a control without published objectives counts as one (`<id>_obj`)."""
        return self.objectives or (f"{self.id}_obj",)

    def expand_objectives(self, refs: "Iterable[str]") -> list[str]:
        """Objective references (a leaf, a parent such as `si-2_obj.c`, or `<id>_obj` for all) -> leaves."""
        out: list[str] = []
        for ref in refs:
            ref = ref.strip().lower()
            for leaf in self.objective_ids:
                if leaf == ref or leaf.startswith(ref + "-") or leaf.startswith(ref + ".") or \
                        ref == f"{self.id}_obj":
                    if leaf not in out:
                        out.append(leaf)
        return out

    @property
    def lowest_baseline(self) -> str | None:
        return self.baselines[0] if self.baselines else None

    def in_baseline(self, level: str) -> bool:
        return level in self.baselines

    @property
    def full_title(self) -> str:
        if self.parent:
            parent = get_catalog().get(self.parent)
            if parent:
                return f"{parent.title} | {self.title}"
        return self.title


class Catalog:
    def __init__(self, data: dict[str, Any]):
        self.meta = data["catalog"]
        self.source = data.get("source", "")
        self.families = {f["label"]: f["title"] for f in data["families"]}
        self.baselines_meta = {k: {kk: vv for kk, vv in v.items() if kk != "controls"}
                               for k, v in data["baselines"].items()}
        member: dict[str, list[str]] = {}
        for level in BASELINES:
            for cid in data["baselines"][level]["controls"]:
                member.setdefault(cid, []).append(level)
        self.controls: dict[str, Control] = {}
        for c in data["controls"]:
            self.controls[c["id"]] = Control(
                id=c["id"], label=c["label"], title=c["title"], family=c["family"].upper(), cls=c.get("class"),
                parent=c.get("parent"), implementation_level=c.get("implementationLevel"),
                withdrawn=bool(c.get("withdrawn")), sort_id=c.get("sortId") or c["id"],
                baselines=tuple(member.get(c["id"], ())), objectives=tuple(c.get("objectives") or ()),
                statements=tuple(c.get("statements") or ()),
                params=tuple((p["id"], p.get("label", "")) for p in c.get("params") or ()))

    def get(self, control: str) -> Control | None:
        return self.controls.get(to_oscal_id(control))

    def title(self, control: str) -> str | None:
        c = self.get(control)
        return c.full_title if c else None

    def baseline(self, level: str) -> list[Control]:
        if level not in BASELINES:
            raise ValueError(f"unknown baseline {level!r}")
        return sorted((c for c in self.controls.values() if level in c.baselines), key=lambda c: c.sort_id)

    def sort_key(self, control: str) -> str:
        c = self.get(control)
        return c.sort_id if c else to_oscal_id(control)

    def list(self, family: str | None = None, baseline: str | None = None,
             include_withdrawn: bool = False) -> list[Control]:
        out = []
        for c in self.controls.values():
            if family and c.family != family.upper():
                continue
            if baseline and baseline not in c.baselines:
                continue
            if c.withdrawn and not include_withdrawn:
                continue
            out.append(c)
        return sorted(out, key=lambda c: c.sort_id)


@lru_cache
def get_catalog() -> Catalog:
    return Catalog(json.loads(CATALOG_FILE.read_text(encoding="utf-8")))


def control_dict(c: Control) -> dict[str, Any]:
    return {"control": c.label, "id": c.id, "title": c.full_title, "family": c.family, "class": c.cls,
            "baseline": c.lowest_baseline, "baselines": list(c.baselines),
            "implementationLevel": c.implementation_level, "withdrawn": c.withdrawn,
            "objectives": list(c.objective_ids)}
