"""Rebuild `nist_800_53_rev5.json` (trimmed NIST SP 800-53 rev5 catalog + baselines).

    python build_catalog.py <dir with the official usnistgov/oscal-content rev5 JSON files>

Inputs (https://github.com/usnistgov/oscal-content/tree/main/nist.gov/SP800-53/rev5/json):
NIST_SP-800-53_rev5_catalog.json and NIST_SP-800-53_rev5_{LOW,MODERATE,HIGH}-baseline_profile.json.
Keeps, per control and enhancement: id, label, title, family, class, parent, implementation
level, withdrawn flag, sort id; the SP 800-53A assessment-objective ids (leaf `*_obj.*` parts, the
unit of objective coverage, compliance review M2), the statement part ids (`*_smt.*`, OSCAL
statement-level responses) and the organization-defined parameter ids + labels (`set-parameters`);
plus the baseline membership from the three official profiles. Extra profiles (FedRAMP, CNSSI 1253)
live in `profiles/*.json` next to this file (see README.md).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

OUT = Path(__file__).parent / "nist_800_53_rev5.json"
SRC = "https://github.com/usnistgov/oscal-content/tree/main/nist.gov/SP800-53/rev5/json"


def _prop(c: dict, name: str, cls: str | None = None) -> str | None:
    for p in c.get("props") or []:
        if p.get("name") == name and (cls is None or p.get("class") == cls):
            return p.get("value")
    return None


def _label(c: dict) -> str:
    for p in c.get("props") or []:
        if p.get("name") == "label" and not p.get("class"):
            return p["value"]
    return c["id"].upper()


def _leaf_objectives(part: dict) -> list[str]:
    subs = [p for p in part.get("parts") or [] if p.get("name") == "assessment-objective"]
    if not subs:
        return [part["id"]] if part.get("id") else []
    return [o for p in subs for o in _leaf_objectives(p)]


def _objectives(c: dict) -> list[str]:
    for p in c.get("parts") or []:
        if p.get("name") == "assessment-objective":
            return _leaf_objectives(p)
    return []


def _statements(c: dict) -> list[str]:
    out: list[str] = []

    def walk(p: dict) -> None:
        subs = [s for s in p.get("parts") or [] if s.get("name") == "item"]
        if not subs and p.get("id"):
            out.append(p["id"])
        for s in subs:
            walk(s)

    for p in c.get("parts") or []:
        if p.get("name") == "statement":
            walk(p)
    return out


def _params(c: dict) -> list[dict]:
    out = []
    for p in c.get("params") or []:
        label = p.get("label") or ((p.get("select") or {}).get("how-many") and "selection") or ""
        out.append({"id": p["id"], "label": label} if label else {"id": p["id"]})
    return out


def main(src: Path) -> None:
    cat = json.loads((src / "NIST_SP-800-53_rev5_catalog.json").read_text())["catalog"]
    controls: list[dict] = []

    def walk(c: dict, family: str, parent: str | None) -> None:
        controls.append({
            "id": c["id"], "label": _label(c), "title": c["title"], "family": family, "class": c.get("class"),
            "parent": parent, "implementationLevel": _prop(c, "implementation-level"),
            "withdrawn": _prop(c, "status") == "withdrawn", "sortId": _prop(c, "sort-id") or c["id"],
            **({"objectives": obj} if (obj := _objectives(c)) else {}),
            **({"statements": smt} if (smt := _statements(c)) else {}),
            **({"params": prm} if (prm := _params(c)) else {}),
        })
        for sub in c.get("controls") or []:
            walk(sub, family, c["id"])

    families = []
    for g in cat["groups"]:
        families.append({"id": g["id"], "label": g["id"].upper(), "title": g["title"]})
        for c in g.get("controls") or []:
            walk(c, g["id"], None)
    baselines: dict[str, dict] = {}
    for level in ("LOW", "MODERATE", "HIGH"):
        prof = json.loads((src / f"NIST_SP-800-53_rev5_{level}-baseline_profile.json").read_text())["profile"]
        ids = [i for imp in prof["imports"] for inc in imp.get("include-controls") or [] for i in inc.get("with-ids") or []]
        baselines[level.lower()] = {"uuid": prof["uuid"], "version": prof["metadata"]["version"],
                                    "title": prof["metadata"]["title"], "controls": ids}
    out = {
        "source": SRC,
        "catalog": {"uuid": cat["uuid"], "title": cat["metadata"]["title"], "version": cat["metadata"]["version"],
                    "lastModified": cat["metadata"]["last-modified"]},
        "families": families,
        "baselines": baselines,
        "controls": controls,
    }
    OUT.write_text(json.dumps(out, separators=(",", ":"), ensure_ascii=False) + "\n")
    print(f"wrote {OUT} ({OUT.stat().st_size} bytes, {len(controls)} controls)")


if __name__ == "__main__":
    main(Path(sys.argv[1] if len(sys.argv) > 1 else "."))
