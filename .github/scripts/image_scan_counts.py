#!/usr/bin/env python3
"""CRITICAL/HIGH counts for the image-scan workflow (.github/workflows/image-scan.yaml).

  count  <label> <trivy.json> <grype.json> -o <out.json>   one image variant -> counts JSON
  report <counts-dir>                                       all counts -> markdown (stdout)

"fixable" = a fixed version exists (trivy FixedVersion, grype fix.state == fixed). Both scans are run
with the pack's OpenVEX (api/vex/posture-images.vex.json), so not_affected findings are already gone;
the counts are distinct (vulnerability, package, version) tuples, HIGH and CRITICAL only.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys


def _trivy(path: str) -> dict[tuple[str, str, str], tuple[str, bool]]:
    doc = json.loads(pathlib.Path(path).read_text() or "{}")
    out = {}
    for res in doc.get("Results") or []:
        for v in res.get("Vulnerabilities") or []:
            if v.get("Severity") in ("CRITICAL", "HIGH"):
                out[(v["VulnerabilityID"], v["PkgName"], v.get("InstalledVersion", ""))] = (
                    v["Severity"], bool(v.get("FixedVersion")))
    return out


def _grype(path: str) -> dict[tuple[str, str, str], tuple[str, bool]]:
    doc = json.loads(pathlib.Path(path).read_text() or "{}")
    out = {}
    for m in doc.get("matches") or []:
        v, a = m["vulnerability"], m["artifact"]
        sev = (v.get("severity") or "").upper()
        if sev in ("CRITICAL", "HIGH"):
            out[(v["id"], a["name"], a.get("version", ""))] = (sev, (v.get("fix") or {}).get("state") == "fixed")
    return out


def _counts(found: dict) -> dict[str, int]:
    vals = list(found.values())
    return {
        "critical": sum(s == "CRITICAL" for s, _ in vals),
        "high": sum(s == "HIGH" for s, _ in vals),
        "fixable_critical": sum(s == "CRITICAL" and f for s, f in vals),
        "fixable_high": sum(s == "HIGH" and f for s, f in vals),
    }


def count(args: argparse.Namespace) -> int:
    doc = {"label": args.label, "trivy": _counts(_trivy(args.trivy)), "grype": _counts(_grype(args.grype))}
    pathlib.Path(args.output).write_text(json.dumps(doc, indent=2) + "\n")
    print(json.dumps(doc))
    return 0


def _cell(c: dict[str, int] | None) -> str:
    if not c:
        return "n/a"
    return f"{c['critical']} / {c['high']} ({c['fixable_critical']} / {c['fixable_high']})"


def report(args: argparse.Namespace) -> int:
    rows: dict[str, dict[str, dict]] = {}
    for f in sorted(pathlib.Path(args.dir).rglob("*.json")):
        d = json.loads(f.read_text())
        image, _, variant = d["label"].partition(":")
        rows.setdefault(image, {})[variant] = d
    lines = [
        "<!-- image-scan-counts -->",
        "### Image scan: CRITICAL / HIGH (fixable), pack VEX applied",
        "",
        "| image | trivy before | trivy after | grype before | grype after |",
        "|---|---|---|---|---|",
    ]
    for image in sorted(rows):
        b, a = rows[image].get("before"), rows[image].get("after")
        lines.append(f"| {image} | {_cell(b and b['trivy'])} | {_cell(a and a['trivy'])} | "
                     f"{_cell(b and b['grype'])} | {_cell(a and a['grype'])} |")
    lines += ["", "_before_ = the base branch's Dockerfiles (pull requests only). The job fails when an "
              "_after_ image has a fixable CRITICAL or HIGH finding (trivy minus `.github/trivy/ignore.yaml`, "
              "grype `--only-fixed`). Unfixed Debian CVEs are triaged in `api/vex/posture-images.vex.json`."]
    print("\n".join(lines))
    return 0


def main() -> int:
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("count")
    c.add_argument("label")
    c.add_argument("trivy")
    c.add_argument("grype")
    c.add_argument("-o", "--output", required=True)
    r = sub.add_parser("report")
    r.add_argument("dir")
    a = p.parse_args()
    return count(a) if a.cmd == "count" else report(a)


if __name__ == "__main__":
    sys.exit(main())
