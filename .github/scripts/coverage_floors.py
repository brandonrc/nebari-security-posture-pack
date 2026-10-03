#!/usr/bin/env python3
"""Per-module coverage floors on top of pytest-cov's global --cov-fail-under.

Reads a coverage.py JSON report (`--cov-report=json`) and fails when any module
matching a pattern below is under its floor (line+branch percent, as coverage.py
reports it). Ratchet the numbers up, never down. Usage:

    python .github/scripts/coverage_floors.py api/coverage.json
"""
from __future__ import annotations

import fnmatch
import json
import os
import sys

# path glob (relative to api/) -> minimum percent covered (statements + branches)
FLOORS: dict[str, float] = {
    "src/posture/scoring.py": 95,
    "src/posture/correlate.py": 95,
    "src/posture/severity.py": 95,
    "src/posture/auth.py": 95,
    "src/posture/posture_checks.py": 95,
    "src/posture/scanners/*.py": 95,
    "src/posture/inventory.py": 80,
}


def main(path: str) -> int:
    with open(path, encoding="utf-8") as fh:
        files = json.load(fh)["files"]
    rows, failed = [], False
    for pattern, floor in FLOORS.items():
        matched = [f for f in files if fnmatch.fnmatch(f, pattern)]
        if not matched:
            print(f"::error::coverage floor pattern {pattern!r} matched no file", file=sys.stderr)
            failed = True
        for f in sorted(matched):
            pct = files[f]["summary"]["percent_covered"]
            ok = pct + 1e-9 >= floor
            failed |= not ok
            rows.append((f, pct, floor, ok))
            if not ok:
                print(f"::error file=api/{f}::coverage {pct:.1f}% is below the {floor}% floor")
    out = ["| module | coverage | floor | |", "|---|---|---|---|"]
    out += [f"| `{f}` | {pct:.1f}% | {floor}% | {'ok' if ok else '**FAIL**'} |" for f, pct, floor, ok in rows]
    text = "\n".join(out)
    print(text)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write("### Per-module coverage floors\n\n" + text + "\n")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "coverage.json"))
