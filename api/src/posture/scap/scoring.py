"""STIG score (SCORING.md addendum, DESIGN §14), pure functions.

Image STIG score = 100 x (1 - sum(failed weight) / sum(evaluated weight)) with CAT I = 10,
CAT II = 4, CAT III = 1, over rules whose result is pass or fail (notapplicable / notchecked /
error / unknown / informational are excluded). None when nothing was evaluated (no benchmark
applies, or every rule was notchecked in chroot mode).
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

CAT_WEIGHT = {"cat1": 10.0, "cat2": 4.0, "cat3": 1.0}
OPEN_KEYS = {"cat1": "cat1Open", "cat2": "cat2Open", "cat3": "cat3Open"}


def stig_score(rows: Iterable[tuple[str, str]]) -> float | None:
    """rows: (severity cat, result)."""
    evaluated = failed = 0.0
    for cat, result in rows:
        if result not in ("pass", "fail"):
            continue
        w = CAT_WEIGHT.get(cat, 1.0)
        evaluated += w
        if result == "fail":
            failed += w
    if evaluated <= 0:
        return None
    return round(100.0 * (1.0 - failed / evaluated), 1)


def open_by_cat(rows: Iterable[tuple[str, str]]) -> dict[str, int]:
    out = {"cat1Open": 0, "cat2Open": 0, "cat3Open": 0}
    for cat, result in rows:
        if result == "fail":
            out[OPEN_KEYS.get(cat, "cat3Open")] += 1
    return out


def image_stig(summaries: list[dict[str, Any]]) -> dict[str, Any]:
    """Denormalised `images.stig` from the image's per-benchmark summaries (scap_image_summary
    rows as dicts with pass/fail/... counts, cat*Open and the weighted sums)."""
    evaluated = [s for s in summaries if s.get("status") == "evaluated"]
    if not summaries:
        return {"status": "notEvaluated", "score": None, "benchmarks": 0}
    if not evaluated:
        st = summaries[0].get("status") or "notApplicable"
        return {"status": st, "score": None, "benchmarks": 0, "error": summaries[0].get("error")}
    ev_w = sum(float(s.get("evaluatedWeight") or 0) for s in evaluated)
    fail_w = sum(float(s.get("failedWeight") or 0) for s in evaluated)
    score = round(100.0 * (1.0 - fail_w / ev_w), 1) if ev_w > 0 else None
    out: dict[str, Any] = {"status": "evaluated", "score": score, "benchmarks": len(evaluated),
                           "benchmarkIds": [s.get("benchmarkKey") for s in evaluated]}
    for k in ("pass", "fail", "notapplicable", "notchecked", "error", "cat1Open", "cat2Open", "cat3Open"):
        out[k] = sum(int(s.get(k) or 0) for s in evaluated)
    out["fidelity"] = "degraded" if any(s.get("rootfsFidelity") == "degraded" for s in evaluated) else "full"
    return out


def weights(rows: Iterable[tuple[str, str]]) -> tuple[float, float]:
    """(evaluated weight, failed weight) for combining benchmarks."""
    ev = fl = 0.0
    for cat, result in rows:
        if result in ("pass", "fail"):
            w = CAT_WEIGHT.get(cat, 1.0)
            ev += w
            if result == "fail":
                fl += w
    return ev, fl


def configuration_score(posture: float | None, stig_scores: Iterable[float | None]) -> float | None:
    """Workload configuration posture: mean of workloadPostureScore and the STIG scores of its
    images when any image has one; otherwise workloadPostureScore unchanged."""
    vals = [s for s in stig_scores if s is not None]
    if not vals:
        return posture
    parts = ([posture] if posture is not None else []) + vals
    return round(sum(parts) / len(parts), 1)
