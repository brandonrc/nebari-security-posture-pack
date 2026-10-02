"""Scoring per docs/SCORING.md (pure functions)."""

from __future__ import annotations

import math
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

VULN_BASE = {"critical": 10.0, "high": 4.0, "medium": 1.0, "low": 0.2, "negligible": 0.05, "unknown": 0.05}
CHECK_WEIGHT = {"critical": 10.0, "high": 4.0, "medium": 1.0, "low": 0.2}
AGREEMENT_MULT = {1: 0.6, 2: 0.85, 3: 1.0}
FIXABLE_MULT = 1.25
VULN_SCALE = 40.0
POSTURE_SCALE = 20.0
SYSTEM_NAMESPACE_FACTOR = 0.5
SYSTEM_NAMESPACES = frozenset({"kube-system"})
VULN_SHARE = 0.7
POSTURE_SHARE = 0.3


def grade(score: float | None) -> str:
    if score is None:
        return "?"
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 65:
        return "C"
    if score >= 50:
        return "D"
    return "F"


def agreement_multiplier(n_scanners: int, n_succeeded: int) -> float:
    """1 scanner 0.6, 2 scanners 0.85, 3 scanners 1.0 — relative to the scanners that
    completed: a finding reported by *every* succeeded scanner is full agreement (1.0),
    so a lone surviving scanner gives 1.0 (with `confidence: low`)."""
    if n_succeeded <= 1 or n_scanners >= n_succeeded:
        return 1.0
    return AGREEMENT_MULT.get(max(1, min(n_scanners, 3)), 1.0)


@dataclass(frozen=True)
class VulnInput:
    severity: str
    n_scanners: int
    fixable: bool


def finding_penalty(f: VulnInput, n_succeeded: int) -> float:
    base = VULN_BASE.get(f.severity, VULN_BASE["unknown"])
    mult = agreement_multiplier(f.n_scanners, n_succeeded)
    return base * mult * (FIXABLE_MULT if f.fixable else 1.0)


@dataclass(frozen=True)
class ImageScore:
    score: float | None
    grade: str
    penalty: float
    confidence: str  # high | medium | low | none


def image_vuln_score(findings: Iterable[VulnInput], n_succeeded: int) -> ImageScore:
    if n_succeeded <= 0:
        return ImageScore(None, "?", 0.0, "none")
    penalty = sum(finding_penalty(f, n_succeeded) for f in findings)
    score = round(100.0 * math.exp(-penalty / VULN_SCALE), 1)
    confidence = "low" if n_succeeded == 1 else ("medium" if n_succeeded == 2 else "high")
    return ImageScore(score, grade(score), round(penalty, 4), confidence)


def check_weight(severity: str, namespace: str | None = None) -> float:
    w = CHECK_WEIGHT.get(severity, 0.0)
    if namespace in SYSTEM_NAMESPACES:
        w *= SYSTEM_NAMESPACE_FACTOR
    return w


def posture_score(failed_weights: Iterable[float]) -> float:
    return round(100.0 * math.exp(-sum(failed_weights) / POSTURE_SCALE), 1)


def combine(vuln: float | None, posture: float | None) -> float | None:
    """0.7 x vuln + 0.3 x posture (workload and cluster level)."""
    if vuln is None:
        return None
    if posture is None:
        return round(vuln, 1)
    return round(VULN_SHARE * vuln + POSTURE_SHARE * posture, 1)


def mean(values: Sequence[float]) -> float | None:
    vals = [v for v in values if v is not None]
    return round(sum(vals) / len(vals), 1) if vals else None


def weighted_mean(pairs: Iterable[tuple[float | None, float]]) -> float | None:
    num = 0.0
    den = 0.0
    for value, weight in pairs:
        if value is None or weight <= 0:
            continue
        num += value * weight
        den += weight
    return round(num / den, 1) if den > 0 else None
