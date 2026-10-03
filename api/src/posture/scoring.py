"""Scoring per docs/SCORING.md (pure functions). The cluster grade is an internal hygiene index
for trends, not an assessment result (compliance review S4)."""

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
# The one definition of the Kubernetes system namespaces (scoring, posture checks, reports; the
# control evidence engine's default `systemNamespaces` is the same set). Compliance review S4.
SYSTEM_NAMESPACES = frozenset({"kube-system", "kube-public", "kube-node-lease"})
SCANNERS_ALL = ("trivy", "grype", "clair")
# Scanners able to detect a package type (S4): Clair covers OS distribution packages only, so a
# language-ecosystem finding is compared against Trivy and Grype alone.
LANGUAGE_SCANNERS = ("trivy", "grype")
OS_PKG_TYPES = frozenset({
    "os", "os-pkgs", "deb", "dpkg", "debian", "ubuntu", "apk", "alpine", "rpm", "redhat", "centos", "rocky",
    "alma", "almalinux", "amazon", "oracle", "photon", "suse", "sles", "opensuse", "opensuse-leap",
    "opensuse.leap", "wolfi", "chainguard", "mariner", "cbl-mariner", "azurelinux", "fedora", "bitnami-os",
    "distroless", "minimos", "echo", "binary-os",
})


def capable_scanners(pkg_type: str | None, succeeded: tuple[str, ...] | list[str]) -> int:
    """How many of the succeeded scanners can detect findings of this package type."""
    t = (pkg_type or "").strip().lower()
    if not t or t in OS_PKG_TYPES:
        return len(succeeded)
    return sum(1 for s in succeeded if s in LANGUAGE_SCANNERS) or len(succeeded)
VULN_SHARE = 0.7
POSTURE_SHARE = 0.3
# cluster score once supply-chain data exists (SCORING.md, DESIGN §12)
CLUSTER_VULN_SHARE = 0.6
CLUSTER_POSTURE_SHARE = 0.25
CLUSTER_SUPPLY_CHAIN_SHARE = 0.15


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
    pkg_type: str | None = None
    kev: bool = False  # CISA Known Exploited Vulnerability: never down-weighted (S4)
    succeeded: tuple[str, ...] = ()  # scanners that completed (for capability-aware agreement)


def finding_penalty(f: VulnInput, n_succeeded: int) -> float:
    """Agreement is computed over the scanners *capable* of the package type (S4): a language
    package only Trivy and Grype can see is full agreement when both report it. KEV findings are
    never down-weighted."""
    base = VULN_BASE.get(f.severity, VULN_BASE["unknown"])
    capable = capable_scanners(f.pkg_type, f.succeeded) if f.succeeded else n_succeeded
    mult = 1.0 if f.kev else agreement_multiplier(f.n_scanners, capable)
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


def combine_cluster(vuln: float | None, posture: float | None, supply_chain: float | None) -> float | None:
    """Cluster: 0.6 x vuln + 0.25 x posture + 0.15 x supplyChain; without supply-chain data
    the workload formula (0.7 / 0.3) applies. Missing posture renormalizes the rest."""
    if supply_chain is None:
        return combine(vuln, posture)
    if vuln is None:
        return None
    parts = [(vuln, CLUSTER_VULN_SHARE), (supply_chain, CLUSTER_SUPPLY_CHAIN_SHARE)]
    if posture is not None:
        parts.append((posture, CLUSTER_POSTURE_SHARE))
    return round(sum(v * w for v, w in parts) / sum(w for _, w in parts), 1)


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
