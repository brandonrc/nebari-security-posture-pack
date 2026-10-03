"""Supply-chain score (docs/SCORING.md, DESIGN §12) and control tags (pure functions).

Per image: start 100; -40 unsigned (-20 signed but not verified), -20 no SBOM,
-15 no provenance, -15 update available (-25 when a major version behind),
-10 mutable tag without a digest pin (per container spec); floor 0.

A check that is switched off contributes nothing (neither pass nor fail); an image
whose checks never ran has no score. Cluster `supplyChainScore` is the
container-weighted mean over running containers (all non-ephemeral containers
when nothing runs), mirroring `vulnScore`.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from ..controls import load_controls
from ..images import has_mutable_tag
from ..scoring import grade

PENALTY_UNSIGNED = 40.0
PENALTY_UNVERIFIED = 20.0
PENALTY_NO_SBOM = 20.0
PENALTY_NO_PROVENANCE = 15.0
PENALTY_UPDATE = 15.0
PENALTY_UPDATE_MAJOR = 25.0
PENALTY_MUTABLE_TAG = 10.0


@dataclass(frozen=True)
class SupplyChainInputs:
    """Per-image check results; None = check not run (disabled / never checked)."""

    signed: bool | None = None
    verified: bool | None = None
    verification_configured: bool = False
    has_sbom: bool | None = None
    has_provenance: bool | None = None
    update_available: bool | None = None
    major_behind: bool = False

    @property
    def checked(self) -> bool:
        return any(v is not None for v in (self.signed, self.has_sbom, self.has_provenance, self.update_available))


def image_penalties(i: SupplyChainInputs) -> list[tuple[str, float]]:
    """[(finding id, penalty)] for the image-level (tag-independent) part."""
    out: list[tuple[str, float]] = []
    if i.signed is False:
        out.append(("unsigned", PENALTY_UNSIGNED))
    elif i.signed and not i.verified:
        out.append(("unverified", PENALTY_UNVERIFIED))
    if i.has_sbom is False:
        out.append(("no-sbom", PENALTY_NO_SBOM))
    if i.has_provenance is False:
        out.append(("no-provenance", PENALTY_NO_PROVENANCE))
    if i.update_available:
        out.append(("major-update-available" if i.major_behind else "update-available",
                    PENALTY_UPDATE_MAJOR if i.major_behind else PENALTY_UPDATE))
    return out


def supply_chain_score(i: SupplyChainInputs | None, mutable_tag: bool = False) -> float | None:
    if i is None or not i.checked:
        return None
    penalty = sum(p for _, p in image_penalties(i))
    if mutable_tag:
        penalty += PENALTY_MUTABLE_TAG
    return round(max(0.0, 100.0 - penalty), 1)


def container_score(i: SupplyChainInputs | None, spec_image: str) -> float | None:
    return supply_chain_score(i, has_mutable_tag(spec_image))


def inputs_from_json(sig: dict[str, Any] | None, sbom: dict[str, Any] | None, prov: dict[str, Any] | None,
                     update: dict[str, Any] | None, *, verification_configured: bool,
                     sbom_checked: bool, provenance_checked: bool, updates_checked: bool,
                     major_behind: bool = False) -> SupplyChainInputs:
    return SupplyChainInputs(
        signed=None if sig is None else bool(sig.get("signed")),
        verified=None if sig is None else bool(sig.get("verified")),
        verification_configured=verification_configured,
        has_sbom=(bool((sbom or {}).get("hasSBOM")) if sbom_checked else None),
        has_provenance=(bool((prov or {}).get("hasProvenance")) if provenance_checked else None),
        update_available=(bool((update or {}).get("updateAvailable")) if updates_checked else None),
        major_behind=major_behind,
    )


def weighted_mean(pairs: Iterable[tuple[float | None, float]]) -> float | None:
    num = den = 0.0
    for v, w in pairs:
        if v is None or w <= 0:
            continue
        num += v * w
        den += w
    return round(num / den, 1) if den else None


def cluster_supply_chain_score(container_scores: Iterable[float | None]) -> float | None:
    return weighted_mean((s, 1.0) for s in container_scores)


def score_and_grade(score: float | None) -> dict[str, Any]:
    return {"score": score, "grade": grade(score)}


# ---------------------------------------------------------------- 800-53 tags
PROVENANCE_CONTROL_KEYS = ("unsigned", "unverified", "no-sbom", "no-provenance", "update-available",
                           "major-update-available", "mutable-tag", "helm-release-behind")


def provenance_controls(finding: str) -> list[str]:
    """controls.yaml `provenance:` section (DESIGN §12)."""
    return list(((load_controls().get("provenance") or {}).get(finding)) or [])
