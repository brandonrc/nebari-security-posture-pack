"""Per-image analysis: scanner results -> consensus findings + score (pure)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from .correlate import ConsensusFinding, agreement_index, apply_vex, correlate
from .scanners.base import ScanResult
from .scoring import ImageScore, VulnInput, image_vuln_score
from .severity import zero_counts

if TYPE_CHECKING:
    from .vex import ImageVex


@dataclass
class ImageAnalysis:
    consensus: list[ConsensusFinding]
    score: ImageScore
    counts: dict[str, int]
    fixable: dict[str, int]
    agreement_index: float | None
    succeeded: list[str]
    scanners: dict[str, dict[str, Any]] = field(default_factory=dict)
    os_family: str | None = None
    os_name: str | None = None
    vex_suppressed: int = 0  # consensus findings a `not_affected` VEX statement covers
    vex_recorded: int = 0  # findings with any applicable VEX statement (all statuses)


def scanner_summary(r: ScanResult) -> dict[str, Any]:
    out: dict[str, Any] = {"status": r.status, "findings": len(r.findings), "durationMs": r.duration_ms}
    if r.error:
        out["error"] = r.error
    if r.version:
        out["version"] = r.version
    return out


def analyze(results: list[ScanResult], vex: ImageVex | None = None) -> ImageAnalysis:
    """`vex`: the image's applicable statements (posture.vex). Findings a `not_affected`
    statement covers stay in `consensus` (marked) but count neither in the score nor in
    `counts` / `fixable` (SCORING.md, VEX)."""
    ok = [r for r in results if r.ok]
    succeeded = [r.scanner for r in ok]
    findings = [f for r in ok for f in r.findings]
    consensus = correlate(findings, succeeded)
    suppressed = apply_vex(consensus, vex)
    open_ = [c for c in consensus if not c.suppressed]
    from .reports.kev import lookup as kev_lookup  # S4: KEV findings are never down-weighted

    score = image_vuln_score(
        (VulnInput(c.severity, len(c.scanners), c.fixable, pkg_type=c.pkg_type,
                   kev=kev_lookup(c.vuln_id) is not None, succeeded=tuple(succeeded)) for c in open_),
        len(succeeded),
    )
    counts, fixable = zero_counts(), zero_counts()
    for c in open_:
        counts[c.severity] += 1
        if c.fixable:
            fixable[c.severity] += 1
    os_src = next((r for r in ok if r.os_family), None)
    return ImageAnalysis(
        consensus=consensus,
        score=score,
        counts=counts,
        fixable=fixable,
        agreement_index=agreement_index(consensus, len(succeeded)),
        succeeded=succeeded,
        scanners={r.scanner: scanner_summary(r) for r in results},
        os_family=os_src.os_family if os_src else None,
        os_name=os_src.os_name if os_src else None,
        vex_suppressed=suppressed,
        vex_recorded=sum(1 for c in consensus if c.vex_status),
    )
