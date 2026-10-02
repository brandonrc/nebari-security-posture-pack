"""Per-image analysis: scanner results -> consensus findings + score (pure)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .correlate import ConsensusFinding, agreement_index, correlate
from .scanners.base import ScanResult
from .scoring import ImageScore, VulnInput, image_vuln_score
from .severity import zero_counts


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


def scanner_summary(r: ScanResult) -> dict[str, Any]:
    out: dict[str, Any] = {"status": r.status, "findings": len(r.findings), "durationMs": r.duration_ms}
    if r.error:
        out["error"] = r.error
    if r.version:
        out["version"] = r.version
    return out


def analyze(results: list[ScanResult]) -> ImageAnalysis:
    ok = [r for r in results if r.ok]
    succeeded = [r.scanner for r in ok]
    findings = [f for r in ok for f in r.findings]
    consensus = correlate(findings, succeeded)
    score = image_vuln_score(
        (VulnInput(c.severity, len(c.scanners), c.fixable) for c in consensus), len(succeeded)
    )
    counts, fixable = zero_counts(), zero_counts()
    for c in consensus:
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
    )
