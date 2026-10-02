"""Cross-scanner correlation: (vulnId, package) -> consensus finding (DESIGN §4.6)."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field

from .scanners.base import Finding
from .severity import max_severity, severity_rank

SCANNER_PREFERENCE = ("trivy", "grype", "clair")


def normalize_package(name: str) -> str:
    return re.sub(r"[-_.]+", "-", (name or "").strip().lower())


@dataclass
class ConsensusFinding:
    vuln_id: str
    package: str
    severity: str
    scanners: list[str]
    per_scanner: dict[str, str]
    agreement: float
    installed_version: str | None = None
    fixed_version: str | None = None
    pkg_type: str | None = None
    cvss: float | None = None
    title: str | None = None
    url: str | None = None
    extra: dict = field(default_factory=dict)

    @property
    def fixable(self) -> bool:
        return bool(self.fixed_version)

    @property
    def key(self) -> tuple[str, str]:
        return (self.vuln_id, normalize_package(self.package))


def correlate(findings: Iterable[Finding], succeeded: Iterable[str]) -> list[ConsensusFinding]:
    """Group per-scanner findings by (vulnId, normalized package).

    `agreement = len(scanners) / len(succeeded scanners)`; severity = max over scanners.
    """
    succeeded = [s for s in SCANNER_PREFERENCE if s in set(succeeded)] or list(set(succeeded))
    n_ok = max(len(succeeded), 1)
    groups: dict[tuple[str, str], list[Finding]] = {}
    for f in findings:
        key = (f.vuln_id.upper() if f.vuln_id.upper().startswith(("CVE-", "GHSA-")) else f.vuln_id,
               normalize_package(f.package))
        groups.setdefault(key, []).append(f)
    out: list[ConsensusFinding] = []
    for (vid, _pkg), items in groups.items():
        items.sort(key=lambda f: SCANNER_PREFERENCE.index(f.scanner) if f.scanner in SCANNER_PREFERENCE else 99)
        per: dict[str, str] = {}
        for f in items:
            prev = per.get(f.scanner)
            if prev is None or severity_rank(f.severity) > severity_rank(prev):
                per[f.scanner] = f.severity
        scanners = [s for s in SCANNER_PREFERENCE if s in per] + sorted(s for s in per if s not in SCANNER_PREFERENCE)
        cvss_vals = [f.cvss for f in items if f.cvss]
        out.append(
            ConsensusFinding(
                vuln_id=vid,
                package=items[0].package,
                severity=max_severity(per.values()),
                scanners=scanners,
                per_scanner=per,
                agreement=round(min(len(scanners) / n_ok, 1.0), 4),
                installed_version=next((f.installed_version for f in items if f.installed_version), None),
                fixed_version=next((f.fixed_version for f in items if f.fixed_version), None),
                pkg_type=next((f.pkg_type for f in items if f.pkg_type), None),
                cvss=max(cvss_vals) if cvss_vals else None,
                title=next((f.title for f in items if f.title), None),
                url=next((f.url for f in items if f.url), None),
            )
        )
    out.sort(key=lambda c: (-severity_rank(c.severity), -(c.cvss or 0), c.vuln_id, c.package))
    return out


def agreement_index(consensus: list[ConsensusFinding], n_succeeded: int) -> float | None:
    """Mean agreement across consensus findings (1.0 when clean, None if no scanner ran)."""
    if n_succeeded == 0:
        return None
    if not consensus:
        return 1.0
    return round(sum(c.agreement for c in consensus) / len(consensus), 4)
