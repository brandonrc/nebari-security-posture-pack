"""Severity vocabulary shared by scanners, correlation and scoring."""

from __future__ import annotations

SEVERITIES = ("critical", "high", "medium", "low", "negligible", "unknown")
_RANK = {s: i for i, s in enumerate(reversed(SEVERITIES))}  # unknown=0 .. critical=5

_ALIASES = {
    "critical": "critical",
    "crit": "critical",
    "high": "high",
    "important": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "minor": "low",
    "negligible": "negligible",
    "none": "negligible",
    "informational": "negligible",
    "info": "negligible",
    "unknown": "unknown",
    "": "unknown",
}


def normalize_severity(value: object) -> str:
    if value is None:
        return "unknown"
    return _ALIASES.get(str(value).strip().lower(), "unknown")


def severity_rank(sev: str) -> int:
    return _RANK.get(sev, 0)


def max_severity(values) -> str:
    best = "unknown"
    for v in values:
        if severity_rank(v) > severity_rank(best):
            best = v
    return best


def zero_counts() -> dict[str, int]:
    return {s: 0 for s in SEVERITIES}
