"""Spreadsheet formula-injection neutralisation (security review M5).

Image tags, workload / Helm chart names and scanner titles are attacker-influenced. A cell
that starts with `=`, `+`, `-`, `@`, tab or CR can be evaluated as a formula by Excel /
LibreOffice when a CSV is opened (or when an xlsx is re-saved as CSV), so such strings get
a leading `'` (OWASP "CSV injection" guidance). Non-strings are returned unchanged.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def safe_cell(value: Any) -> Any:
    if isinstance(value, str) and value.startswith(FORMULA_PREFIXES):
        return "'" + value
    return value


def safe_row(values: Iterable[Any]) -> list[Any]:
    return [safe_cell(v) for v in values]
