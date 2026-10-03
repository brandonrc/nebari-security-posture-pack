"""Per-scan CVE rollup (architecture review M4): `vuln_rollup`, one row per vulnerability over
the consensus findings of the running images, written once at the end of every scan with a
single INSERT ... SELECT, so `/vulnerabilities` filters, sorts and paginates in SQL instead of
grouping every consensus row in Python on each request. `kev` marks CVEs in the CISA KEV
catalog (reports/kev.py, the same source as `/summary` `exposure`).
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from sqlalchemy import text, update
from sqlalchemy.ext.asyncio import AsyncSession

from .db.models import Scan

# severity -> rank (severity.severity_rank: unknown 0 .. critical 5)
_RANK_SQL = ("CASE {col} WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 "
             "WHEN 'low' THEN 2 WHEN 'negligible' THEN 1 ELSE 0 END")
_SEV_SQL = ("CASE {col} WHEN 5 THEN 'critical' WHEN 4 THEN 'high' WHEN 3 THEN 'medium' "
            "WHEN 2 THEN 'low' WHEN 1 THEN 'negligible' ELSE 'unknown' END")

ROLLUP_SQL = f"""
WITH f AS (
    SELECT c.image_id, c.vuln_id, c.package, c.severity, c.scanners, c.agreement, c.fixable, c.cvss,
           c.title, c.url, c.first_seen_at, {_RANK_SQL.format(col="c.severity")} AS r
    FROM consensus_findings c JOIN images i ON i.id = c.image_id
    WHERE i.running
), wl AS (
    SELECT DISTINCT image_fk, namespace, workload_kind, workload_name
    FROM containers WHERE scan_id = :scan_id AND image_fk IS NOT NULL
), agg AS (
    SELECT vuln_id, max(r) AS r, round(max(agreement)::numeric, 4)::float AS agreement,
           count(DISTINCT image_id) AS images, bool_or(fixable) AS fixable, max(cvss) AS cvss,
           (array_agg(title ORDER BY r DESC, image_id) FILTER (WHERE title IS NOT NULL AND title <> ''))[1] AS title,
           (array_agg(url ORDER BY r DESC, image_id) FILTER (WHERE url IS NOT NULL AND url <> ''))[1] AS url,
           min(first_seen_at) AS first_seen,
           jsonb_agg(DISTINCT package ORDER BY package) AS packages,
           string_agg(DISTINCT package, ' ') AS package_text
    FROM f GROUP BY vuln_id
), sc AS (
    SELECT vuln_id, jsonb_agg(s ORDER BY CASE s WHEN 'trivy' THEN 0 WHEN 'grype' THEN 1 WHEN 'clair' THEN 2
                                             ELSE 3 END, s) AS scanners
    FROM (SELECT DISTINCT f.vuln_id, s FROM f, jsonb_array_elements_text(f.scanners) AS s) x GROUP BY vuln_id
), w AS (
    SELECT x.vuln_id, count(DISTINCT (wl.namespace, wl.workload_kind, wl.workload_name)) AS workloads
    FROM (SELECT DISTINCT vuln_id, image_id FROM f) x JOIN wl ON wl.image_fk = x.image_id GROUP BY x.vuln_id
)
INSERT INTO vuln_rollup (scan_id, vuln_id, severity, severity_rank, scanners, agreement, images_affected,
                         workloads_affected, fix_available, cvss, kev, title, url, first_seen, packages, search)
SELECT :scan_id, agg.vuln_id, {_SEV_SQL.format(col="agg.r")}, agg.r, coalesce(sc.scanners, '[]'::jsonb),
       coalesce(agg.agreement, 0), agg.images, coalesce(w.workloads, 0), coalesce(agg.fixable, false), agg.cvss,
       false, agg.title, agg.url, agg.first_seen, agg.packages,
       lower(agg.vuln_id || ' ' || coalesce(agg.title, '') || ' ' || coalesce(agg.package_text, ''))
FROM agg LEFT JOIN sc ON sc.vuln_id = agg.vuln_id LEFT JOIN w ON w.vuln_id = agg.vuln_id
"""


async def write_vuln_rollup(session: AsyncSession, scan_id: int) -> int:
    """(Re)write the rollup of `scan_id` inside the caller's transaction; returns the row count.
    Reads the scan's `containers` rows, so call it after they are inserted."""
    await session.execute(text("DELETE FROM vuln_rollup WHERE scan_id = :scan_id"), {"scan_id": scan_id})
    res = await session.execute(text(ROLLUP_SQL), {"scan_id": scan_id})
    kev_ids = await asyncio.to_thread(_kev_ids)  # may refresh the feed once a day (bounded timeout)
    if kev_ids:
        await session.execute(text("UPDATE vuln_rollup SET kev = true WHERE scan_id = :scan_id "
                                   "AND vuln_id = ANY(:ids)"), {"scan_id": scan_id, "ids": kev_ids})
    await session.execute(update(Scan).where(Scan.id == scan_id).values(vuln_rollup_at=datetime.now(UTC)))
    return res.rowcount or 0


def _kev_ids() -> list[str]:
    from .reports.kev import catalog

    return sorted((catalog().get("entries") or {}).keys())
