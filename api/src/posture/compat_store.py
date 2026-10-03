"""Materialized provenance-collector-pack reports (architecture review §1).

The compat API (`/api/reports*`, `/api/export`, polled by Grafana) used to rebuild every
scan's report document from the containers / images / provenance tables on each request.
The worker now renders it once per completed scan into `compat_reports` (Go-identical JSON
bytes plus the list entry), and the router serves the stored bytes.

`metadata.collectorVersion`: the Go collector binary's version when the provenance stage ran
the collector engine (`ProvenanceStage.collector_version`), else this API's version
(`<version>+posture`).
"""

from __future__ import annotations

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from .db.models import CompatReportRow, Scan
from .provenance.models import ImageProvenance
from .provenance.report import go_json, load_report, report_filename, scan_time


async def materialize(session: AsyncSession, scan_id: int, cluster_name: str,
                      collector_version: str | None = None) -> bool:
    """Render and store scan `scan_id`'s report (inside the caller's transaction). False when
    the scan has no provenance results (it is then not a compat report, like before)."""
    scan = await session.get(Scan, scan_id)
    if scan is None or not await session.scalar(
            select(ImageProvenance.id).where(ImageProvenance.scan_id == scan_id).limit(1)):
        return False
    doc = await load_report(session, scan, cluster_name)
    if collector_version:
        doc["metadata"]["collectorVersion"] = collector_version
    await session.execute(delete(CompatReportRow).where(CompatReportRow.scan_id == scan_id))
    session.add(CompatReportRow(scan_id=scan_id, filename=report_filename(scan_time(scan)),
                                generated_at=scan_time(scan), cluster_name=cluster_name or None,
                                summary=doc["summary"], body=go_json(doc, indent=True)))
    return True
