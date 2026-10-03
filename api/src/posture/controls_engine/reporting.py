"""Glue for report generation: attach the latest engine data to a ReportSnapshot."""

from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from . import engine


async def attach(session: AsyncSession, snapshot: Any, scan_id: Any = None) -> None:
    from .. import app_settings

    if scan_id is None and getattr(snapshot, "controls_engine", None):
        return  # already attached by build_snapshot (from the run of the snapshot's scan)
    st = await app_settings.load(session)
    ce = st.controls_engine
    snapshot.controls_engine = {
        "data": await engine.latest_data(session, scan_id),
        "baseline": ce.baseline,
        "organizationStatement": ce.organization_statement,
        "notApplicable": dict(ce.not_applicable),
        "inheritOrganizationalControls": ce.inherit_organizational_controls,
        "commonControlProviders": [p.model_dump(by_alias=True) for p in ce.common_control_providers],
        # S3: effective ODP values (profile ODP set, overridden by settings) for SSP set-parameters
        "parameters": ce.parameters.effective(ce.baseline),
        "parameterExtra": {"adminSubjects": list(ce.admin_subjects), "approvedIssuers": list(ce.approved_issuers),
                           "slaDays": st.remediation_sla_days.model_dump()},
    }
