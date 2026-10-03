"""Glue for report generation: attach the latest engine data to a ReportSnapshot."""

from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from . import engine


async def attach(session: AsyncSession, snapshot: Any) -> None:
    from .. import app_settings

    ce = (await app_settings.load(session)).controls_engine
    snapshot.controls_engine = {
        "data": await engine.latest_data(session),
        "baseline": ce.baseline,
        "organizationStatement": ce.organization_statement,
        "notApplicable": dict(ce.not_applicable),
        "inheritOrganizationalControls": ce.inherit_organizational_controls,
    }
