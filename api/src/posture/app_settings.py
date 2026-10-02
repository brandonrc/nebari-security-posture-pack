"""Editable settings (single `settings` row, JSON) layered over env defaults."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator
from pydantic.alias_generators import to_camel
from sqlalchemy.ext.asyncio import AsyncSession

from .config import Settings, get_settings
from .db.models import Setting


class CamelModel(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True, extra="ignore")


class ScannerToggles(CamelModel):
    trivy: bool = True
    grype: bool = True
    clair: bool = True


class SlaDays(CamelModel):
    critical: int = Field(15, ge=1, le=3650)
    high: int = Field(30, ge=1, le=3650)
    medium: int = Field(90, ge=1, le=3650)
    low: int = Field(180, ge=1, le=3650)


class ReportsSettings(CamelModel):
    auto_generate: list[str] = Field(default_factory=list)

    @field_validator("auto_generate")
    @classmethod
    def _known_types(cls, v: list[str]) -> list[str]:
        from .reports.registry import REPORT_TYPES

        known = {t["type"] for t in REPORT_TYPES}
        out: list[str] = []
        for t in v:
            t = (t or "").strip()
            if t and t not in known:
                raise ValueError(f"unknown report type {t!r} (known: {', '.join(sorted(known))})")
            if t and t not in out:
                out.append(t)
        return out


class AppSettings(CamelModel):
    scan_interval_hours: float = Field(6, gt=0, le=24 * 30)
    rescan_after_hours: float = Field(24, ge=0, le=24 * 365)
    excluded_namespaces: list[str] = Field(default_factory=list)
    scanners: ScannerToggles = Field(default_factory=ScannerToggles)
    parallelism: int = Field(3, ge=1, le=32)
    system_name: str = "nebari"
    organization: str = ""
    remediation_sla_days: SlaDays = Field(default_factory=SlaDays)
    reports: ReportsSettings = Field(default_factory=ReportsSettings)
    admin_groups: list[str] = Field(default_factory=list)  # read-only (from env)

    @field_validator("excluded_namespaces")
    @classmethod
    def _strip(cls, v: list[str]) -> list[str]:
        return sorted({s.strip() for s in v if s and s.strip()})


EDITABLE = {"scan_interval_hours", "rescan_after_hours", "excluded_namespaces", "scanners", "parallelism",
            "system_name", "organization", "remediation_sla_days", "reports"}


def defaults(env: Settings | None = None) -> AppSettings:
    env = env or get_settings()
    return AppSettings(
        scan_interval_hours=env.scan_interval_hours,
        rescan_after_hours=env.rescan_after_hours,
        excluded_namespaces=env.excluded_namespaces,
        scanners=ScannerToggles(trivy=env.trivy_enabled, grype=env.grype_enabled, clair=env.clair_enabled),
        parallelism=env.scan_parallelism,
        system_name=env.cluster_name,
        reports=ReportsSettings(auto_generate=env.reports_auto_generate),
        admin_groups=sorted(env.admin_group_set),
    )


async def load(session: AsyncSession, env: Settings | None = None) -> AppSettings:
    base = defaults(env)
    row = await session.get(Setting, 1)
    if row is None or not row.data:
        return base
    merged = base.model_dump()
    stored = AppSettings.model_validate({**base.model_dump(by_alias=True), **row.data}).model_dump()
    for k in EDITABLE:
        merged[k] = stored[k]
    return AppSettings.model_validate(merged)


async def save(session: AsyncSession, new: AppSettings, user: str | None) -> AppSettings:
    data = new.model_dump(by_alias=True, include=EDITABLE)
    row = await session.get(Setting, 1)
    if row is None:
        session.add(Setting(id=1, data=data, updated_by=user))
    else:
        row.data = data
        row.updated_by = user
    await session.commit()
    return await load(session)


def apply_patch(current: AppSettings, patch: dict[str, Any]) -> AppSettings:
    """Merge a (camelCase) partial update; adminGroups is read-only and ignored."""
    body = current.model_dump(by_alias=True)
    for k, v in patch.items():
        if k in ("adminGroups", "admin_groups"):
            continue
        if isinstance(v, dict) and isinstance(body.get(k), dict):
            body[k] = {**body[k], **v}
        else:
            body[k] = v
    return AppSettings.model_validate(body)
