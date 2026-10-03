"""Editable settings (single `settings` row, JSON) layered over env defaults."""

from __future__ import annotations

import os
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator
from pydantic.alias_generators import to_camel
from sqlalchemy.ext.asyncio import AsyncSession

from .config import Settings, get_settings
from .controls_engine.settings import ControlsEngineSettings
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


class ProvenanceSettings(CamelModel):
    """Supply-chain checks (DESIGN §12); keys mirror provenance-collector-pack's config."""

    enabled: bool = True
    verify_signatures: bool = True
    cosign_public_key: str = ""  # PEM text, file path or KMS URI; "" = existence check only
    cosign_certificate_identity_regexp: str = ""
    cosign_certificate_oidc_issuer_regexp: str = ""
    check_sbom: bool = True
    check_provenance: bool = True
    check_updates: bool = True
    skip_prerelease: bool = True
    update_level: str = "patch"
    helm_releases: bool = True
    recheck_hours: float = Field(24, ge=0, le=24 * 30)

    @field_validator("update_level")
    @classmethod
    def _level(cls, v: str) -> str:
        v = (v or "patch").strip().lower()
        if v not in ("patch", "minor", "major"):
            raise ValueError("updateLevel must be patch, minor or major")
        return v


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
    controls_engine: ControlsEngineSettings = Field(default_factory=ControlsEngineSettings)  # DESIGN §13
    provenance: ProvenanceSettings = Field(default_factory=ProvenanceSettings)
    admin_groups: list[str] = Field(default_factory=list)  # read-only (from env)

    @field_validator("excluded_namespaces")
    @classmethod
    def _strip(cls, v: list[str]) -> list[str]:
        return sorted({s.strip() for s in v if s and s.strip()})


EDITABLE = {"scan_interval_hours", "rescan_after_hours", "excluded_namespaces", "scanners", "parallelism",
            "system_name", "organization", "remediation_sla_days", "reports", "provenance"}
EDITABLE = EDITABLE | {"controls_engine"}


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
        provenance=ProvenanceSettings(
            enabled=env.provenance_enabled, verify_signatures=env.provenance_verify_signatures,
            cosign_public_key=env.provenance_cosign_public_key,
            cosign_certificate_identity_regexp=env.provenance_cosign_certificate_identity_regexp,
            cosign_certificate_oidc_issuer_regexp=env.provenance_cosign_certificate_oidc_issuer_regexp,
            check_sbom=env.provenance_check_sbom, check_provenance=env.provenance_check_provenance,
            check_updates=env.provenance_check_updates, skip_prerelease=env.provenance_skip_prerelease,
            update_level=env.provenance_update_level, helm_releases=env.provenance_helm_enabled,
            recheck_hours=env.provenance_recheck_hours),
        controls_engine=ControlsEngineSettings(enabled=env.controls_engine_enabled, baseline=env.controls_baseline,
                                               admin_subjects=env.controls_admin_subjects),
        admin_groups=sorted(env.admin_group_set),
    )


# Signature trust anchors (security review L5). With PROVENANCE_TRUST_SETTINGS_LOCKED=true (chart
# default) they come only from the env (PROVENANCE_COSIGN_*), PUT /settings refuses to change them
# and any value stored earlier is ignored.
TRUST_FIELDS = ("cosign_public_key", "cosign_certificate_identity_regexp", "cosign_certificate_oidc_issuer_regexp")


def trust_settings_locked() -> bool:
    return os.environ.get("PROVENANCE_TRUST_SETTINGS_LOCKED", "").strip().lower() in ("1", "true", "yes", "on")


def locked_trust_changes(current: AppSettings, patch: dict[str, Any]) -> list[str]:
    """camelCase names of trust fields the patch would change while locked."""
    if not trust_settings_locked() or not isinstance(patch.get("provenance"), dict):
        return []
    prov = patch["provenance"]
    out = []
    for f in TRUST_FIELDS:
        alias = ProvenanceSettings.model_fields[f].alias or f
        if any(k in prov and prov[k] != getattr(current.provenance, f) for k in (alias, f)):
            out.append(alias)
    return sorted(set(out))


async def load(session: AsyncSession, env: Settings | None = None) -> AppSettings:
    base = defaults(env)
    row = await session.get(Setting, 1)
    if row is None or not row.data:
        return base
    merged = base.model_dump()
    stored = AppSettings.model_validate({**base.model_dump(by_alias=True), **row.data}).model_dump()
    for k in EDITABLE:
        merged[k] = stored[k]
    merged["controls_engine"]["enabled"] = base.controls_engine.enabled  # read-only (env)
    if trust_settings_locked():
        for f in TRUST_FIELDS:
            merged["provenance"][f] = getattr(base.provenance, f)
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
