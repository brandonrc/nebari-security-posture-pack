"""Editable settings section `controlsEngine` (DESIGN §13), embedded in `app_settings.AppSettings`."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator
from pydantic.alias_generators import to_camel

from .catalog import to_label


class _Camel(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True, extra="ignore")


class ControlParameters(_Camel):
    """Organization-defined parameters (defaults: FedRAMP moderate values)."""

    max_login_failures: int = Field(3, ge=1, le=100)  # AC-7
    min_password_length: int = Field(12, ge=1, le=256)  # IA-5(1)
    max_session_idle_seconds: int = Field(900, ge=60, le=7 * 86400)  # AC-11 / AC-12
    max_session_lifespan_seconds: int = Field(43200, ge=300, le=30 * 86400)  # AC-12
    min_log_retention_days: int = Field(90, ge=1, le=3650)  # AU-11
    cert_renewal_window_days: int = Field(30, ge=1, le=365)  # SC-12(1)
    log_window_minutes: int = Field(10, ge=1, le=1440)  # AU-12 ingest freshness
    lockout_window_seconds: int = Field(900, ge=60, le=86400)  # AC-7 a: failure-count window
    min_lockout_seconds: int = Field(1800, ge=60, le=30 * 86400)  # AC-7 b: minimum lockout duration
    require_admin_release: bool = False  # AC-7 b: lock until an administrator releases the account


class CommonControlProvider(_Camel):
    """A named, separately authorized common control provider (CCP) whose controls this system
    inherits (M1): e.g. the hosting data center's or the organization's CCP package in eMASS.
    Only controls listed here are ever reported `inherited`."""

    name: str  # CCP system name, e.g. "DISA Enterprise Hosting (eMASS 1234)"
    controls: list[str] = Field(default_factory=list)  # AC-1, PE-3, ...
    authorization_ref: str = ""  # eMASS ID / ATO letter reference
    date_authorized: str = ""  # YYYY-MM-DD of the CCP's ATO (OSCAL leveraged-authorization date-authorized)
    statement: str = ""  # the CCP's implementation statement for the inherited controls

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        v = (v or "").strip()
        if not v:
            raise ValueError("commonControlProviders[].name is required")
        return v

    @field_validator("controls")
    @classmethod
    def _controls(cls, v: list[str]) -> list[str]:
        return list(dict.fromkeys(to_label(c) for c in v if c and c.strip()))

    @field_validator("date_authorized")
    @classmethod
    def _date(cls, v: str) -> str:
        v = (v or "").strip()
        if v:
            from datetime import date

            date.fromisoformat(v)
        return v


class ControlsEngineSettings(_Camel):
    enabled: bool = True  # read-only: env CONTROLS_ENGINE_ENABLED (chart controlsEngine.enabled)
    baseline: Literal["low", "moderate", "high"] = "moderate"
    admin_subjects: list[str] = Field(default_factory=list)  # Keycloak usernames, User:/Group:/ServiceAccount:ns/name
    # M1: organization-level controls with no evidence are reported `org-provided-unverified` (never
    # counted as implemented) only when this is on; off = `not-assessed`. Neither is `inherited`.
    inherit_organizational_controls: bool = False
    organization_statement: str = ""  # SSP text for organization-provided (unverified) controls
    common_control_providers: list[CommonControlProvider] = Field(default_factory=list)
    # SC-17 / IA-5(2): cert-manager ClusterIssuers that chain to an approved CA (DoD PKI, ECA, the
    # organization's CA). Empty = no CA is approved yet, so cm-issuer-ready fails.
    approved_issuers: list[str] = Field(default_factory=list)
    not_applicable: dict[str, str] = Field(default_factory=dict)  # tailoring: control -> justification
    parameters: ControlParameters = Field(default_factory=ControlParameters)

    @field_validator("admin_subjects")
    @classmethod
    def _subjects(cls, v: list[str]) -> list[str]:
        return list(dict.fromkeys(s.strip() for s in v if s and s.strip()))

    @field_validator("not_applicable")
    @classmethod
    def _tailoring(cls, v: dict[str, str]) -> dict[str, str]:
        return {to_label(k): (r or "").strip() for k, r in v.items() if k and k.strip()}
