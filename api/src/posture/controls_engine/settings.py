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


class ControlsEngineSettings(_Camel):
    enabled: bool = True  # read-only: env CONTROLS_ENGINE_ENABLED (chart controlsEngine.enabled)
    baseline: Literal["low", "moderate", "high"] = "moderate"
    admin_subjects: list[str] = Field(default_factory=list)  # Keycloak usernames, User:/Group:/ServiceAccount:ns/name
    inherit_organizational_controls: bool = True
    organization_statement: str = ""  # SSP text for controls inherited from the organization
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
