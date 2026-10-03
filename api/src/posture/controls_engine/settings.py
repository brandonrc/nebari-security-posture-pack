"""Editable settings section `controlsEngine` (DESIGN §13), embedded in `app_settings.AppSettings`."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator
from pydantic.alias_generators import to_camel

from .catalog import to_label


class _Camel(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True, extra="ignore")


class ControlParameters(_Camel):
    """Organization-defined parameters. Unset (null) = the selected baseline's ODP set
    (data/profiles/*.json, each value with its cited source: FedRAMP Rev5 for the NIST and FedRAMP
    profiles, DISA SRG / CNSSI 1253 for the DoD profile; compliance review M7). A value set here
    overrides the profile."""

    max_login_failures: int | None = Field(None, ge=1, le=100)  # AC-7 a
    min_password_length: int | None = Field(None, ge=1, le=256)  # IA-5(1)
    max_session_idle_seconds: int | None = Field(None, ge=60, le=7 * 86400)  # AC-11 / AC-12 / SC-10
    max_session_lifespan_seconds: int | None = Field(None, ge=300, le=30 * 86400)  # AC-12
    min_log_retention_days: int | None = Field(None, ge=1, le=3650)  # AU-11
    cert_renewal_window_days: int | None = Field(None, ge=1, le=365)  # SC-12
    log_window_minutes: int = Field(10, ge=1, le=1440)  # AU-12 ingest freshness (operational)
    lockout_window_seconds: int | None = Field(None, ge=60, le=86400)  # AC-7 a: failure-count window
    min_lockout_seconds: int | None = Field(None, ge=60, le=30 * 86400)  # AC-7 b: minimum lockout duration
    require_admin_release: bool | None = None  # AC-7 b: lock until an administrator releases the account

    def effective(self, baseline: str) -> dict[str, object]:
        """camelCase ODP name -> value used for `baseline` (explicit setting, else the profile value)."""
        from .catalog import odp_profile

        out: dict[str, object] = {}
        for name, odp in odp_profile(baseline).items():
            attr = "".join("_" + ch.lower() if ch.isupper() else ch for ch in name)
            explicit = getattr(self, attr, None)
            out[name] = explicit if explicit is not None else odp.get("value")
        out["logWindowMinutes"] = self.log_window_minutes
        return out


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


class StigAsset(_Camel):
    """STIG checklist ASSET identifiers (CKL HOST_NAME / HOST_IP / HOST_FQDN / HOST_MAC); eMASS asset
    import and HW/SW reconciliation need real values (compliance review M6)."""

    host_name: str = ""
    host_ip: str = ""
    host_fqdn: str = ""
    host_mac: str = ""


class ControlsEngineSettings(_Camel):
    enabled: bool = True  # read-only: env CONTROLS_ENGINE_ENABLED (chart controlsEngine.enabled)
    # NIST SP 800-53B LOW/MODERATE/HIGH, FedRAMP Rev5 Moderate, or the CNSSI 1253 M-M-M approximation
    baseline: Literal["low", "moderate", "high", "fedramp-moderate-rev5", "cnssi-1253-mod-mod-mod"] = "moderate"
    admin_subjects: list[str] = Field(default_factory=list)  # Keycloak usernames, User:/Group:/ServiceAccount:ns/name
    # M1: organization-level controls with no evidence are reported `org-provided-unverified` (never
    # counted as implemented) only when this is on; off = `not-assessed`. Neither is `inherited`.
    inherit_organizational_controls: bool = False
    organization_statement: str = ""  # SSP text for organization-provided (unverified) controls
    common_control_providers: list[CommonControlProvider] = Field(default_factory=list)
    # SC-17 / IA-5(2): cert-manager ClusterIssuers that chain to an approved CA (DoD PKI, ECA, the
    # organization's CA). Empty = no CA is approved yet, so cm-issuer-ready fails.
    approved_issuers: list[str] = Field(default_factory=list)
    stig_asset: StigAsset = Field(default_factory=StigAsset)
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
