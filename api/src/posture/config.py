"""Runtime configuration (env vars, see docs/DESIGN.md §5)."""

from __future__ import annotations

from functools import lru_cache
from typing import Annotated

from pydantic import field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


def _split(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(v).strip() for v in value if str(v).strip()]
    return [v.strip() for v in str(value).split(",") if v.strip()]


CsvList = Annotated[list[str], NoDecode]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=None, extra="ignore", case_sensitive=False)

    database_url: str = "postgresql+asyncpg://posture:posture@localhost:5432/posture"

    # auth
    auth_mode: str = "oidc"  # oidc | disabled
    oidc_jwks_url: str = (
        "http://keycloak-keycloakx-http.keycloak.svc.cluster.local:80"
        "/auth/realms/nebari/protocol/openid-connect/certs"
    )
    oidc_issuers: CsvList = []
    oidc_audience: str | None = None
    admin_groups: CsvList = ["admin"]
    jwks_cache_seconds: int = 600

    # scanners
    trivy_server_url: str = "http://trivy:4954"
    clair_url: str = "http://clair:6060"
    trivy_enabled: bool = True
    grype_enabled: bool = True
    clair_enabled: bool = True
    trivy_bin: str = "trivy"
    grype_bin: str = "grype"
    clairctl_bin: str = "clairctl"
    skopeo_bin: str = "skopeo"

    # mirror
    mirror_enabled: bool = True
    mirror_registry: str = "registry.container-registry.svc.cluster.local:5000"
    mirror_insecure: bool = True
    mirror_rewrite: CsvList = []  # "localhost:32000=registry...:5000,..."
    mirror_all_platforms: bool = False
    registry_auth_file: str | None = None

    # scheduling
    scan_parallelism: int = 3
    scan_timeout_seconds: int = 600
    scan_interval_hours: float = 6
    rescan_after_hours: float = 24
    excluded_namespaces: CsvList = []
    grype_db_update_hours: float = 12
    worker_poll_seconds: float = 5
    # Before scanning, wait (at most this long) for the grype DB to exist and for Clair to
    # have run the updaters named in CLAIR_READY_UPDATERS (substring match), so the first
    # scan after an install does not record "database does not exist" / empty Clair results.
    scanner_ready_timeout_seconds: float = 1800
    clair_ready_updaters: CsvList = ["alpine", "debian", "ubuntu"]
    scan_on_start: bool = True

    # reports (DESIGN §11): bytes on disk, metadata in the `reports` table
    reports_dir: str = "/data/reports"
    reports_keep_per_type: int = 50
    reports_auto_generate: CsvList = []  # default for settings `reports.autoGenerate`

    # supply-chain provenance (DESIGN §12; names mirror provenance-collector-pack's
    # PROVENANCE_* env vars where they exist)
    provenance_enabled: bool = True
    provenance_verify_signatures: bool = True
    provenance_cosign_public_key: str = ""  # PEM text, file path or KMS URI
    provenance_cosign_certificate_identity_regexp: str = ""  # keyless verification
    provenance_cosign_certificate_oidc_issuer_regexp: str = ""
    provenance_check_sbom: bool = True
    provenance_check_provenance: bool = True
    provenance_check_updates: bool = True
    provenance_skip_prerelease: bool = True
    provenance_update_level: str = "patch"  # patch | minor | major
    provenance_helm_enabled: bool = True  # needs cluster-wide secrets list (chart: provenance.helmReleases.enabled)
    provenance_helm_chart_repos: CsvList = []  # https://.../ (index.yaml) or oci://host/path
    provenance_recheck_hours: float = 24  # reuse signature/SBOM/provenance results per digest
    provenance_concurrency: int = 8
    provenance_registry_timeout: float = 30
    provenance_compat_internal_port: int | None = None  # unauthenticated /api/reports* listener (Grafana)
    cosign_bin: str = "cosign"

    # misc
    cache_dir: str = "/cache"
    log_level: str = "INFO"
    cluster_name: str = "nebari"

    @field_validator("oidc_issuers", "admin_groups", "excluded_namespaces", "mirror_rewrite", "reports_auto_generate",
                     "clair_ready_updaters", "provenance_helm_chart_repos",
                     mode="before")
    @classmethod
    def _csv(cls, v: object) -> list[str]:
        return _split(v)

    @field_validator("provenance_compat_internal_port", mode="before")
    @classmethod
    def _empty_port(cls, v: object) -> object:
        return None if v in ("", "0", 0) else v

    @field_validator("database_url")
    @classmethod
    def _async_driver(cls, v: str) -> str:
        for prefix in ("postgresql://", "postgres://"):
            if v.startswith(prefix):
                return "postgresql+asyncpg://" + v[len(prefix):]
        return v

    @property
    def auth_disabled(self) -> bool:
        return self.auth_mode.lower() == "disabled"

    @property
    def admin_group_set(self) -> set[str]:
        return {g.lstrip("/") for g in self.admin_groups}

    @property
    def rewrite_map(self) -> dict[str, str]:
        out: dict[str, str] = {}
        for item in self.mirror_rewrite:
            if "=" in item:
                src, dst = item.split("=", 1)
                if src.strip() and dst.strip():
                    out[src.strip()] = dst.strip()
        return out


@lru_cache
def get_settings() -> Settings:
    return Settings()
