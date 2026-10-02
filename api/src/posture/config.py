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
    scan_on_start: bool = True

    # misc
    cache_dir: str = "/cache"
    log_level: str = "INFO"
    cluster_name: str = "nebari"

    @field_validator("oidc_issuers", "admin_groups", "excluded_namespaces", "mirror_rewrite", mode="before")
    @classmethod
    def _csv(cls, v: object) -> list[str]:
        return _split(v)

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
