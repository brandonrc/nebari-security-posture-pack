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
    oidc_issuers: CsvList = []  # REQUIRED with auth_mode=oidc (the API refuses to start without it)
    oidc_audience: str | None = None  # legacy single value; merged into accepted_audiences
    # `aud` must contain, or `azp` equal, one of these (security review H1). The chart sets
    # OIDC_CLIENT_IDS to the operator-provisioned client id `<namespace>-<fullname>`.
    oidc_audiences: CsvList = []
    oidc_client_ids: CsvList = []
    posture_dev: bool = False  # POSTURE_DEV=1 is required for AUTH_MODE=disabled
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
    scan_on_start: bool = True  # no scan ever finished: run the first one at startup (else after one interval)
    # worker stages run by this process (posture.worker --stages overrides); "" = all.
    # The chart splits inventory,scan / provenance,controls,reports (worker.splitPrivileged).
    worker_stages: str = ""

    # retention (pruning implemented in the worker / report code)
    history_retain_scans: int = 30  # newest done scans whose history rows are kept
    reports_retention_max_total_bytes: int = 2 * 1024**3  # cap on the reports directory ("2Gi" accepted)

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
    provenance_max_major_jump: int = 50  # ignore update candidates whose MAJOR is this far above current; 0 = off
    provenance_helm_enabled: bool = True  # needs cluster-wide secrets list (chart: provenance.helmReleases.enabled)
    provenance_helm_chart_repos: CsvList = []  # https://.../ (index.yaml) or oci://host/path
    provenance_recheck_hours: float = 24  # reuse signature/SBOM/provenance results per digest
    provenance_concurrency: int = 8
    provenance_registry_timeout: float = 30
    provenance_compat_internal_port: int | None = None  # unauthenticated /api/reports* listener (Grafana)
    cosign_bin: str = "cosign"

    # control evidence engine (DESIGN §13)
    controls_engine_enabled: bool = True
    controls_baseline: str = "moderate"  # default for settings controlsEngine.baseline
    controls_system_namespaces: CsvList = ["kube-system", "kube-public", "kube-node-lease"]
    controls_admin_subjects: CsvList = []  # default for settings controlsEngine.adminSubjects
    controls_keycloak_url: str = "http://keycloak-keycloakx-http.keycloak.svc.cluster.local:80/auth"
    controls_keycloak_realm: str = "nebari"
    controls_keycloak_admin_realm: str = ""  # realm of the admin credentials; "" = target realm, then master
    controls_keycloak_client_id: str = "admin-cli"
    controls_keycloak_admin_secret_name: str = "nebari-realm-admin-credentials"
    controls_keycloak_admin_secret_namespace: str = "keycloak"
    controls_keycloak_admin_group: str = ""  # "" = first of ADMIN_GROUPS
    controls_keycloak_verify_tls: bool = True
    controls_loki_url: str = ""  # "" = discover Services
    controls_prometheus_url: str = ""
    controls_alertmanager_url: str = ""
    controls_registry_url: str = ""  # "" = MIRROR_REGISTRY
    controls_discover_cluster_ip: bool = False
    controls_timeout_seconds: float = 30
    controls_tls_probe: bool = True

    @field_validator("controls_system_namespaces", "controls_admin_subjects", mode="before")
    @classmethod
    def _controls_csv(cls, v: object) -> list[str]:
        return _split(v)

    # misc
    cache_dir: str = "/cache"
    log_level: str = "INFO"
    cluster_name: str = "nebari"

    @field_validator("oidc_issuers", "oidc_audiences", "oidc_client_ids", "admin_groups", "excluded_namespaces", "mirror_rewrite", "reports_auto_generate",
                     "clair_ready_updaters", "provenance_helm_chart_repos",
                     mode="before")
    @classmethod
    def _csv(cls, v: object) -> list[str]:
        return _split(v)

    @field_validator("reports_retention_max_total_bytes", mode="before")
    @classmethod
    def _quantity(cls, v: object) -> object:
        """Kubernetes-style quantities from the chart: 2Gi, 500Mi, 1G, or plain bytes."""
        if isinstance(v, str):
            t = v.strip()
            units = {"Ki": 1024, "Mi": 1024**2, "Gi": 1024**3, "Ti": 1024**4,
                     "K": 1000, "k": 1000, "M": 1000**2, "G": 1000**3, "T": 1000**4}
            for suffix in sorted(units, key=len, reverse=True):
                if t.endswith(suffix):
                    return int(float(t[: -len(suffix)]) * units[suffix])
            return int(float(t)) if t else 0
        return v

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
    def accepted_audiences(self) -> list[str]:
        out = [*self.oidc_audiences, *self.oidc_client_ids]
        if self.oidc_audience:
            out.append(self.oidc_audience)
        return list(dict.fromkeys(a for a in out if a))

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
