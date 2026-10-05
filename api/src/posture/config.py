"""Runtime configuration (env vars, see docs/DESIGN.md §5)."""

from __future__ import annotations

from functools import lru_cache
from typing import Annotated, Any

from pydantic import field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


def _split(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(v).strip() for v in value if str(v).strip()]
    return [v.strip() for v in str(value).split(",") if v.strip()]


CsvList = Annotated[list[str], NoDecode]

# ComplianceAsCode / SSG release (BSD-3-Clause), pinned by the sha256 GitHub publishes for the asset.
# Only the datastreams named in `include` are kept on the content volume (~150 MB).
SSG_VERSION = "0.1.82"
DEFAULT_SCAP_SOURCES: list[dict[str, Any]] = [{
    "name": "ssg", "kind": "ssg",
    "url": f"https://github.com/ComplianceAsCode/content/releases/download/v{SSG_VERSION}/"
           f"scap-security-guide-{SSG_VERSION}.zip",
    "sha256": "765e84bdce7f9055f9b9c2dd0ee2b713d4255f8eec94eac6d35ea4973c28919c",
    "include": ["ssg-debian11-ds.xml", "ssg-debian12-ds.xml", "ssg-debian13-ds.xml", "ssg-ubuntu2204-ds.xml",
                "ssg-ubuntu2404-ds.xml", "ssg-rhel8-ds.xml", "ssg-rhel9-ds.xml", "ssg-rhel10-ds.xml",
                "ssg-al2023-ds.xml", "ssg-sle15-ds.xml", "ssg-fedora-ds.xml"],
}]


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
    provenance_helm_index_ttl_hours: float = 12  # CACHE_DIR/helm-index/: chart repo index.yaml + OCI tag list TTL
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

    # SCAP scanner (DESIGN §14, posture.scap): product / OS STIGs inside images with OpenSCAP
    scanners_scap_enabled: bool = False  # default for settings scanners.scap
    scap_embedded: bool = False  # run the scap stage inside the scan worker (dev; degraded rootfs fidelity)
    scap_content_dir: str = ""  # "" = CACHE_DIR/scap-content
    scap_work_dir: str = ""  # rootfs + oscap scratch; "" = CACHE_DIR/scap
    # [{name, kind: ssg|disa|custom, url, sha256, include: [globs]}] as JSON; default: the pinned SSG release
    scap_content_sources: list[dict[str, Any]] | None = None
    scap_disa_urls: list[Any] = []  # [{url, sha256, name?, include?}] (kind disa) as JSON
    scap_content_offline: bool = False  # air-gapped: never fetch, index SCAP_CONTENT_DIR only
    scap_content_refresh_hours: float = 24
    scap_prefer_disa: bool = True
    scap_timeout_seconds: int = 900  # per image (all its benchmarks)
    scap_max_rootfs_gb: float = 10
    scap_finalize_wait_seconds: float = 600  # privileged worker waits this long for a queued scap stage
    scap_skip_validation: bool = False  # oscap --skip-valid
    scap_benchmarks_file: str = ""  # extra os-release/product -> benchmark candidates (benchmarks.yaml format)
    oscap_bin: str = "oscap"
    oscap_chroot_bin: str = "oscap-chroot"

    @field_validator("scap_content_sources", "scap_disa_urls", mode="before")
    @classmethod
    def _scap_json(cls, v: object) -> object:
        if isinstance(v, str):
            import json

            t = v.strip()
            return json.loads(t) if t else []
        return v

    # misc
    cache_dir: str = "/cache"
    log_level: str = "INFO"
    cluster_name: str = "nebari"

    # >>> operations / scale (docs/reviews/architecture.md, docs/OPERATIONS.md)
    # report worker (posture.report_worker): one report at a time, leased rows, per-report timeout
    report_worker_isolation: str = "process"  # process (child per report, killable) | inline
    report_worker_embedded: bool = True  # scan worker also drains the queue (until a report-worker Deployment runs)
    report_timeout_seconds: float = 1200
    report_lease_seconds: float = 120
    report_max_attempts: int = 2  # leases that expired (worker died) before the row is failed
    reports_retention_per_type: int | None = None  # default 20; REPORTS_KEEP_PER_TYPE is the old name
    reports_max_total_bytes: int | None = None  # alias of REPORTS_RETENTION_MAX_TOTAL_BYTES
    raw_max_gz_bytes: int = 4 * 1024 * 1024  # raw scanner JSON kept per row (gzip); larger -> summary only
    # scan memory / admission (M2)
    grype_max_concurrent: int = 2
    scan_max_image_gb: float = 20  # larger images are scanned last, one at a time
    # MIRROR_MODE: registry (skopeo copy into MIRROR_REGISTRY; needed by Clair) | local (per-digest
    # OCI layout under CACHE_DIR/images, scanned in place) | off (scanners pull the original ref)
    mirror_mode: str = "local"
    image_cache_max_bytes: int = 20 * 1024**3
    # pod watcher: targeted scans for new digests (m11)
    event_scans_enabled: bool = True
    event_scan_debounce_seconds: float = 60  # collection window after the first new digest
    event_scans_debounce_seconds: float = 300  # at most one event scan per this many seconds
    event_scans_min_pod_age_seconds: float = 120  # younger pods wait (short-lived verify pods)
    event_scans_include_jobs: bool = False  # pods owned by Jobs / CronJobs

    @field_validator("reports_max_total_bytes", "image_cache_max_bytes", "raw_max_gz_bytes", mode="before")
    @classmethod
    def _ops_quantity(cls, v: object) -> object:
        """2Gi / 500Mi / 20G or plain bytes (chart values are Kubernetes quantities)."""
        if isinstance(v, str) and v.strip():
            t = v.strip()
            units = {"Ki": 1024, "Mi": 1024**2, "Gi": 1024**3, "Ti": 1024**4, "K": 1000, "k": 1000,
                     "M": 1000**2, "G": 1000**3, "T": 1000**4}
            for suffix in sorted(units, key=len, reverse=True):
                if t.endswith(suffix):
                    return int(float(t[: -len(suffix)]) * units[suffix])
            return int(float(t))
        return None if v == "" else v
    # <<< operations / scale

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

    # >>> operations / scale (properties)
    @property
    def report_keep_per_type(self) -> int:
        if self.reports_retention_per_type is not None:
            return self.reports_retention_per_type
        if "reports_keep_per_type" in self.model_fields_set:
            return self.reports_keep_per_type
        return 20

    @property
    def report_max_total_bytes(self) -> int:
        if self.reports_max_total_bytes is not None:
            return self.reports_max_total_bytes
        return int(self.reports_retention_max_total_bytes or 0)

    @property
    def effective_mirror_mode(self) -> str:
        """MIRROR_ENABLED=false (the 0.1 switch) still means off."""
        mode = (self.mirror_mode or "local").strip().lower()
        if not self.mirror_enabled:
            return "off"
        return mode if mode in ("registry", "local", "off") else "local"
    # <<< operations / scale (properties)

    @property
    def scap_content_path(self) -> str:
        import os

        return self.scap_content_dir or os.path.join(self.cache_dir, "scap-content")

    @property
    def scap_work_path(self) -> str:
        import os

        return self.scap_work_dir or os.path.join(self.cache_dir, "scap")

    @property
    def scap_sources(self) -> list[dict[str, Any]]:
        """Content sources: SCAP_CONTENT_SOURCES (default: the pinned SSG release) + SCAP_DISA_URLS."""
        base = DEFAULT_SCAP_SOURCES if self.scap_content_sources is None else self.scap_content_sources
        disa = [{"kind": "disa", **({"url": d} if isinstance(d, str) else d)} for d in self.scap_disa_urls]
        return [dict(x) for x in base] + disa


@lru_cache
def get_settings() -> Settings:
    return Settings()
