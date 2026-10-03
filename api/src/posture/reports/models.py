"""ReportSnapshot: the DB-independent input of every report generator (DESIGN §11).

Attributes are snake_case (see models_contract.md); `model_dump(by_alias=True)` gives
the camelCase JSON used by the API.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel


class _M(BaseModel):
    model_config = ConfigDict(extra="allow", alias_generator=to_camel, populate_by_name=True)


class SystemInfo(_M):
    name: str = "Nebari cluster"
    organization: str = ""
    cluster_name: str | None = None
    description: str = ""
    hostname: str = ""  # FQDN (CKL HOST_FQDN)
    ip_address: str = ""
    host_name: str = ""  # CKL HOST_NAME (short host / asset name)
    mac_address: str = ""
    poc_name: str = ""
    poc_email: str = ""
    poc_phone: str = ""
    classification: str = "UNCLASSIFIED"
    marking: str = "CUI"
    emass_system_id: str = ""


class ScanInfo(_M):
    id: int | str
    status: str = "done"
    trigger: str = "scheduled"
    started_at: datetime | None = None
    finished_at: datetime | None = None
    requested_by: str = ""
    score: float | None = None
    grade: str = "?"
    vuln_score: float | None = None
    posture_score: float | None = None


class Scope(_M):
    kind: Literal["cluster", "namespace", "workload"] = "cluster"
    name: str | None = None


class ScannerStatus(_M):
    name: str
    enabled: bool = True
    version: str = ""
    db_updated_at: datetime | None = None
    healthy: bool = True
    last_error: str | None = None
    last_run_at: datetime | None = None


class ImageRecord(_M):
    id: int | str
    ref: str
    registry: str = ""
    repository: str = ""
    tag: str = ""
    digest: str = ""
    score: float | None = None
    grade: str = "?"
    counts: dict[str, int] = Field(default_factory=dict)
    fixable: dict[str, int] = Field(default_factory=dict)
    namespaces: list[str] = Field(default_factory=list)
    workloads: list[str] = Field(default_factory=list)
    packs: list[str] = Field(default_factory=list)
    containers: int = 0
    running_containers: int | None = None
    running: bool = True
    os: str = ""
    base_os: str | None = None
    scanner_status: dict[str, str] = Field(default_factory=dict)
    scanner_versions: dict[str, str] = Field(default_factory=dict)
    agreement_index: float | None = None
    last_scanned_at: datetime | None = None
    mirrored: bool = False
    warnings: list[str] = Field(default_factory=list)
    system_namespace: bool = False


class FindingRecord(_M):
    image_id: int | str
    vuln_id: str
    severity: str
    package: str
    installed_version: str = ""
    fixed_version: str | None = None
    pkg_type: str = ""
    scanners: list[str] = Field(default_factory=list)
    agreement: float | None = None
    per_scanner: dict[str, str] = Field(default_factory=dict)
    cvss: float | None = None
    title: str = ""
    description: str = ""
    url: str = ""
    fixable: bool | None = None
    first_seen_at: datetime | None = None
    fix_published_at: datetime | None = None  # release date of the fixed version, when the scanner knows it
    published_at: datetime | None = None  # vulnerability publication date
    sla_due_at: datetime | None = None
    controls: list[str] = Field(default_factory=list)
    status: str = "open"


class WorkloadRecord(_M):
    namespace: str
    kind: str
    name: str
    pack: str | None = None
    score: float | None = None
    grade: str = "?"
    image_ids: list[int | str] = Field(default_factory=list)
    images: list[str] = Field(default_factory=list)  # refs
    containers: int = 0
    running: bool = True
    system_namespace: bool = False
    posture: dict[str, int] = Field(default_factory=dict)
    counts: dict[str, int] = Field(default_factory=dict)


class NamespaceRecord(_M):
    name: str
    pack: str | None = None
    managed: bool = False
    score: float | None = None
    grade: str = "?"
    workloads: int = 0
    images: int = 0
    system_namespace: bool = False


class CheckDefinition(_M):
    id: str
    title: str = ""
    severity: str = "medium"
    category: str = ""
    description: str = ""
    remediation: str = ""
    controls: list[str] = Field(default_factory=list)
    passed: int = 0
    failed: int = 0


class PostureResult(_M):
    check_id: str
    status: str
    title: str = ""
    namespace: str = ""
    kind: str = ""
    name: str = ""
    container: str | None = None
    detail: str = ""
    severity: str | None = None
    controls: list[str] = Field(default_factory=list)
    remediation: str = ""
    system_namespace: bool | None = None
    first_seen_at: datetime | None = None


class TrendPoint(_M):
    scan_id: int | str
    finished_at: datetime | None = None
    score: float | None = None
    grade: str = "?"
    critical: int = 0
    high: int = 0


class ReportSnapshot(_M):
    generated_at: datetime
    system: SystemInfo = Field(default_factory=SystemInfo)
    scan: ScanInfo
    scope: Scope = Field(default_factory=Scope)
    sla_days: dict[str, int] = Field(default_factory=dict)
    scanners: list[ScannerStatus] = Field(default_factory=list)
    images: list[ImageRecord] = Field(default_factory=list)
    findings: list[FindingRecord] = Field(default_factory=list)
    workloads: list[WorkloadRecord] = Field(default_factory=list)
    namespaces: list[NamespaceRecord] = Field(default_factory=list)
    checks: list[CheckDefinition] = Field(default_factory=list)
    posture_results: list[PostureResult] = Field(default_factory=list)
    trend: list[TrendPoint] = Field(default_factory=list)
    summary: dict[str, Any] | None = None
