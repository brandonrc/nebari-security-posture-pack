"""SQLAlchemy models (DESIGN §6, §11)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

JSONType = JSON(none_as_null=True).with_variant(JSONB(none_as_null=True), "postgresql")


class Base(DeclarativeBase):
    type_annotation_map = {dict[str, Any]: JSONType, list[Any]: JSONType}


def _now_col(nullable: bool = False):
    return mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=nullable)


class Setting(Base):
    __tablename__ = "settings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    data: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)
    updated_at: Mapped[datetime] = _now_col()
    updated_by: Mapped[str | None] = mapped_column(String(255))


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    trigger: Mapped[str] = mapped_column(String(16), nullable=False, default="manual")
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="queued", index=True)
    requested_by: Mapped[str | None] = mapped_column(String(255))
    force: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    target_image_ids: Mapped[list[Any] | None] = mapped_column(JSONType)
    target_namespaces: Mapped[list[Any] | None] = mapped_column(JSONType)
    created_at: Mapped[datetime] = _now_col()
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    images_total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    images_done: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    images_failed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # accounting (0006): images_total = images this scan attempted (= rescanned); null = older row
    images_inventoried: Mapped[int | None] = mapped_column(Integer)  # unique images in the inventory
    images_rescanned: Mapped[int | None] = mapped_column(Integer)  # stale / forced / targeted: scanned now
    images_skipped_fresh: Mapped[int | None] = mapped_column(Integer)  # candidates still fresh (rescanAfterHours)
    images_targeted: Mapped[int | None] = mapped_column(Integer)  # targeted / event scans: candidate images
    inventory_hash: Mapped[str | None] = mapped_column(String(64))  # sha256 of the inventory's image keys
    posture_hash: Mapped[str | None] = mapped_column(String(64))  # sha256 of workloads + security contexts
    score: Mapped[float | None] = mapped_column(Float)
    grade: Mapped[str | None] = mapped_column(String(2))
    vuln_score: Mapped[float | None] = mapped_column(Float)
    posture_score: Mapped[float | None] = mapped_column(Float)
    per_scanner: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)
    log: Mapped[list[Any]] = mapped_column(JSONType, nullable=False, default=list)
    error: Mapped[str | None] = mapped_column(Text)
    inventory_complete: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    vuln_rollup_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))  # vuln_rollup written
    # SCAP hand-off (0007, DESIGN §14): null = not requested (disabled), queued | running | done |
    # skipped | failed; scap_image_ids = images the scap stage evaluates for this scan
    scap_status: Mapped[str | None] = mapped_column(String(16))
    scap_image_ids: Mapped[list[Any] | None] = mapped_column(JSONType)
    scap_finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    scap_detail: Mapped[dict[str, Any] | None] = mapped_column(JSONType)  # {stats, log[], worker}


class Image(Base):
    __tablename__ = "images"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    key: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    ref: Mapped[str] = mapped_column(Text, nullable=False)
    registry_host: Mapped[str] = mapped_column("registry", String(255), nullable=False)
    repository: Mapped[str] = mapped_column(Text, nullable=False)
    tag: Mapped[str | None] = mapped_column(String(255))
    tags: Mapped[list[Any]] = mapped_column(JSONType, nullable=False, default=list)
    digest: Mapped[str | None] = mapped_column(String(100), index=True)
    score: Mapped[float | None] = mapped_column(Float)
    grade: Mapped[str] = mapped_column(String(2), nullable=False, default="?")
    penalty: Mapped[float | None] = mapped_column(Float)
    confidence: Mapped[str | None] = mapped_column(String(8))
    counts: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)
    fixable: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)
    scanners: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)
    agreement_index: Mapped[float | None] = mapped_column(Float)
    namespaces: Mapped[list[Any]] = mapped_column(JSONType, nullable=False, default=list)
    workloads: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    containers: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    running: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)
    mirrored: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    mirror_ref: Mapped[str | None] = mapped_column(Text)
    warnings: Mapped[list[Any]] = mapped_column(JSONType, nullable=False, default=list)
    os_family: Mapped[str | None] = mapped_column(String(64))
    os_name: Mapped[str | None] = mapped_column(String(64))
    first_seen_at: Mapped[datetime] = _now_col()
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_scanned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_scan_id: Mapped[int | None] = mapped_column(BigInteger)
    size_bytes: Mapped[int | None] = mapped_column(BigInteger)  # compressed layers + config (admission)


class ImageScan(Base):
    """One row per image per scan per scanner (raw JSON gzip-compressed, <= 2 MB raw)."""

    __tablename__ = "image_scans"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    image_id: Mapped[int] = mapped_column(ForeignKey("images.id", ondelete="CASCADE"), nullable=False, index=True)
    scanner: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    error: Mapped[str | None] = mapped_column(Text)
    version: Mapped[str | None] = mapped_column(String(64))
    db_updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[datetime] = _now_col()
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    findings_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    scanned_ref: Mapped[str | None] = mapped_column(Text)
    raw_gz: Mapped[bytes | None] = mapped_column(LargeBinary)
    raw_size: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    truncated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class FindingRow(Base):
    """Normalized per-scanner findings (latest image_scan per image/scanner only)."""

    __tablename__ = "findings"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    image_scan_id: Mapped[int] = mapped_column(ForeignKey("image_scans.id", ondelete="CASCADE"), nullable=False,
                                               index=True)
    image_id: Mapped[int] = mapped_column(ForeignKey("images.id", ondelete="CASCADE"), nullable=False, index=True)
    scanner: Mapped[str] = mapped_column(String(16), nullable=False)
    vuln_id: Mapped[str] = mapped_column(String(128), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    package: Mapped[str] = mapped_column(Text, nullable=False)
    installed_version: Mapped[str | None] = mapped_column(Text)
    fixed_version: Mapped[str | None] = mapped_column(Text)
    pkg_type: Mapped[str | None] = mapped_column(String(64))
    cvss: Mapped[float | None] = mapped_column(Float)
    title: Mapped[str | None] = mapped_column(Text)
    url: Mapped[str | None] = mapped_column(Text)


class ConsensusFindingRow(Base):
    """Current consensus findings per image (replaced on each successful rescan)."""

    __tablename__ = "consensus_findings"
    __table_args__ = (
        UniqueConstraint("image_id", "vuln_id", "package", name="uq_consensus_image_vuln_pkg"),
        Index("ix_consensus_vuln", "vuln_id"),
    )
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    image_id: Mapped[int] = mapped_column(ForeignKey("images.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_id: Mapped[int | None] = mapped_column(BigInteger)
    vuln_id: Mapped[str] = mapped_column(String(128), nullable=False)
    package: Mapped[str] = mapped_column(Text, nullable=False)
    installed_version: Mapped[str | None] = mapped_column(Text)
    fixed_version: Mapped[str | None] = mapped_column(Text)
    pkg_type: Mapped[str | None] = mapped_column(String(64))
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    scanners: Mapped[list[Any]] = mapped_column(JSONType, nullable=False, default=list)
    per_scanner: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)
    agreement: Mapped[float] = mapped_column(Float, nullable=False, default=0)
    cvss: Mapped[float | None] = mapped_column(Float)
    title: Mapped[str | None] = mapped_column(Text)
    url: Mapped[str | None] = mapped_column(Text)
    fixable: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    first_seen_at: Mapped[datetime] = _now_col()
    last_seen_at: Mapped[datetime] = _now_col()
    # VEX (posture.vex): newest applicable statement. `not_affected` = suppressed: kept and
    # exported with its justification, but not an open finding (score, counts, POA&M, SAR).
    vex_status: Mapped[str | None] = mapped_column(String(32))
    vex_justification: Mapped[str | None] = mapped_column(String(64))
    vex_source: Mapped[str | None] = mapped_column(Text)
    vex_detail: Mapped[str | None] = mapped_column(Text)

    @classmethod
    def open_filter(cls):
        """SQL condition: not suppressed by a `not_affected` VEX statement."""
        from sqlalchemy import or_

        return or_(cls.vex_status.is_(None), cls.vex_status != "not_affected")


class ContainerRow(Base):
    """Inventory snapshot per scan."""

    __tablename__ = "containers"
    __table_args__ = (Index("ix_containers_scan_ns", "scan_id", "namespace"),)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    namespace: Mapped[str] = mapped_column(String(253), nullable=False)
    pod: Mapped[str] = mapped_column(String(253), nullable=False)
    container: Mapped[str] = mapped_column(String(253), nullable=False)
    container_type: Mapped[str] = mapped_column(String(16), nullable=False)
    image: Mapped[str] = mapped_column(Text, nullable=False)
    image_id_raw: Mapped[str | None] = mapped_column(Text)
    image_fk: Mapped[int | None] = mapped_column(ForeignKey("images.id", ondelete="SET NULL"), index=True)
    workload_kind: Mapped[str] = mapped_column(String(64), nullable=False)
    workload_name: Mapped[str] = mapped_column(String(253), nullable=False)
    pack: Mapped[str | None] = mapped_column(String(255))
    running: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    pod_phase: Mapped[str | None] = mapped_column(String(32))
    security: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)


class WorkloadRow(Base):
    __tablename__ = "workloads"
    __table_args__ = (Index("ix_workloads_scan_ns", "scan_id", "namespace"),)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    namespace: Mapped[str] = mapped_column(String(253), nullable=False)
    kind: Mapped[str] = mapped_column(String(64), nullable=False)
    name: Mapped[str] = mapped_column(String(253), nullable=False)
    pack: Mapped[str | None] = mapped_column(String(255))
    score: Mapped[float | None] = mapped_column(Float)
    grade: Mapped[str] = mapped_column(String(2), nullable=False, default="?")
    vuln_score: Mapped[float | None] = mapped_column(Float)
    posture_score: Mapped[float | None] = mapped_column(Float)
    containers: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    running_containers: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    image_ids: Mapped[list[Any]] = mapped_column(JSONType, nullable=False, default=list)
    posture_passed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    posture_failed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    counts: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)
    system_namespace: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class PostureResultRow(Base):
    __tablename__ = "posture_results"
    __table_args__ = (Index("ix_posture_scan_check", "scan_id", "check_id"),)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    check_id: Mapped[str] = mapped_column(String(64), nullable=False)
    namespace: Mapped[str] = mapped_column(String(253), nullable=False)
    kind: Mapped[str] = mapped_column(String(64), nullable=False)
    name: Mapped[str] = mapped_column(String(253), nullable=False)
    pod: Mapped[str | None] = mapped_column(String(253))
    container: Mapped[str] = mapped_column(String(253), nullable=False, default="")
    status: Mapped[str] = mapped_column(String(8), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    detail: Mapped[str | None] = mapped_column(Text)
    weight: Mapped[float] = mapped_column(Float, nullable=False, default=0)
    system_namespace: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class ScanSnapshot(Base):
    """Scores per scan at cluster / namespace / workload / image level."""

    __tablename__ = "scan_snapshots"
    __table_args__ = (Index("ix_snapshots_scan_level", "scan_id", "level"),)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    level: Mapped[str] = mapped_column(String(16), nullable=False)  # cluster|namespace|workload|image
    key: Mapped[str] = mapped_column(Text, nullable=False, default="")
    score: Mapped[float | None] = mapped_column(Float)
    grade: Mapped[str | None] = mapped_column(String(2))
    data: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)
    created_at: Mapped[datetime] = _now_col()


class ScannerStatus(Base):
    """Scanner health/version as observed by the worker (the api has no scanner binaries)."""

    __tablename__ = "scanner_status"
    name: Mapped[str] = mapped_column(String(16), primary_key=True)
    version: Mapped[str | None] = mapped_column(String(64))
    db_updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    healthy: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    last_error: Mapped[str | None] = mapped_column(Text)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = _now_col()


class WorkerHeartbeat(Base):
    __tablename__ = "worker_heartbeat"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    hostname: Mapped[str | None] = mapped_column(String(255))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    beat_at: Mapped[datetime] = _now_col()


class Report(Base):
    """Compliance report metadata (DESIGN §11); generators are in posture.reports."""

    __tablename__ = "reports"
    __table_args__ = (Index("ix_reports_type_created", "type", "created_at"),
                      Index("ix_reports_status_created", "status", "created_at"))
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[int | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"), index=True)
    type: Mapped[str] = mapped_column(String(32), nullable=False)
    format: Mapped[str] = mapped_column(String(16), nullable=False)
    scope_kind: Mapped[str] = mapped_column(String(16), nullable=False, default="cluster")
    scope_name: Mapped[str | None] = mapped_column(String(512))
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="queued")
    created_at: Mapped[datetime] = _now_col()
    created_by: Mapped[str | None] = mapped_column(String(255))
    size_bytes: Mapped[int | None] = mapped_column(BigInteger)
    filename: Mapped[str | None] = mapped_column(String(512))
    content_type: Mapped[str | None] = mapped_column(String(255))
    error: Mapped[str | None] = mapped_column(Text)
    path: Mapped[str | None] = mapped_column(Text)
    options: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)
    # report-worker queue (lease + heartbeat; posture.report_worker)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    leased_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    worker_id: Mapped[str | None] = mapped_column(String(255))


class VulnRollupRow(Base):
    """CVE-centric rollup of the running images' consensus findings, written once per scan
    (`/vulnerabilities` is served from it with SQL filter / sort / keyset pagination)."""

    __tablename__ = "vuln_rollup"
    __table_args__ = (
        UniqueConstraint("scan_id", "vuln_id", name="uq_vuln_rollup_scan_vuln"),
        Index("ix_vuln_rollup_scan_sev", "scan_id", "severity_rank"),
        Index("ix_vuln_rollup_search_trgm", "search", postgresql_using="gin",
              postgresql_ops={"search": "gin_trgm_ops"}),
    )
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    vuln_id: Mapped[str] = mapped_column(String(128), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    severity_rank: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    scanners: Mapped[list[Any]] = mapped_column(JSONType, nullable=False, default=list)
    agreement: Mapped[float] = mapped_column(Float, nullable=False, default=0)
    images_affected: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    workloads_affected: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    fix_available: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    cvss: Mapped[float | None] = mapped_column(Float)
    kev: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")
    title: Mapped[str | None] = mapped_column(Text)
    url: Mapped[str | None] = mapped_column(Text)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    packages: Mapped[list[Any]] = mapped_column(JSONType, nullable=False, default=list)
    search: Mapped[str] = mapped_column(Text, nullable=False, default="")  # lower(vulnId title packages) for `q`


class CompatReportRow(Base):
    """provenance-collector-pack report JSON (Go-identical bytes), materialized once per scan."""

    __tablename__ = "compat_reports"
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), primary_key=True)
    filename: Mapped[str] = mapped_column(String(64), nullable=False)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    cluster_name: Mapped[str | None] = mapped_column(String(255))
    summary: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)
    body: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    created_at: Mapped[datetime] = _now_col()
