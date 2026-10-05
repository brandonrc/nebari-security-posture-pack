"""SCAP tables (DESIGN §14; migration 0007_scap).

Importing this module registers the tables on the shared `Base` and maps the denormalised
`images.stig` column (per-image STIG summary used by `/images`, `/summary` and the
configuration score). The scan hand-off columns (`scans.scap_*`) live on `Scan` itself.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, DateTime, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from ..db.models import Base, Image, JSONType, _now_col


class ScapContent(Base):
    """One row per (content file, XCCDF benchmark) of SCAP_CONTENT_DIR, written by the worker
    that owns the directory (scap-worker, or the scan worker with SCAP_EMBEDDED)."""

    __tablename__ = "scap_content"
    __table_args__ = (UniqueConstraint("path", "benchmark_id", name="uq_scap_content_path_benchmark"),)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    path: Mapped[str] = mapped_column(Text, nullable=False)  # relative to SCAP_CONTENT_DIR
    file: Mapped[str] = mapped_column(Text, nullable=False)
    benchmark_id: Mapped[str] = mapped_column(Text, nullable=False)
    datastream_id: Mapped[str | None] = mapped_column(Text)
    title: Mapped[str] = mapped_column(Text, nullable=False, default="")
    version: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    release_info: Mapped[str] = mapped_column(Text, nullable=False, default="")
    status_date: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    source: Mapped[str] = mapped_column(String(16), nullable=False, default="custom")  # ssg | disa | custom
    source_name: Mapped[str | None] = mapped_column(String(200))
    url: Mapped[str | None] = mapped_column(Text)
    sha256: Mapped[str | None] = mapped_column(String(64))
    size_bytes: Mapped[int | None] = mapped_column(BigInteger)
    profiles: Mapped[list[Any]] = mapped_column(JSONType, nullable=False, default=list)
    rules: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    fetched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    indexed_at: Mapped[datetime] = _now_col()


class ScapImageSummary(Base):
    """Latest evaluation per (image, benchmark). An image with no applicable benchmark (or whose
    rootfs could not be built) has one row with benchmark_key "" and status notApplicable / error,
    so "never evaluated" is distinguishable from "nothing applies"."""

    __tablename__ = "scap_image_summary"
    __table_args__ = (UniqueConstraint("image_id", "benchmark_key", name="uq_scap_summary_image_benchmark"),)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    image_id: Mapped[int] = mapped_column(ForeignKey("images.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_id: Mapped[int | None] = mapped_column(BigInteger)
    benchmark_key: Mapped[str] = mapped_column(String(64), nullable=False, default="")  # benchmarks.yaml key
    benchmark_id: Mapped[str | None] = mapped_column(Text)  # XCCDF benchmark id
    title: Mapped[str] = mapped_column(Text, nullable=False, default="")
    version: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    source: Mapped[str | None] = mapped_column(String(16))
    profile_id: Mapped[str | None] = mapped_column(Text)
    profile_title: Mapped[str | None] = mapped_column(Text)
    content_path: Mapped[str | None] = mapped_column(Text)
    content_sha256: Mapped[str | None] = mapped_column(String(64))
    # evaluated | notApplicable | error | timeout
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="evaluated")
    counts: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)  # pass, fail, ...
    cat1_open: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    cat2_open: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    cat3_open: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    evaluated_weight: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    failed_weight: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    score: Mapped[float | None] = mapped_column(Float)
    rootfs_fidelity: Mapped[str | None] = mapped_column(String(16))  # full | degraded
    rootfs: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)
    detected: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)
    oscap_version: Mapped[str | None] = mapped_column(String(32))
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error: Mapped[str | None] = mapped_column(Text)
    evaluated_at: Mapped[datetime] = _now_col()


class ScapResultRow(Base):
    """One row per (image, benchmark, rule) of the latest evaluation (notselected rules omitted)."""

    __tablename__ = "scap_results"
    __table_args__ = (
        Index("ix_scap_results_image_benchmark", "image_id", "benchmark_key"),
        Index("ix_scap_results_benchmark_rule", "benchmark_key", "rule_id"),
    )
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    summary_id: Mapped[int] = mapped_column(ForeignKey("scap_image_summary.id", ondelete="CASCADE"), nullable=False,
                                            index=True)
    image_id: Mapped[int] = mapped_column(ForeignKey("images.id", ondelete="CASCADE"), nullable=False)
    scan_id: Mapped[int | None] = mapped_column(BigInteger)
    benchmark_key: Mapped[str] = mapped_column(String(64), nullable=False)
    rule_id: Mapped[str] = mapped_column(Text, nullable=False)
    stig_id: Mapped[str | None] = mapped_column(String(64))  # V- when known, else SV-
    vuln_id: Mapped[str | None] = mapped_column(String(32))
    sv_id: Mapped[str | None] = mapped_column(String(64))
    rule_version: Mapped[str | None] = mapped_column(String(64))  # STIG ID, e.g. RHEL-09-412035
    cci: Mapped[list[Any]] = mapped_column(JSONType, nullable=False, default=list)
    nist: Mapped[list[Any]] = mapped_column(JSONType, nullable=False, default=list)
    severity: Mapped[str] = mapped_column(String(8), nullable=False)  # cat1 | cat2 | cat3
    # pass | fail | notapplicable | notchecked | error | unknown | informational
    result: Mapped[str] = mapped_column(String(16), nullable=False)
    title: Mapped[str] = mapped_column(Text, nullable=False, default="")
    fix_text: Mapped[str | None] = mapped_column(Text)
    group_title: Mapped[str | None] = mapped_column(Text)
    checked_at: Mapped[datetime] = _now_col()
    # first evaluation that found this rule failing on this image (kept across re-evaluations while it
    # keeps failing; the POA&M SLA clock), null for non-failing rows
    first_failed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


# Denormalised per-image STIG summary (scoring.image_stig), added by migration 0007.
if "stig" not in Image.__table__.c:
    Image.stig = mapped_column("stig", JSONType, nullable=True)  # type: ignore[attr-defined]
