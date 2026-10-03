"""Supply-chain tables (DESIGN §12; migration 0002_provenance).

Kept out of `db/models.py` (shared) on purpose; importing this module registers
the tables on the shared `Base` and adds the denormalized `Image.provenance`
column (latest per-image result, used by `ImageSummary.provenance`).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from ..db.models import Base, Image, JSONType, _now_col


class ImageProvenance(Base):
    """One row per image per scan (results are reused across scans for `recheckHours`)."""

    __tablename__ = "image_provenance"
    __table_args__ = (Index("ix_image_provenance_scan_image", "scan_id", "image_id", unique=True),)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    image_id: Mapped[int] = mapped_column(ForeignKey("images.id", ondelete="CASCADE"), nullable=False, index=True)
    digest: Mapped[str | None] = mapped_column(String(100))
    checked_at: Mapped[datetime] = _now_col()  # when the registry was last asked (cache key)
    # their JSON shapes: {signed,verified,error?} {hasSBOM,format?} {hasProvenance,predicateType?}
    signature: Mapped[dict[str, Any] | None] = mapped_column(JSONType)
    sbom: Mapped[dict[str, Any] | None] = mapped_column(JSONType)
    provenance: Mapped[dict[str, Any] | None] = mapped_column(JSONType)
    # {tag: UpdateInfo JSON} for every tag this digest runs under
    updates: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)
    details: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)
    error: Mapped[str | None] = mapped_column(Text)
    score: Mapped[float | None] = mapped_column(Float)


class HelmReleaseRow(Base):
    __tablename__ = "helm_releases"
    __table_args__ = (Index("ix_helm_releases_scan", "scan_id"),)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    namespace: Mapped[str] = mapped_column(String(253), nullable=False)
    release_name: Mapped[str] = mapped_column(String(253), nullable=False)
    chart: Mapped[str] = mapped_column(String(253), nullable=False, default="")
    version: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    app_version: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    revision: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_deployed: Mapped[str | None] = mapped_column(String(64))
    update: Mapped[dict[str, Any] | None] = mapped_column(JSONType)
    chart_source: Mapped[str | None] = mapped_column(Text)


# Denormalized latest result on the image row (added by migration 0002).
if "provenance" not in Image.__table__.c:
    Image.provenance = mapped_column("provenance", JSONType, nullable=True)  # type: ignore[attr-defined]
