"""Tables of the control evidence engine (migration `0003_controls_engine`)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, DateTime, Float, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from ..db.models import Base, JSONType


class ControlAssertionRun(Base):
    """One engine run. Also the on-demand queue: the API inserts `queued`, the worker claims it."""

    __tablename__ = "control_assertion_runs"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="queued", index=True)
    trigger: Mapped[str] = mapped_column(String(16), nullable=False, default="manual")  # manual|scan|scheduled
    scan_id: Mapped[int | None] = mapped_column(BigInteger)
    requested_by: Mapped[str | None] = mapped_column(String(255))
    baseline: Mapped[str] = mapped_column(String(16), nullable=False, default="moderate")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    summary: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)
    error: Mapped[str | None] = mapped_column(Text)


class ControlAssertionResult(Base):
    __tablename__ = "control_assertion_results"
    __table_args__ = (Index("ix_car_assertion_checked", "assertion_id", "checked_at"),)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("control_assertion_runs.id", ondelete="CASCADE"), nullable=False,
                                        index=True)
    assertion_id: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(Text, nullable=False, default="")
    component: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    controls: Mapped[list[Any]] = mapped_column(JSONType, nullable=False, default=list)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="medium")
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    detail: Mapped[str | None] = mapped_column(Text)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class ControlStatusRow(Base):
    __tablename__ = "control_statuses"
    __table_args__ = (Index("ix_control_statuses_run_control", "run_id", "control"),)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("control_assertion_runs.id", ondelete="CASCADE"), nullable=False)
    control: Mapped[str] = mapped_column(String(32), nullable=False)  # label: AC-6(10)
    oscal_id: Mapped[str] = mapped_column(String(32), nullable=False)  # ac-6.10
    family: Mapped[str] = mapped_column(String(4), nullable=False)
    baseline: Mapped[str | None] = mapped_column(String(16))  # lowest baseline containing the control
    in_baseline: Mapped[bool] = mapped_column(nullable=False, default=False)  # selected baseline of the run
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    components: Mapped[list[Any]] = mapped_column(JSONType, nullable=False, default=list)
    assertions: Mapped[list[Any]] = mapped_column(JSONType, nullable=False, default=list)
    detail: Mapped[str | None] = mapped_column(Text)
    score: Mapped[float | None] = mapped_column(Float)  # passed / evaluated assertions
