"""control evidence engine (DESIGN §13): control_assertion_runs, control_assertion_results,
control_statuses

Revision ID: 0003_controls_engine
Revises: 0002_provenance
Create Date: 2026-10-03
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0003_controls_engine"
down_revision = "0002_provenance"
branch_labels = None
depends_on = None

JSONB = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")


def upgrade() -> None:
    op.create_table(
        "control_assertion_runs",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("trigger", sa.String(length=16), nullable=False),
        sa.Column("scan_id", sa.BigInteger(), nullable=True),
        sa.Column("requested_by", sa.String(length=255), nullable=True),
        sa.Column("baseline", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("summary", JSONB, nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_control_assertion_runs_status", "control_assertion_runs", ["status"])
    op.create_table(
        "control_assertion_results",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("run_id", sa.BigInteger(), nullable=False),
        sa.Column("assertion_id", sa.String(length=64), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("component", sa.String(length=64), nullable=False),
        sa.Column("controls", JSONB, nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column("evidence", JSONB, nullable=False),
        sa.Column("duration_ms", sa.Integer(), nullable=False),
        sa.Column("checked_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["run_id"], ["control_assertion_runs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_control_assertion_results_run_id", "control_assertion_results", ["run_id"])
    op.create_index("ix_car_assertion_checked", "control_assertion_results", ["assertion_id", "checked_at"])
    op.create_table(
        "control_statuses",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("run_id", sa.BigInteger(), nullable=False),
        sa.Column("control", sa.String(length=32), nullable=False),
        sa.Column("oscal_id", sa.String(length=32), nullable=False),
        sa.Column("family", sa.String(length=4), nullable=False),
        sa.Column("baseline", sa.String(length=16), nullable=True),
        sa.Column("in_baseline", sa.Boolean(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("components", JSONB, nullable=False),
        sa.Column("assertions", JSONB, nullable=False),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column("score", sa.Float(), nullable=True),
        sa.ForeignKeyConstraint(["run_id"], ["control_assertion_runs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_control_statuses_run_control", "control_statuses", ["run_id", "control"])


def downgrade() -> None:
    op.drop_index("ix_control_statuses_run_control", table_name="control_statuses")
    op.drop_table("control_statuses")
    op.drop_index("ix_car_assertion_checked", table_name="control_assertion_results")
    op.drop_index("ix_control_assertion_results_run_id", table_name="control_assertion_results")
    op.drop_table("control_assertion_results")
    op.drop_index("ix_control_assertion_runs_status", table_name="control_assertion_runs")
    op.drop_table("control_assertion_runs")
