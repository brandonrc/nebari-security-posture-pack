"""SCAP scanner (DESIGN §14): scap_content, scap_image_summary, scap_results, images.stig and the
scan hand-off columns scans.scap_status / scap_image_ids / scap_finished_at / scap_detail

Revision ID: 0007_scap
Revises: 0006_scan_accounting
Create Date: 2026-10-05
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0007_scap"
down_revision = "0006_scan_accounting"
branch_labels = None
depends_on = None

JSON = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")
NOW = sa.text("now()")


def upgrade() -> None:
    op.create_table(
        "scap_content",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("path", sa.Text(), nullable=False),
        sa.Column("file", sa.Text(), nullable=False),
        sa.Column("benchmark_id", sa.Text(), nullable=False),
        sa.Column("datastream_id", sa.Text(), nullable=True),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("version", sa.String(length=128), nullable=False),
        sa.Column("release_info", sa.Text(), nullable=False),
        sa.Column("status_date", sa.String(length=32), nullable=False),
        sa.Column("source", sa.String(length=16), nullable=False),
        sa.Column("source_name", sa.String(length=200), nullable=True),
        sa.Column("url", sa.Text(), nullable=True),
        sa.Column("sha256", sa.String(length=64), nullable=True),
        sa.Column("size_bytes", sa.BigInteger(), nullable=True),
        sa.Column("profiles", JSON, nullable=False),
        sa.Column("rules", sa.Integer(), nullable=False),
        sa.Column("fetched_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("indexed_at", sa.DateTime(timezone=True), server_default=NOW, nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("path", "benchmark_id", name="uq_scap_content_path_benchmark"),
    )
    op.create_table(
        "scap_image_summary",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("image_id", sa.BigInteger(), nullable=False),
        sa.Column("scan_id", sa.BigInteger(), nullable=True),
        sa.Column("benchmark_key", sa.String(length=64), nullable=False),
        sa.Column("benchmark_id", sa.Text(), nullable=True),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("version", sa.String(length=128), nullable=False),
        sa.Column("source", sa.String(length=16), nullable=True),
        sa.Column("profile_id", sa.Text(), nullable=True),
        sa.Column("profile_title", sa.Text(), nullable=True),
        sa.Column("content_path", sa.Text(), nullable=True),
        sa.Column("content_sha256", sa.String(length=64), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("counts", JSON, nullable=False),
        sa.Column("cat1_open", sa.Integer(), nullable=False),
        sa.Column("cat2_open", sa.Integer(), nullable=False),
        sa.Column("cat3_open", sa.Integer(), nullable=False),
        sa.Column("evaluated_weight", sa.Float(), nullable=False),
        sa.Column("failed_weight", sa.Float(), nullable=False),
        sa.Column("score", sa.Float(), nullable=True),
        sa.Column("rootfs_fidelity", sa.String(length=16), nullable=True),
        sa.Column("rootfs", JSON, nullable=False),
        sa.Column("detected", JSON, nullable=False),
        sa.Column("oscap_version", sa.String(length=32), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), server_default=NOW, nullable=False),
        sa.ForeignKeyConstraint(["image_id"], ["images.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("image_id", "benchmark_key", name="uq_scap_summary_image_benchmark"),
    )
    op.create_index(op.f("ix_scap_image_summary_image_id"), "scap_image_summary", ["image_id"], unique=False)
    op.create_table(
        "scap_results",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("summary_id", sa.BigInteger(), nullable=False),
        sa.Column("image_id", sa.BigInteger(), nullable=False),
        sa.Column("scan_id", sa.BigInteger(), nullable=True),
        sa.Column("benchmark_key", sa.String(length=64), nullable=False),
        sa.Column("rule_id", sa.Text(), nullable=False),
        sa.Column("stig_id", sa.String(length=64), nullable=True),
        sa.Column("vuln_id", sa.String(length=32), nullable=True),
        sa.Column("sv_id", sa.String(length=64), nullable=True),
        sa.Column("rule_version", sa.String(length=64), nullable=True),
        sa.Column("cci", JSON, nullable=False),
        sa.Column("nist", JSON, nullable=False),
        sa.Column("severity", sa.String(length=8), nullable=False),
        sa.Column("result", sa.String(length=16), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("fix_text", sa.Text(), nullable=True),
        sa.Column("group_title", sa.Text(), nullable=True),
        sa.Column("checked_at", sa.DateTime(timezone=True), server_default=NOW, nullable=False),
        sa.ForeignKeyConstraint(["image_id"], ["images.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["summary_id"], ["scap_image_summary.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_scap_results_summary_id"), "scap_results", ["summary_id"], unique=False)
    op.create_index("ix_scap_results_image_benchmark", "scap_results", ["image_id", "benchmark_key"], unique=False)
    op.create_index("ix_scap_results_benchmark_rule", "scap_results", ["benchmark_key", "rule_id"], unique=False)
    op.add_column("images", sa.Column("stig", JSON, nullable=True))
    op.add_column("scans", sa.Column("scap_status", sa.String(length=16), nullable=True))
    op.add_column("scans", sa.Column("scap_image_ids", JSON, nullable=True))
    op.add_column("scans", sa.Column("scap_finished_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("scans", sa.Column("scap_detail", JSON, nullable=True))


def downgrade() -> None:
    op.drop_column("scans", "scap_detail")
    op.drop_column("scans", "scap_finished_at")
    op.drop_column("scans", "scap_image_ids")
    op.drop_column("scans", "scap_status")
    op.drop_column("images", "stig")
    op.drop_index("ix_scap_results_benchmark_rule", table_name="scap_results")
    op.drop_index("ix_scap_results_image_benchmark", table_name="scap_results")
    op.drop_index(op.f("ix_scap_results_summary_id"), table_name="scap_results")
    op.drop_table("scap_results")
    op.drop_index(op.f("ix_scap_image_summary_image_id"), table_name="scap_image_summary")
    op.drop_table("scap_image_summary")
    op.drop_table("scap_content")
