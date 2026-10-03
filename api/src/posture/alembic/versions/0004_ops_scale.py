"""ops / scale (docs/reviews/architecture.md M3, M4, M2, §1, m9): report-worker lease columns,
per-scan vuln_rollup (+ pg_trgm search index), compat_reports, scans.vuln_rollup_at,
images.size_bytes, per-table autovacuum for the churny tables.

Revision ID: 0004_ops_scale
Revises: 0003_controls_engine
Create Date: 2026-10-03
"""

from __future__ import annotations

import logging

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0004_ops_scale"
down_revision = "0003_controls_engine"
branch_labels = None
depends_on = None

JSONB = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")
log = logging.getLogger("alembic.runtime.migration")

# delete+insert per image per rescan; the default 20 % scale factor lets ~140k dead rows pile
# up at 500 images before a vacuum (architecture review §2 / m9)
AUTOVACUUM = {"findings": 0.05, "consensus_findings": 0.05, "images": 0.05, "image_scans": 0.1}


def _trgm_available(bind) -> bool:
    if bind.dialect.name != "postgresql":
        return False
    if bind.execute(sa.text("SELECT 1 FROM pg_extension WHERE extname = 'pg_trgm'")).scalar():
        return True
    try:  # trusted extension since PG 13: the database owner may create it
        with bind.begin_nested():
            bind.execute(sa.text("CREATE EXTENSION IF NOT EXISTS pg_trgm"))
        return True
    except Exception as e:  # noqa: BLE001  (no privilege / not installed: `q` falls back to a scan)
        log.warning("pg_trgm unavailable (%s); /vulnerabilities?q= will not use an index", str(e).splitlines()[0])
        return False


def upgrade() -> None:
    bind = op.get_bind()
    for col in ("started_at", "finished_at", "leased_until", "heartbeat_at"):
        op.add_column("reports", sa.Column(col, sa.DateTime(timezone=True), nullable=True))
    op.add_column("reports", sa.Column("attempts", sa.Integer(), server_default="0", nullable=False))
    op.add_column("reports", sa.Column("worker_id", sa.String(length=255), nullable=True))
    op.create_index("ix_reports_status_created", "reports", ["status", "created_at"])
    op.add_column("scans", sa.Column("vuln_rollup_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("images", sa.Column("size_bytes", sa.BigInteger(), nullable=True))

    op.create_table(
        "vuln_rollup",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("scan_id", sa.BigInteger(), nullable=False),
        sa.Column("vuln_id", sa.String(length=128), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("severity_rank", sa.SmallInteger(), nullable=False),
        sa.Column("scanners", JSONB, nullable=False),
        sa.Column("agreement", sa.Float(), nullable=False),
        sa.Column("images_affected", sa.Integer(), nullable=False),
        sa.Column("workloads_affected", sa.Integer(), nullable=False),
        sa.Column("fix_available", sa.Boolean(), nullable=False),
        sa.Column("cvss", sa.Float(), nullable=True),
        sa.Column("kev", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("title", sa.Text(), nullable=True),
        sa.Column("url", sa.Text(), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("packages", JSONB, nullable=False),
        sa.Column("search", sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_id", "vuln_id", name="uq_vuln_rollup_scan_vuln"),
    )
    op.create_index("ix_vuln_rollup_scan_sev", "vuln_rollup", ["scan_id", "severity_rank"])
    if _trgm_available(bind):
        op.create_index("ix_vuln_rollup_search_trgm", "vuln_rollup", ["search"], postgresql_using="gin",
                        postgresql_ops={"search": "gin_trgm_ops"})

    op.create_table(
        "compat_reports",
        sa.Column("scan_id", sa.BigInteger(), nullable=False),
        sa.Column("filename", sa.String(length=64), nullable=False),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("cluster_name", sa.String(length=255), nullable=True),
        sa.Column("summary", JSONB, nullable=False),
        sa.Column("body", sa.LargeBinary(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("scan_id"),
    )

    if bind.dialect.name == "postgresql":
        for table, factor in AUTOVACUUM.items():
            op.execute(f"ALTER TABLE {table} SET (autovacuum_vacuum_scale_factor = {factor}, "
                       f"autovacuum_analyze_scale_factor = {factor})")


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        for table in AUTOVACUUM:
            op.execute(f"ALTER TABLE {table} RESET (autovacuum_vacuum_scale_factor, autovacuum_analyze_scale_factor)")
    op.drop_table("compat_reports")
    op.execute("DROP INDEX IF EXISTS ix_vuln_rollup_search_trgm")
    op.drop_index("ix_vuln_rollup_scan_sev", table_name="vuln_rollup")
    op.drop_table("vuln_rollup")
    op.drop_column("images", "size_bytes")
    op.drop_column("scans", "vuln_rollup_at")
    op.drop_index("ix_reports_status_created", table_name="reports")
    for col in ("worker_id", "attempts", "heartbeat_at", "leased_until", "finished_at", "started_at"):
        op.drop_column("reports", col)
