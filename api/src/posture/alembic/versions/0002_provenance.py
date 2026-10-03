"""supply-chain provenance (DESIGN §12): image_provenance, helm_releases, images.provenance

Revision ID: 0002_provenance
Revises: 0001
Create Date: 2026-10-03 12:00:00
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0002_provenance"
down_revision = "0001"
branch_labels = None
depends_on = None

JSON = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")


def upgrade() -> None:
    op.create_table(
        "image_provenance",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("scan_id", sa.BigInteger(), nullable=False),
        sa.Column("image_id", sa.BigInteger(), nullable=False),
        sa.Column("digest", sa.String(length=100), nullable=True),
        sa.Column("checked_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("signature", JSON, nullable=True),
        sa.Column("sbom", JSON, nullable=True),
        sa.Column("provenance", JSON, nullable=True),
        sa.Column("updates", JSON, nullable=False),
        sa.Column("details", JSON, nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("score", sa.Float(), nullable=True),
        sa.ForeignKeyConstraint(["image_id"], ["images.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_image_provenance_scan_image", "image_provenance", ["scan_id", "image_id"], unique=True)
    op.create_index(op.f("ix_image_provenance_image_id"), "image_provenance", ["image_id"], unique=False)
    op.create_table(
        "helm_releases",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("scan_id", sa.BigInteger(), nullable=False),
        sa.Column("namespace", sa.String(length=253), nullable=False),
        sa.Column("release_name", sa.String(length=253), nullable=False),
        sa.Column("chart", sa.String(length=253), nullable=False),
        sa.Column("version", sa.String(length=128), nullable=False),
        sa.Column("app_version", sa.String(length=128), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("last_deployed", sa.String(length=64), nullable=True),
        sa.Column("update", JSON, nullable=True),
        sa.Column("chart_source", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_helm_releases_scan", "helm_releases", ["scan_id"], unique=False)
    op.add_column("images", sa.Column("provenance", JSON, nullable=True))


def downgrade() -> None:
    op.drop_column("images", "provenance")
    op.drop_index("ix_helm_releases_scan", table_name="helm_releases")
    op.drop_table("helm_releases")
    op.drop_index(op.f("ix_image_provenance_image_id"), table_name="image_provenance")
    op.drop_index("ix_image_provenance_scan_image", table_name="image_provenance")
    op.drop_table("image_provenance")
