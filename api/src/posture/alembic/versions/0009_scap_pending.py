"""scans.scap_pending / scap_deferred: a scan finalized before its SCAP stage completed

Revision ID: 0009_scap_pending
Revises: 0008_vex
Create Date: 2026-10-05
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0009_scap_pending"
down_revision = "0008_vex"
branch_labels = None
depends_on = None

JSON = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")


def upgrade() -> None:
    op.add_column("scans", sa.Column("scap_pending", sa.Boolean(), nullable=False, server_default="false"))
    op.add_column("scans", sa.Column("scap_deferred", JSON, nullable=True))


def downgrade() -> None:
    op.drop_column("scans", "scap_deferred")
    op.drop_column("scans", "scap_pending")
