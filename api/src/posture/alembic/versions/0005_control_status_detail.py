"""control statuses: responsibility, provider, 800-53A objectives, derivation inputs; wider status
(compliance review M1-M3: org-provided-unverified, hybrid, objective coverage)

Revision ID: 0005_control_status_detail
Revises: 0004_ops_scale
Create Date: 2026-10-03
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0005_control_status_detail"
down_revision = "0004_ops_scale"
branch_labels = None
depends_on = None

JSONB = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")


def upgrade() -> None:
    op.alter_column("control_statuses", "status", type_=sa.String(length=32), existing_type=sa.String(length=20),
                    existing_nullable=False)
    op.add_column("control_statuses", sa.Column("responsibility", sa.String(length=16), nullable=True))
    op.add_column("control_statuses", sa.Column("provider", sa.String(length=255), nullable=True))
    op.add_column("control_statuses", sa.Column("objectives", JSONB, nullable=True))
    op.add_column("control_statuses", sa.Column("inputs", JSONB, nullable=True))


def downgrade() -> None:
    op.drop_column("control_statuses", "inputs")
    op.drop_column("control_statuses", "objectives")
    op.drop_column("control_statuses", "provider")
    op.drop_column("control_statuses", "responsibility")
    op.alter_column("control_statuses", "status", type_=sa.String(length=20), existing_type=sa.String(length=32),
                    existing_nullable=False)
