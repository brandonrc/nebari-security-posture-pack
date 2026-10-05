"""VEX: consensus_findings.vex_status / vex_justification / vex_source / vex_detail

Revision ID: 0008_vex
Revises: 0007_scap
Create Date: 2026-10-05
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0008_vex"
down_revision = "0007_scap"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("consensus_findings", sa.Column("vex_status", sa.String(length=32), nullable=True))
    op.add_column("consensus_findings", sa.Column("vex_justification", sa.String(length=64), nullable=True))
    op.add_column("consensus_findings", sa.Column("vex_source", sa.Text(), nullable=True))
    op.add_column("consensus_findings", sa.Column("vex_detail", sa.Text(), nullable=True))


def downgrade() -> None:
    for col in ("vex_detail", "vex_source", "vex_justification", "vex_status"):
        op.drop_column("consensus_findings", col)
