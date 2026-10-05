"""posture_results.status: varchar(8) -> varchar(16) for `accepted-risk` (13 characters)

Grace 2026-10-05 (revision 20): the first scan with the scap-worker's risk acceptance failed in
finalize with "value too long for type character varying(8)".

Revision ID: 0010_posture_status_len
Revises: 0009_scap_pending
Create Date: 2026-10-05
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0010_posture_status_len"
down_revision = "0009_scap_pending"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column("posture_results", "status", type_=sa.String(16), existing_type=sa.String(8),
                    existing_nullable=False)


def downgrade() -> None:
    op.execute("UPDATE posture_results SET status = 'fail' WHERE status = 'accepted-risk'")
    op.alter_column("posture_results", "status", type_=sa.String(8), existing_type=sa.String(16),
                    existing_nullable=False)
